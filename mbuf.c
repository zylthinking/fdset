
#include "zyl.h"
#include "mbuf.h"

struct mbuf_list {
    struct list_head head;
    lock_t llk;
    uintptr_t ref;
    uintptr_t nr, capacity;
    uintptr_t bytes;
    intptr_t clone;
};

#define prefix_length sizeof(intptr_t)
#define pool_size 64
static struct mbuf_list* buf_pool[pool_size] = {0};

#if (defined(__GNUC__) || defined(__clang__))
__attribute__((constructor))
#endif
static void mbuf_init()
{
    static struct mbuf_list obj = {
        LIST_HEAD_INIT(obj.head),
        lock_initial,
        1,
        0,
        32,
        sizeof(my_buffer),
        0
    };

    assert1(__builtin_offsetof(mem_head, u.head) == 0);
    assert1(__builtin_offsetof(my_buffer, head) == 0);
    buf_pool[0] = &obj;
}

#if defined(_MSC_VER)
#pragma data_seg(".CRT$XIU")
static intptr_t ptr = mbuf_init;
#pragma data_seg()
#endif

intptr_t mbuf_hget(uintptr_t bytes, uintptr_t capacity, intptr_t clone)
{
    struct mbuf_list* list = NULL;
    intptr_t indx = -1;
LABEL:
    for (intptr_t i = 1; i < pool_size; ++i) {
        if (buf_pool[i] == NULL) {
            if (indx == -1) {
                indx = i;
            }
            continue;
        }

        lock(&buf_pool[i]->llk);
        if (buf_pool[i]->bytes == bytes && buf_pool[i]->clone == clone) {
            ++buf_pool[i]->ref;
            if (buf_pool[i]->capacity < capacity) {
                buf_pool[i]->capacity = capacity;
            }
            unlock(&buf_pool[i]->llk);

            if (list != NULL) {
                my_free(list);
            }
            return i;
        }
        unlock(&buf_pool[i]->llk);
    }

    if (indx == -1) {
        if (list != NULL) {
            my_free(list);
        }
        return -1;
    }

    if (list == NULL) {
        list = (struct mbuf_list *) my_malloc(sizeof(struct mbuf_list));
        if (list == NULL) {
            return -1;
        }
    }

    list->llk = lock_val;
    list->ref = 1;
    list->bytes = bytes;
    list->nr = 0;
    list->capacity = capacity;
    list->clone = clone;
    INIT_LIST_HEAD(&list->head);

    void* ptr = __sync_val_compare_and_swap(&buf_pool[indx], NULL, list);
    if (ptr != NULL) {
        indx = -1;
        goto LABEL;
    }
    return indx;
}

static inline void* addr_base(struct list_head* headp)
{
    char* base = (char *) headp - prefix_length;
    check_memory(base);
    return base;
}

void mbuf_reap(intptr_t handle)
{
    if (handle <= 0 || handle >= pool_size) {
        return;
    }

    struct mbuf_list* list = buf_pool[handle];
    if (list == NULL) {
        return;
    }

    struct list_head head;
    INIT_LIST_HEAD(&head);
    uintptr_t nr = 0;

    lock(&list->llk);
    --list->ref;
    if (list->ref == 0) {
        list_add(&head, &list->head);
        list_del_init(&list->head);
        nr = list->nr;
        list->nr = 0;
    }
    unlock(&list->llk);

    while (!list_empty(&head)) {
        --nr;
        struct list_head* ent = head.next;
        list_del(ent);
        void* addr = addr_base(ent);
        my_free(addr);
    }
    assert1(nr == 0);
}

static char* alloc_from_handle(uintptr_t handle, uintptr_t bytes, const char* func, int line)
{
    struct mbuf_list* list = buf_pool[handle];
    char* pch = NULL;
    if (list->nr == 0) {
LABEL:
        pch = (char *) debug_malloc(bytes + prefix_length, func, line);
        if (pch != NULL) {
            *((intptr_t *) pch) = handle;
            pch += prefix_length;
            INIT_LIST_HEAD((struct list_head *) pch);
        }
    } else {
        struct list_head* head = &list->head;
        if (0 == try_lock(&list->llk)) {
            if (list->nr == 0) {
                unlock(&list->llk);
                goto LABEL;
            }

            struct list_head* next = head->next;
            list_del_init(next);
            --list->nr;
            unlock(&list->llk);

            pch = (char *) next;
        } else {
            goto LABEL;
        }
    }
    return pch;
}

static my_buffer* mbuf_alloc_head(const char* func, int line)
{
    struct mbuf_list* list = buf_pool[0];
    my_buffer* mbuf = (my_buffer *) alloc_from_handle(0, list->bytes, func, line);
    mbuf->any = NULL;
    return mbuf;
}

static void do_free(struct list_head* addr)
{
    char* base = addr_base(addr);
    intptr_t handle = *((intptr_t *) base);
    if (handle < 0) {
        my_free(base);
        return;
    }

    struct mbuf_list* list = buf_pool[handle];
    assert1(list != NULL);

    lock(&list->llk);
    if (list->nr < list->capacity && list->ref > 0) {
        list_add(addr, &list->head);
        ++list->nr;
    } else {
        my_free(base);
    }
    unlock(&list->llk);
}

static void mbuf_free(my_buffer* mbuf)
{
    if (mbuf->memh != NULL) {
        mbuf->memh->u.mem.addref(mbuf->memh, -1);
    }
    do_free(&mbuf->head);
}

static inline intptr_t __mem_head_addref(mem_head* head, intptr_t ref)
{
    assert1(((void *) &head->u.mem) == ((void *) head));
    assert1(((void *) &head->u.head) == ((void *) head));

    if (ref > 0) {
        ref = __sync_add_and_fetch(&head->u.mem.ref, ref);
    } else if (ref < 0) {
        ref = -ref;
        ref = __sync_sub_and_fetch(&head->u.mem.ref, ref);
    }

    assert1(ref >= 0);
    return ref;
}

static intptr_t mem_head_addref_1(mem_head* head, intptr_t ref)
{
    ref = __mem_head_addref(head, ref);
    if (ref == 0) {
        do_free(&head->u.head);
    }
    return ref;
}

static intptr_t mem_head_addref_2(mem_head* head, intptr_t ref)
{
    ref = __mem_head_addref(head, ref);
    return ref;
}

static my_buffer* mbuf_clone(my_buffer* buf)
{
    mem_head* p = buf->memh;
    if (p == NULL || p->u.mem.addref == NULL) {
        return NULL;
    }

    my_buffer* mbuf = mbuf_alloc_head(__FUNCTION__, __LINE__);
    if (mbuf == NULL) {
        return NULL;
    }

    p->u.mem.addref(p, 1);
    mbuf->memh = p;

    mbuf->length = buf->length;
    mbuf->ptr[0] = buf->ptr[0];
    mbuf->ptr[1] = buf->ptr[1];
    mbuf->mop = buf->mop;
    return mbuf;
}

static void mbuf_no_free(my_buffer* mbuf)
{
    (void) mbuf;
    return;
}

void mbuf_tell(my_buffer* mbuf)
{
    void* addr = (void *) mbuf;
    addr = (void *) ((intptr_t) addr - prefix_length);
    my_tell(addr);

    mem_head* memh = mbuf->memh;
    if (memh == NULL || memh == (mem_head *) (mbuf + 1)) {
        return;
    }

    addr = (void *) memh;
    addr = (void *) ((intptr_t) addr - prefix_length);
    my_tell(addr);
}

static my_buffer* mbuf_singleton(my_buffer* mbuf)
{
    mbuf_tell(mbuf);
    assert1(0);
    return NULL;
}

static struct mbuf_operations mop_clone = {
    mbuf_clone, mbuf_free
};

static struct mbuf_operations mop_singleton = {
    mbuf_singleton, mbuf_free
};

static my_buffer* mbuf_alloc_1_clone(intptr_t handle,
                            struct mbuf_list* list, const char* func, int line)
{
    my_buffer* mbuf = mbuf_alloc_head(func, line);
    if (mbuf == NULL) {
        return NULL;
    }

    size_t bytes = list->bytes + sizeof(mem_head) + prefix_length;
    mem_head* mem = (mem_head *) alloc_from_handle(handle, bytes, func, line);
    if (mem == NULL) {
        mbuf->memh = NULL;
        mbuf_free(mbuf);
        mbuf = NULL;
    } else {
        mem->u.mem.ref = 1;
        mem->u.mem.addref = mem_head_addref_1;

        mbuf->memh = mem;
        mbuf->length = list->bytes;
        mbuf->ptr[0] = mbuf->ptr[1] = (char *) (mem + 1);
        mbuf->mop = &mop_clone;
    }
    return mbuf;
}

static my_buffer* mbuf_alloc_1_singleton(intptr_t handle,
                            struct mbuf_list* list, const char* func, int line)
{

    uintptr_t bytes = list->bytes + sizeof(my_buffer) + prefix_length;
    my_buffer* mbuf = (my_buffer *) alloc_from_handle(handle, bytes, func, line);
    if (mbuf != NULL) {
        mbuf->any = NULL;
        mbuf->memh = NULL;
        mbuf->length = list->bytes;
        mbuf->ptr[0] = mbuf->ptr[1] = (char *) (mbuf + 1);
        mbuf->mop = &mop_singleton;
    }
    return mbuf;
}

my_buffer* do_mbuf_alloc_1(intptr_t handle, const char* func, int line)
{
    if (handle <= 0 || handle >= pool_size) {
        return NULL;
    }

    register struct mbuf_list* list = buf_pool[handle];
    if (list == NULL) {
        return NULL;
    }

    my_buffer* mbuf = NULL;
    if (list->clone) {
        mbuf = mbuf_alloc_1_clone(handle, list, func, line);
    } else {
        mbuf = mbuf_alloc_1_singleton(handle, list, func, line);
    }

    return mbuf;
}

my_buffer* do_mbuf_alloc_2(uintptr_t bytes, const char* func, int line)
{
    intptr_t len = bytes;
    assert1(len > 0);

    mem_head* p = NULL;
    my_buffer* mbuf = mbuf_alloc_head(func, line);
    if (mbuf == NULL) {
        return NULL;
    }

    size_t total = bytes + sizeof(mem_head) + prefix_length;
    char* pch = (char *) debug_malloc(total, func, line);
    if (pch != NULL) {
        *((intptr_t *) pch) = -len;

        p = (mem_head *) (pch + prefix_length);
        p->u.mem.ref = 1;
        p->u.mem.addref = mem_head_addref_1;

        mbuf->memh = p;
        mbuf->length = bytes;
        mbuf->ptr[0] = mbuf->ptr[1] = (char *) (p + 1);
        mbuf->mop = &mop_clone;
    } else {
        mbuf->memh = NULL;
        mbuf_free(mbuf);
        mbuf = NULL;
    }

    return mbuf;
}

my_buffer* do_mbuf_alloc_3(uintptr_t bytes, const char* func, int line)
{
    intptr_t len = bytes;
    assert1(len > 0);

    size_t total = bytes + sizeof(my_buffer) + prefix_length;
    char* pch = (char *) debug_malloc(total, func, line);
    my_buffer* mbuf = NULL;
    if (pch != NULL) {
        *((intptr_t *) pch) = -len;
        mbuf = (my_buffer *) (pch + prefix_length);

        INIT_LIST_HEAD(&mbuf->head);
        mbuf->any = NULL;
        mbuf->memh = NULL;
        mbuf->length = bytes;
        mbuf->ptr[0] = mbuf->ptr[1] = (char *) (mbuf + 1);
        mbuf->mop = &mop_singleton;
    }

    return mbuf;
}

static void mbuf_free2(my_buffer* mbuf1)
{
    mem_head* memh = mbuf1->memh;
    my_buffer* mbuf2 = ((my_buffer *) memh) - 1;

    intptr_t ref = mbuf1->memh->u.mem.addref(memh, -1);
    if (mbuf1 != mbuf2) {
        do_free(&mbuf1->head);
    }

    if (ref == 0) {
        do_free(&mbuf2->head);
    }
}

my_buffer* do_mbuf_alloc_4(void* addr, uintptr_t bytes, const char* func, int line)
{
    static struct mbuf_operations mbuf_mop2 = {
        mbuf_clone, mbuf_free2
    };
    intptr_t len = (intptr_t) sizeof(mem_head);

    size_t total = len + sizeof(my_buffer) + prefix_length;
    char* pch = (char *) debug_malloc(total, func, line);
    my_buffer* mbuf = NULL;
    if (pch != NULL) {
        *((intptr_t *) pch) = -len;
        mbuf = (my_buffer *) (pch + prefix_length);

        INIT_LIST_HEAD(&mbuf->head);
        mbuf->any = NULL;
        mbuf->memh = (mem_head *) (mbuf + 1);
        mbuf->memh->u.mem.ref = 1;
        mbuf->memh->u.mem.addref = mem_head_addref_2;

        mbuf->length = bytes;
        mbuf->ptr[0] = mbuf->ptr[1] = (char *) addr;
        mbuf->mop = &mbuf_mop2;
    }
    return mbuf;
}

my_buffer* do_mbuf_alloc_5(void* addr, uintptr_t bytes, const char* func, int line)
{
    my_buffer* mbuf = mbuf_alloc_head(func, line);
    if (mbuf == NULL) {
        return NULL;
    }

    mbuf->memh = NULL;
    mbuf->length = bytes;
    mbuf->ptr[0] = mbuf->ptr[1] = (char *) addr;
    mbuf->mop = &mop_singleton;
    return mbuf;
}

my_buffer* mbuf_alloc_6(void* addr, uintptr_t bytes)
{
    static struct mbuf_operations mbuf_mop3 = {
        mbuf_singleton, mbuf_no_free
    };
    size_t len = sizeof(my_buffer);
    assert1(bytes >= len);
    my_buffer* mbuf = (my_buffer *) addr;

    INIT_LIST_HEAD(&mbuf->head);
    mbuf->any = NULL;
    mbuf->memh = NULL;
    mbuf->length = bytes - len;
    mbuf->ptr[0] = mbuf->ptr[1] = ((char *) addr) + len;
    mbuf->mop = &mbuf_mop3;
    return mbuf;
}

void my_buffer_dump(my_buffer* mbuf)
{
    logmsg("mbuf(%p) dump %d bytes: ", mbuf, mbuf->length);
    for (int i = 0; i < mbuf->length; ++i) {
        const unsigned char* pch = (const unsigned char *) (mbuf->ptr[1] + i);
        logmsg("%02x ", pch[0]);
    }
    logmsg("\n");
}

uint32_t free_buffer(list_head* head)
{
    uint32_t n = 0;
    while (!list_empty(head)) {
        list_head* ent = head->next;
        list_del(ent);

        my_buffer* buf = list_entry(ent, my_buffer, head);
        buf->mop->free(buf);
        ++n;
    }
    return n;
}

uint32_t calc_buffer_length(list_head* head)
{
    uint32_t n = 0;
    for (list_head* ent = head->next; ent != head; ent = ent->next) {
        my_buffer* buf = list_entry(ent, my_buffer, head);
        n += buf->length;
    }
    return n;
}
