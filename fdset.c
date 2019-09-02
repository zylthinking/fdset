
#include "list_head.h"
#include "fdset.h"
#include "fdset_in.h"
#include "fdctx.h"
#include "lkf.h"
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <linux/futex.h>
#include <pthread.h>
#include <fcntl.h>

#ifdef __ANDROID__
    #ifndef EPOLLRDHUP
    #define EPOLLRDHUP 0x2000
    #endif

    #ifndef EPOLLONESHOT
    #define EPOLLONESHOT (1 << 30)
    #endif
#endif
#define epoll_mask(x) (((uint32_t) x | EPOLLONESHOT | EPOLLET))
#define futex(p1, p2, p3, p4, p5, p6) syscall(__NR_futex, p1, p2, p3, p4, p5, p6)

typedef struct {
    int fd;
    int efd;
    uint32_t cycle;

    my_handle* hos;
    int32_t* keep;
    lock_t fdctx_lck;
    lock_t timer_lck;
    lock_t task_lck;

    list_head fdctx_head;
    list_head timer_head;
    list_head task_pool;
} fdset;

typedef struct {
    intptr_t id;
    intptr_t expire;
    my_handle* handle;
    list_head inset;
    list_head inself;
} sched_t;

static void fd_close(int fd)
{
    int n;
    do {
        n = close(fd);
    } while (n == -1 && errno == EINTR);
}

static int make_none_block(int fd)
{
    int val = fcntl(fd, F_GETFL, 0);
    if (val != -1) {
        if (0 == (val & O_NONBLOCK)) {
            val |= O_NONBLOCK;
            val = fcntl(fd, F_SETFL, val);
        } else {
            val = 0;
        }
    }
    return val;
}

static int make_no_sigpipe(int sock)
{
    int n = 0;
#ifdef __APPLE__
    int one = 1;
    n = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &one, sizeof(one));
#endif
    return n;
}

static my_buffer* proto_buffer_alloc(void* fdctx, uint32_t bytes)
{
    fd_contex* ctx = (fd_contex *) fdctx;
    my_buffer* mbuf = NULL;
    if (ctx->read_mbuf != NULL) {
        assert1(ctx->read_mbuf->length == bytes);
        mbuf = ctx->read_mbuf;
        ctx->read_mbuf = NULL;
    } else {
        struct fd_struct* fds = ctx->fds;
        uint32_t needed = roundup(task_bytes + bytes, sizeof(char *));
        if (fds->fop->buffer_get != NULL) {
            mbuf = fds->fop->buffer_get(fds, needed);
        } else {
            mbuf = mbuf_alloc_3(needed);
        }

        if (mbuf != NULL) {
            mbuf->length = bytes;
        }
    }
    return mbuf;
}

static int io_read(fd_contex* fdctx, bool eos)
{
    struct fd_struct* fds = fdctx->fds;
    struct sockaddr_in in;
    do {
        int error = ENOMEM;
        struct sockaddr_in *inptr = NULL;

        my_buffer* mbuf = proto_buffer_alloc(fdctx, fds->bytes);
        if (mbuf != NULL) {
            inptr = &in;
            error = 0;

            if (-1 == fdctx->imp->read(fds->fd, mbuf, inptr)) {
                error = errno;
            }

            if (error == EAGAIN) {
                if (!eos) {
                    fds->bytes = (uint32_t) mbuf->length;
                    fdctx->read_mbuf = mbuf;
                    return 0;
                }
                error = ESHUTDOWN;
            }
            mbuf->length = (uintptr_t) (mbuf->ptr[1] - mbuf->ptr[0]);
            mbuf->ptr[1] = mbuf->ptr[0];
            mbuf->any = (void *) (intptr_t) error;
        }

        errno = error;
        int n = fds->fop->push(fds, mbuf, inptr);
        if (n <= 0) {
            return -1;
        }
        fds->bytes = (uint32_t) n;
    } while (1);
    __builtin_unreachable();
}

static int io_write(fd_contex* fdctx)
{
    my_buffer* mbuf = NULL;
    struct fd_struct* fds = fdctx->fds;
    int n = 0;

    while (1) {
        struct sockaddr_in* in = NULL;
        if (fdctx->write_mbuf != NULL) {
            mbuf = fdctx->write_mbuf;
            in = fdctx->addr;
            fdctx->write_mbuf = NULL;
            fdctx->addr = NULL;
        } else if (0 > fds->fop->pull(fds, &mbuf, &in)) {
            if (mbuf != NULL) {
                mbuf->mop->free(mbuf);
            }
            n = -1;
            break;
        }

        if (mbuf == NULL) {
            break;
        }

        if (-1 == fdctx->imp->write(fds->fd, mbuf, in)) {
            if (EAGAIN != errno) {
                continue;
            }

            if (mbuf->length != 0) {
                fdctx->write_mbuf = mbuf;
                fdctx->addr = in;
                break;
            }
        }

        mbuf->mop->free(mbuf);
        mbuf = NULL;
    }
    return n;
}

static void io_proc(fd_contex* fdctx, uint32_t mask)
{
    int32_t n = 0;
    fdctx->mask[0] = 0;
    struct fd_struct* fds = fdctx->fds;

    mask = fdctx->imp->event_mask(fds, mask);
    if (mask & EPOLLERR) {
        handle_clone(fdctx->self);
        handle_dettach(fdctx->self);
        return;
    }

    if (mask & EPOLLIN) {
        bool eos = (0 != (mask & EPOLLRDHUP));
        if (-1 == io_read(fdctx, eos) || eos) {
            fdctx->mask[1] &= ~EPOLLIN;
        }
    }

    if (mask & EPOLLOUT) {
        n = io_write(fdctx);
        if (n == -1) {
            fdctx->mask[1] &= ~EPOLLOUT;
        }
    }
}

static inline int kevent_modify(fdset* fset, fd_contex* fdctx, int32_t new_mask, int32_t old_mask)
{
    if (new_mask == 0 || new_mask == old_mask) {
        return 0;
    }

    struct epoll_event event;
    event.data.ptr = fdctx;
    event.events = epoll_mask(new_mask);
    fdctx->mask[0] = new_mask;
    int n = epoll_ctl(fset->fd, EPOLL_CTL_MOD, fdctx->fds->fd, &event);
    if (n != 0) {
        assert2(errno != EINTR, "epoll_ctl does not said EINTR");
        __sync_val_compare_and_swap(&fdctx->mask[0], new_mask, old_mask);
    }
    return n;
}

static inline int fdset_watch(fdset* fset, fd_contex* fdctx)
{
    struct fd_struct* fds = fdctx->fds;
    int n = 0;

    lock(&fdctx->mutx);
    int32_t mask = fds->mask & fdctx->mask[1];
    if (mask != fdctx->mask[0]) {
        n = kevent_modify(fset, fdctx, mask, fdctx->mask[0]);
    }
    unlock(&fdctx->mutx);
    return n;
}

static void epoll_event_handler(fd_contex* fdctx, uint32_t events, uint64_t round)
{
    if (0 == round || fdctx->token.round != round) {
        return;
    }

    // no fd_contex_free has been or being called
    // so fdctx->hset is ok for access
    fdset* fset = (fdset *) handle_get(fdctx->hset);
    if (fset == NULL) {
        return;
    }

    io_proc(fdctx, events);
    fdset_watch(fset, fdctx);
    handle_put(fdctx->hset);
}

static void enter_proc_gate(fd_contex* fdctx, intptr_t events, void* handler)
{
    uint64_t round = fdctx->token.round;
    proc_t* proc = heap_alloc(proc);
    proc->fdctx = fdctx;
    proc->handler = (typeof (proc->handler)) handler;
    proc->events = events;
    proc->round = round;

    int n = proc_enter(&fdctx->proc, &proc->node);
    if (n == -1) {
        return;
    }

    lkf_node* node = NULL;
LABEL:
    node = lkf_node_get(&fdctx->proc.list);
    assert1(node != NULL);

    lkf_node* current = NULL;
    do {
        current = lkf_node_next(node);
        if (current != NULL) {
            proc = container_of(current, proc_t, node);
            proc->handler(proc->fdctx, proc->events, proc->round);
            heap_free(proc);
        }
    } while (current != node);

    n = proc_leave(&fdctx->proc);
    if (n == 0) {
        return;
    }
    goto LABEL;
}

intptr_t* sched_handle_alloc(intptr_t id)
{
    sched_t* sched = heap_alloc(sched);
    if (sched != NULL) {
        sched->id = id;
    }
    return (intptr_t *) sched;
}

void sched_handle_free(intptr_t* ptr)
{
    heap_free(ptr);
}

static void sched_timer_handler(fd_contex* fdctx, intptr_t id, uint64_t round)
{
    if (0 == round || fdctx->token.round != round) {
        sched_handle_free((intptr_t *) id);
        return;
    }

    fdset* fset = (fdset *) handle_get(fdctx->hset);
    if (fset == NULL) {
        sched_handle_free((intptr_t *) id);
        return;
    }

    struct list_head* ent;
    sched_t* sched = (sched_t *) id;
    list_add(&sched->inself, &fdctx->timer);

    lock(&fset->timer_lck);
    for (ent = fset->timer_head.prev;
         ent != &fset->timer_head;
         ent = ent->prev)
    {
        sched_t* cur = list_entry(ent, sched_t, inset);
        if (cur->expire <= sched->expire) {
            break;
        }
    }
    list_add(&sched->inset, ent);
    unlock(&fset->timer_lck);

    fdset_watch(fset, fdctx);
    handle_put(fdctx->hset);
}

int fdset_sched(my_handle* handle, uint32_t ms, intptr_t* id)
{
    sched_t* sched = (sched_t *) id;
    assert1(sched != NULL);

    fd_contex* fdctx = (fd_contex *) handle_get(handle);
    if (fdctx == NULL) {
        errno = EBADF;
        return -1;
    }

    if (fdctx->token.round == 0) {
        handle_put(handle);
        errno = ENOENT;
        return -1;
    }

    sched->expire = (intptr_t) now() + ms;
    sched->handle = handle;
    handle_clone(handle);
    enter_proc_gate(fdctx, (intptr_t) sched, (void *) sched_timer_handler);
    handle_put(handle);
    return 0;
}

static void epoll_notify_handler(fd_contex* fdctx, intptr_t id, uint64_t round)
{
    if (0 == round || fdctx->token.round != round) {
        return;
    }

    fdset* fset = (fdset *) handle_get(fdctx->hset);
    if (fset == NULL) {
        return;
    }

    fdctx->fds->fop->notify(fdctx->fds, (intptr_t *) id);
    fdset_watch(fset, fdctx);
    handle_put(fdctx->hset);
}

static void release_all_timer(list_head* headp)
{
    while (!list_empty(headp)) {
        sched_t* sched = list_entry(headp->next, sched_t, inself);
        list_del(headp->next);

        my_handle* handle = (my_handle *) sched->handle;
        fd_contex* fdctx = (fd_contex *) handle_get(handle);
        if (fdctx == NULL) {
            handle_release(handle);
            sched_handle_free(&sched->id);
            continue;
        }
        enter_proc_gate(fdctx, (intptr_t) sched, (void *) epoll_notify_handler);
        handle_put(handle);
        handle_release(handle);
    }
}

static void timer_expires(fdset* fset)
{
    int64_t tms = now();
    list_head *ent, head;
    INIT_LIST_HEAD(&head);

    lock(&fset->timer_lck);
    for (ent = fset->timer_head.next; ent != &fset->timer_head;) {
        sched_t* sched = list_entry(ent, sched_t, inset);
        if (sched->expire > tms) {
            break;
        }
        ent = ent->next;
        list_del(&sched->inset);
        list_del(&sched->inself);
        list_add(&sched->inself, &head);
    }
    unlock(&fset->timer_lck);
    release_all_timer(&head);
}

static int wait_get(uint32_t cycle)
{
    static int64_t wake = 0;
    int64_t snap = wake;
    int64_t current = now();
    if (current < wake) {
        return -1;
    }

    current += cycle;
    if (__sync_bool_compare_and_swap(&wake, snap, current)) {
        return (int) cycle;
    }
    return -1;
}

static void looper(my_handle* handle, int fd, uint32_t cycle)
{
    struct epoll_event events;

    while (1) {
        int nr = epoll_wait(fd, &events, 1, wait_get(cycle));
        fdset* fset = (fdset *) handle_get(handle);
        if (__builtin_expect(fset == NULL, 0)) {
            break;
        }

        if (__builtin_expect(nr == 1, 1)) {
            fd_contex* fdctx = (fd_contex *) events.data.ptr;
            if (__builtin_expect(fdctx != NULL, 1)) {
                enter_proc_gate((fd_contex *) events.data.ptr, (intptr_t) events.events, (void *) epoll_event_handler);
            }
        } else if ((nr != 0) && (nr != -1 || EINTR != errno)) {
            logmsg("what's up? n = %d, errno = %d\n", nr, errno);
        }

        timer_expires(fset);
        handle_put(handle);
    }
}

static void fset_delete(void* addr)
{
    uint64_t seq = atomic_inc_uint64();
    fdset* fset = (fdset *) addr;
    write(fset->efd, &fset, sizeof(fset));

    while (!list_empty(&fset->fdctx_head)) {
        my_handle* handle = NULL;
        struct list_head* ent = fset->fdctx_head.next;
        fd_contex* fdctx = list_entry(ent, fd_contex, set_entry);

        // fdctx will never be freed, so we can acess it
        // even it mybe have been "released"
        // we need list_del_init here we make sure
        // only one of this or fd_contex_free can do the real work.
        //
        // we reach here because fd_contex_free does not call list_del_init
        // yet when we get execute ent = fset->fdctx_head.next;
        // but maybe the fdctx have then been freed.
        lock(&fdctx->mutx);
        int empty = list_empty(ent);
        if (!empty && seq > fdctx->token.born) {
            handle = fdctx->self;
            list_del_init(ent);
			epoll_ctl(fset->fd, EPOLL_CTL_DEL, fdctx->fds->fd, NULL);
        }
        unlock(&fdctx->mutx);

        if (handle != NULL) {
            handle_dettach(handle);
        }
    }

    handle_release(fset->hos);
    //release_all_timer(&fset->timer_head);
    free_buffer(&fset->task_pool);

    if (fset->keep != NULL) {
        fset->keep[2] = 1;
        futex(&fset->keep[2], FUTEX_WAKE, fset->keep[0], NULL, NULL, 0);
    }
    my_free(fset);
}

static void epoll_final(void* addr)
{
    int* fds = (int *) addr;
    fd_close(fds[1]);
    fd_close(fds[0]);
    my_free(fds);
}

static my_handle* epoll_init()
{
    struct epoll_event event;
    event.events = epoll_mask(EPOLLIN);
    event.data.ptr = NULL;

    int fd = epoll_create(1);
    if (fd == -1) {
        goto LABEL4;
    }

    int efd = eventfd(0, 0);
    if (efd == -1) {
        goto LABEL3;
    }

    int n = epoll_ctl(fd, EPOLL_CTL_ADD, efd, &event);
    if (n == -1) {
        goto LABEL2;
    }

    errno = ENOMEM;
    int* fds = (int *) my_malloc(sizeof(int) * 2);
    if (fds == NULL) {
        goto LABEL1;
    }
    fds[0] = fd;
    fds[1] = efd;

    my_handle* handle = handle_attach(fds, epoll_final);
    if (handle == NULL) {
        goto LABEL0;
    }
    return handle;

LABEL0:
    my_free(fds);
LABEL1:
    epoll_ctl(fd, EPOLL_CTL_DEL, efd, NULL);
LABEL2:
    fd_close(efd);
LABEL3:
    fd_close(fd);
LABEL4:
    return NULL;
}

static void* fdset_new(uint32_t ms_cycle)
{
    if (ms_cycle == 0 || ms_cycle == (uint32_t) -1) {
        ms_cycle = 10;
    }

    my_handle* handle1 = epoll_init();
    if (handle1 == NULL) {
        goto LABEL2;
    }

    errno = ENOMEM;
    fdset* fset = (fdset *) my_malloc(sizeof(fdset));
    if (fset == NULL) {
        goto LABEL1;
    }

    my_handle* handle2 = handle_attach(fset, fset_delete);
    if (handle2 == NULL) {
        goto LABEL0;
    }

    int* fds = (int *) handle_get(handle1);
    int fd = fds[0];
    int efd = fds[1];
    handle_put(handle1);

    INIT_LIST_HEAD(&fset->fdctx_head);
    INIT_LIST_HEAD(&fset->task_pool);
    INIT_LIST_HEAD(&fset->timer_head);
    fset->fdctx_lck = lock_val;
    fset->timer_lck = lock_val;
    fset->task_lck = lock_val;
    fset->fd = fd;
    fset->efd = efd;
    fset->hos = handle1;
    fset->keep = NULL;
    fset->cycle = ms_cycle;
    return (void *) handle2;

LABEL0:
    my_free(fset);
LABEL1:
    handle_release(handle1);
LABEL2:
    return NULL;
}

static int fdset_join1(void* set, volatile intptr_t* flag)
{
    assert1(*flag != 0 && *flag != -1);
    fdset* fset = (fdset *) handle_get(set);
    if (fset == NULL) {
        *flag = -1;
        errno = EBADF;
        return -1;
    }
    handle_clone(set);

    my_handle* hos = fset->hos;
    handle_clone(hos);
    int fd = fset->fd;
    uint32_t cycle = fset->cycle;

    *flag = 0;
    handle_put(set);
    looper(set, fd, cycle);
    handle_release(hos);
    handle_release(set);
    return 0;
}

static void* fdset_main_loop(void* ptr)
{
    intptr_t* intp = (intptr_t *) ptr;
    void* fset = (void *) intp[0];
    fdset_join1(fset, intp + 1);
    return NULL;
}

static intptr_t do_fdset_get(void* fset)
{
    intptr_t intp[2];
    intp[0] = (intptr_t) fset;
    intp[1] = intp[0];

    pthread_t tid;
    int n = pthread_create(&tid, NULL, fdset_main_loop, (void *) &intp[0]);
    if (n != 0) {
        return -1;
    }
    pthread_detach(tid);

    while ((volatile intptr_t) intp[1] == intp[0]) {
        sched_yield();
    }
    return intp[1];
}

void* fdset_get(uint32_t* nr, uint32_t cycle)
{
    void* fset = fdset_new(cycle);
    if (fset == NULL || nr == 0) {
        return NULL;
    }

    uint32_t n = 0;
    for (; n < *nr; ++n) {
        if( -1 == do_fdset_get(fset)) {
            break;
        }
    }

    *nr = n;
    if (n == 0) {
        fdset_put(fset);
        fset = NULL;
    }
    return fset;
}

static void unlink_from_fdset(fdset* fset, fd_contex* fdctx)
{
    lock(&fset->fdctx_lck);
    list_del(&fdctx->set_entry);
    unlock(&fset->fdctx_lck);

    list_head* ent = fdctx->timer.next;
    lock(&fset->timer_lck);
    for (; ent != &fdctx->timer; ent = ent->next) {
        sched_t* sched = list_entry(ent, sched_t, inself);
        list_del(&sched->inset);
    }
    unlock(&fset->timer_lck);

    struct fd_struct* fds = fdctx->fds;
    epoll_ctl(fset->fd, EPOLL_CTL_DEL, fds->fd, NULL);
}

static void free_write_buffer(fd_contex* fdctx)
{
    struct fd_struct* fds = fdctx->fds;
    if (fdctx->write_mbuf == NULL) {
        return;
    }

    while (1) {
        int n = fdctx->imp->write(fds->fd, fdctx->write_mbuf, fdctx->addr);
        if (n == 0 || errno != EAGAIN) {
            break;
        }
        usleep(1000);
    }
    fdctx->write_mbuf->mop->free(fdctx->write_mbuf);
}

static void fd_context_delete(fd_contex* fdctx, uint32_t unused1, uint64_t unused2)
{
    (void) unused1;
    (void) unused2;

    fdset* fset = (fdset *) handle_get(fdctx->hset);
    if (fset != NULL) {
        unlink_from_fdset(fset, fdctx);
        handle_release(fdctx->self);
        handle_put(fdctx->hset);
    } else {
        lock(&fdctx->mutx);
        int empty = list_empty(&fdctx->set_entry);
        if (!empty) {
            list_del_init(&fdctx->set_entry);
        }
        unlock(&fdctx->mutx);

        if (!empty) {
            handle_release(fdctx->self);
        }
    }
    handle_release(fdctx->hset);

    if (fdctx->read_mbuf != NULL) {
        fdctx->read_mbuf->mop->free(fdctx->read_mbuf);
    }

    release_all_timer(&fdctx->timer);
    free_write_buffer(fdctx);
    struct fd_struct* fds = fdctx->fds;
    fds->fop->detach(fds);
    fd_contex_put(fdctx);
}

static void fd_contex_free(void* addr)
{
    enter_proc_gate((fd_contex *) addr, 0, (void *) fd_context_delete);
}

static fd_contex* fd_make_context(my_handle* hset, fdset* fset, struct fd_struct* fds)
{
    errno = ENOMEM;

    fd_contex* fdctx = fd_contex_get();
    if (fdctx == NULL) {
        return NULL;
    }

    my_handle* handle = handle_attach(fdctx, fd_contex_free);
    if (handle == NULL) {
        fd_contex_put(fdctx);
        return NULL;
    }

    fdctx->self = handle;
    handle_clone(hset);
    fdctx->hset = hset;
    fdctx->fds = fds;
    fdctx->read_mbuf = NULL;
    fdctx->write_mbuf = NULL;
    fdctx->addr = NULL;
    fdctx->mutx = lock_val;
    fdctx->mask[0] = 0;
    fdctx->mask[1] = EPOLLIN | EPOLLOUT;
    INIT_LIST_HEAD(&fdctx->set_entry);
    INIT_LKF(&fdctx->proc.list);
    fdctx->proc.stat = 0;
    fdctx->imp = implement_by_type(fds->tcp0_udp1 ? tcp_key : udp_key);

    lock(&fset->fdctx_lck);
    list_add(&fdctx->set_entry, &fset->fdctx_head);
    unlock(&fset->fdctx_lck);
    return fdctx;
}

my_handle* fdset_make_handle(void* set, struct fd_struct* fds)
{
    if (fds->fd == -1) {
        errno = EINVAL;
        return NULL;
    }

    if (-1 == make_no_sigpipe(fds->fd) ||
        -1 == make_none_block(fds->fd))
    {
        return NULL;
    }

    my_handle* hset = (my_handle *) set;
    fdset* fset = (fdset *) handle_get(hset);
    if (fset == NULL) {
        errno = EBADF;
        return NULL;
    }

    my_handle* handle = NULL;
    fd_contex* fdctx = fd_make_context(hset, fset, fds);
    if (fdctx != NULL) {
        handle = fdctx->self;
        handle_clone(handle);
    }

    handle_put(hset);
    return handle;
}

static int fdset_add_fdctx(fdset* fset, fd_contex* fdctx)
{
    struct fd_struct* fds = fdctx->fds;
    int32_t mask = fds->mask & fdctx->mask[1];
    uint64_t round = atomic_inc_uint64();
    struct epoll_event event;
    event.data.ptr = fdctx;
    event.events = epoll_mask(mask);

    lock(&fdctx->mutx);
    if (0 != fdctx->token.round) {
        unlock(&fdctx->mutx);
        errno = EEXIST;
        return -1;
    }

    int n = epoll_ctl(fset->fd, EPOLL_CTL_ADD, fds->fd, &event);
    if (-1 == n) {
        unlock(&fdctx->mutx);
        return -1;
    }

    fdctx->mask[0] = mask;
    fdctx->token.round = round;
    unlock(&fdctx->mutx);
    return 0;
}

my_handle* fdset_attach_fd(void* set, struct fd_struct* fds)
{
    if (fds->fd == -1) {
        errno = EINVAL;
        return NULL;
    }

    if (-1 == make_no_sigpipe(fds->fd) ||
        -1 == make_none_block(fds->fd))
    {
        return NULL;
    }

    my_handle* hset = (my_handle *) set;
    fdset* fset = (fdset *) handle_get(hset);
    if (fset == NULL) {
        errno = EBADF;
        return NULL;
    }

    my_handle* handle = NULL;
    fd_contex* fdctx = fd_make_context(hset, fset, fds);

    if (fdctx != NULL) {
        handle_clone(fdctx->self);
        int n = fdset_add_fdctx(fset, fdctx);

        if (0 == n) {
            handle = fdctx->self;
        } else {
            handle_dettach(fdctx->self);
        }
    }

    handle_put(hset);
    return handle;
}

int fdset_attach_handle(void* set, my_handle* handle)
{
    my_handle* hset = (my_handle *) set;
    fdset* fset = (fdset *) handle_get(hset);
    if (fset == NULL) {
        errno = EBADF;
        return -1;
    }

    fd_contex* fdctx = (fd_contex *) handle_get(handle);
    if (fdctx == NULL) {
        errno = EBADF;
        handle_put(hset);
        return -1;
    }

    int n = fdset_add_fdctx(fset, fdctx);
    handle_put(handle);
    handle_put(hset);
    return n;
}

void fdset_put(void* hset)
{
    handle_dettach((my_handle *) hset);
}

int fdset_update_fdmask(my_handle* handle)
{
    fd_contex* fdctx = (fd_contex *) handle_get(handle);
    if (fdctx == NULL) {
        errno = EBADF;
        return -1;
    }

    errno = ENOENT;
    // Once has been added to epoll/kevent,
    // will never be deleted until fdset or fd_contex destroying.
    // As a result, no locking is needed here.
    // For I hold fdctx currently,
    // meaning fd_contex will not be destroyed without my permission.
    // and if fdset is being destroyed cocurrently, the code
    // handle_get(fdctx->hset) will return NULL to break execution.
    // So when I reached fdset_add_fd, it is safe to call it.
    if (0 == fdctx->token.round) {
        handle_put(handle);
        return -1;
    }

    fdset* fset = (fdset *) handle_get(fdctx->hset);
    if (fset == NULL) {
        handle_put(handle);
        return -1;
    }

    int n = fdset_watch(fset, fdctx);
    handle_put(fdctx->hset);
    handle_put(handle);
    return n;
}

fd_struct* fd_struct_from(void* any)
{
    if (any == NULL) {
        return NULL;
    }

    fd_contex* fdctx = (fd_contex *) any;
    struct fd_struct* fds = fdctx->fds;
    return fds;
}

static void do_task_proc(my_buffer* mbuf)
{
    struct task* task_ptr = task_get(mbuf);
    my_handle* handle = task_ptr->handle;
    fd_contex* fdctx = (fd_contex *) handle_get(handle);
    if (fdctx == NULL) {
        mbuf->mop->free(mbuf);
        return;
    }

    handle_clone(handle);
    struct fd_struct* fds = fdctx->fds;
    int32_t n = fds->fop->dispose(fds, mbuf);
    handle_put(handle);
    if (n == -1) {
        handle_dettach(handle);
    } else {
        handle_release(handle);
    }
}

static void task_proc(my_handle* hset)
{
    struct list_head* pool = NULL;
    lock_t* task_lck = NULL;
    fdset* fset = (fdset *) handle_get(hset);
    if (fset != NULL) {
        pool = &fset->task_pool;
        task_lck = &fset->task_lck;
        __sync_add_and_fetch(&fset->keep[0], 1);
    }

    while (fset != NULL) {
        my_buffer* mbuf = NULL;
        lock(task_lck);
        if (fset->keep[2] > 0) {
            assert1(!list_empty(pool));
            --fset->keep[2];
            struct list_head* ent = pool->next;
            list_del(ent);
            mbuf = list_entry(ent, my_buffer, head);
        }
        unlock(task_lck);

        if (mbuf != NULL) {
            do_task_proc(mbuf);
        }
        handle_put(hset);

        if (mbuf == NULL) {
            __sync_add_and_fetch(&fset->keep[1], 1);
            futex(&fset->keep[2], FUTEX_WAIT, 0, NULL, NULL, 0);
            __sync_sub_and_fetch(&fset->keep[1], 1);
        }
        fset = (fdset *) handle_get(hset);
    }
    handle_release(hset);
}

int fdset_join2(void* set, volatile int32_t* flag, int32_t* keep)
{
    assert1(*flag == 0);
    my_handle* hset = (my_handle *) set;
    fdset* fset = (fdset *) handle_get(hset);
    if (fset == NULL) {
        *flag = 1;
        errno = EBADF;
        return -1;
    }

    int32_t* old = __sync_val_compare_and_swap(&fset->keep, NULL, keep);
    if (old != NULL && old != keep) {
        handle_put(hset);
        *flag = 1;
        errno = EINVAL;
        return -1;
    }

    handle_clone(hset);
    *flag = 1;

    handle_put(hset);
    task_proc(hset);
    return 0;
}

static void proto_buffer_free(my_buffer* mbuf)
{
    struct task* taskptr = task_get(mbuf);
    handle_release(taskptr->handle);
    struct mbuf_operations* mop_ptr = (struct mbuf_operations *) taskptr->mop;
    mbuf->mop = mop_ptr;
    mop_ptr->free(mbuf);
}

static my_buffer* proto_buffer_clone(my_buffer* mbuf)
{
    struct task* taskptr = task_get(mbuf);
    handle_clone(taskptr->handle);
    struct mbuf_operations* mop_ptr = (struct mbuf_operations *) taskptr->mop;
    mbuf = mop_ptr->clone(mbuf);
    if (mbuf == NULL) {
        handle_release(taskptr->handle);
    }
    return mbuf;
}

static struct mbuf_operations mop = {
    .clone = proto_buffer_clone,
    .free = proto_buffer_free
};

void proto_buffer_post(my_handle* handle, my_buffer* mbuf)
{
    fd_contex* fdctx = (fd_contex *) handle_get(handle);
    assert1(fdctx != NULL);

    fdset* fset = (fdset *) handle_get(fdctx->hset);
    assert1(fset != NULL);

    int64_t tms = now();
    struct task* taskptr = task_get(mbuf);
    handle_clone(fdctx->self);
    taskptr->tms = tms;
    taskptr->handle = fdctx->self;
    taskptr->mop = mbuf->mop;
    mbuf->mop = &mop;

    lock(&fset->task_lck);
    int32_t tasks = ++fset->keep[2];
    list_add_tail(&mbuf->head, &fset->task_pool);
    mbuf = list_entry(fset->task_pool.prev, my_buffer, head);
    taskptr = task_get(mbuf);
    tms -= taskptr->tms;
    unlock(&fset->task_lck);

    int32_t runs = (int32_t) ((tms - 10) / 10);
    if (runs > fset->keep[1]) {
        runs = fset->keep[1];
    }

    if (runs > 0) {
        if (runs > tasks) {
            runs = tasks;
        }
        futex(&fset->keep[2], FUTEX_WAKE, runs, NULL, NULL, 0);
    }

    handle_put(fdctx->hset);
    handle_put(handle);
}
