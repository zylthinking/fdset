
#ifndef mbuf_h
#define mbuf_h

#include "list_head.h"
#include <stdint.h>

#ifndef capi
#define local_capi
#ifdef __cplusplus
#define capi extern "C"
#else
#define capi
#endif
#endif

typedef struct mem_head_s mem_head;
typedef struct my_buffer my_buffer;
typedef intptr_t (*addref_t)(mem_head *, intptr_t);

struct mem_head_s {
    union {
        list_head head;
        struct {
            intptr_t ref;
            addref_t addref;
        } mem;
    } u;
};

typedef struct mbuf_operations {
    my_buffer* (*clone) (my_buffer*);
    void (*free) (my_buffer*);
} mbuf_operations;

struct my_buffer {
    list_head head;
    mem_head* memh;
    mbuf_operations* mop;

    void* any;
    char* ptr[2];
    uintptr_t length;
};

#define my_buffer_refcount(mbuf) \
({ \
    intptr_t n = 1; \
    if (mbuf->mem_head != NULL) { \
        n = mbuf->u.mem.ref; \
    } \
    n; \
})

#define reset_buffer(mbuf) \
do { \
    intptr_t bytes = (intptr_t) (mbuf->ptr[1] - mbuf->ptr[0]); \
    mbuf->length += bytes; \
} while (0)

capi void mbuf_tell(my_buffer* mbuf);
capi void my_buffer_dump(my_buffer* mbuf);
capi uint32_t free_buffer(list_head* head);
capi uint32_t calc_buffer_length(list_head* head);

capi intptr_t mbuf_hget(uintptr_t bytes, uintptr_t capacity, intptr_t clone);
capi my_buffer* do_mbuf_alloc_1(intptr_t handle, const char* func, int line);
capi void mbuf_reap(intptr_t handle);

capi my_buffer* do_mbuf_alloc_2(uintptr_t bytes, const char* func, int line);
capi my_buffer* do_mbuf_alloc_3(uintptr_t bytes, const char* func, int line);
capi my_buffer* do_mbuf_alloc_4(void* addr, uintptr_t bytes, const char* func, int line);
capi my_buffer* do_mbuf_alloc_5(void* addr, uintptr_t bytes, const char* func, int line);
capi my_buffer* mbuf_alloc_6(void* addr, uintptr_t bytes);

#define mbuf_alloc_1(handle) do_mbuf_alloc_1(handle, __FUNCTION__, __LINE__)
#define mbuf_alloc_2(bytes) do_mbuf_alloc_2(bytes, __FUNCTION__, __LINE__)
#define mbuf_alloc_3(bytes) do_mbuf_alloc_3(bytes, __FUNCTION__, __LINE__)
#define mbuf_alloc_4(addr, bytes) do_mbuf_alloc_4(addr, bytes, __FUNCTION__, __LINE__)
#define mbuf_alloc_5(addr, bytes) do_mbuf_alloc_5(addr, bytes, __FUNCTION__, __LINE__)

#ifdef local_capi
#undef capi
#endif
#endif
