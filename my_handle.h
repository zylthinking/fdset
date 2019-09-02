
#ifndef my_handle_h
#define my_handle_h

#include <stdint.h>
#include "zyl.h"

typedef struct my_handle {
    int ref;
    int stack;
    intptr_t detached;
    void* ptr;
    free_t free;
} my_handle;

static inline my_handle* handle_attach(void* ptr, free_t fp_free, const char* func, int line)
{
    my_handle* handle = (my_handle *) debug_malloc(sizeof(my_handle), func, line);
    if (handle != NULL) {
        handle->ref = 1;
        handle->stack = 1;

        handle->ptr = ptr;
        handle->free = fp_free;
        handle->detached = 0;
    }
    return handle;
}

static inline void handle_put(my_handle* handle, const char* func, int line)
{
    int n = __sync_sub_and_fetch(&(handle)->stack, 1);
    assert1(n >= 0);
    if (n == 0) {
        void* handle_ptr = (void *) __sync_lock_test_and_set(&(handle)->ptr, NULL);
        if ((handle)->free && handle_ptr) {
            (handle)->free(handle_ptr);
        }
    }
}

static inline void* handle_get_with(my_handle* handle, int detach, const char* func, int line)
{
    int n = __sync_add_and_fetch(&handle->stack, 1);
    int b = __sync_bool_compare_and_swap((void **) &handle->detached, (void *) 0, (void *) (intptr_t) detach);
    if (!b) {
        handle_put(handle, func, line);
        return NULL;
    }

    void* ptr = handle->ptr;
    assert2(n > 1 && ptr != NULL, "%d, %p, caller %d@%s", n, ptr, line, func);
    return ptr;
}

static inline int handle_clone(my_handle* handle)
{
    int n = __sync_add_and_fetch(&handle->ref, 1);
    assert1(n > 0);
    return n;
}

static inline int handle_release(my_handle* handle, const char* func, int line)
{
    int n = __sync_sub_and_fetch(&handle->ref, 1);
    assert2(n >= 0, "%p %d:%d, caller %d@%s", handle, handle->ref, handle->stack, line, func);
    if (n > 0) {
        return n;
    }

    // it should be safe to simplely check whether detached equals 0.
    // we know __sync_xxx functions have mb() semantics, and
    // if some one set handle->detached = 1, it only can be called in
    // handle_dettach while still holds a reference of handle.
    // ok, now we have seen handle->ref = 0 above, meaning
    // we have observed the latter handle_release in handle_dettach.
    // then, the mb() assure that
    // we have observed the earlier handle_get_with(handle, 1).
    if (handle->detached == 0) {
        handle_put(handle, func, line);
    }
    assert1(handle->stack == 0);

    my_free(handle);
    return n;
}

static inline int handle_dettach(my_handle* handle, const char* func, int line)
{
    void* ptr = handle_get_with(handle, 1, func, line);
    if (ptr != NULL) {
        __sync_sub_and_fetch(&handle->stack, 1);
        handle_put(handle, func, line);
    }
    return handle_release(handle, func, line);
}

#define handle_get(handle) handle_get_with((my_handle *) (handle), 0, __FUNCTION__, __LINE__)
#define handle_clone(handle) handle_clone((my_handle *) handle)
#define handle_attach(ptr, fptr) handle_attach(ptr, fptr, __FUNCTION__, __LINE__)
#define handle_put(h) handle_put((my_handle *) h, __FUNCTION__, __LINE__)
#define handle_release(handle) handle_release((my_handle *) (handle), __FUNCTION__, __LINE__)
#define handle_dettach(handle) handle_dettach((my_handle *) (handle), __FUNCTION__, __LINE__)

#endif
