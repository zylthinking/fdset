
#ifndef zyl_h
#define zyl_h

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#ifdef _MSC_VER
#include "wcc.h"
#endif

#ifndef imex
#define imex
#endif

#ifdef __cplusplus
#define capi extern "C" imex
#else
#define capi extern imex
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type *) ((intptr_t) ptr - (intptr_t) __builtin_offsetof(type, member)))
#endif

#ifndef roundup
#define roundup(bytes, align) (((bytes) + (align) - 1) & (~((align) - 1)))
#endif

#define event_number(x) (0 == (x & (x - 1)))
#define elements(x) (sizeof(x) / sizeof(x[0]))
typedef int (*printf_t) (const char* fmt, ...);

#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#define systid() ((uintptr_t) syscall(__NR_gettid))
#elif defined(__APPLE__)
#include <sys/syscall.h>
#define systid() ((uintptr_t) syscall(SYS_thread_selfid))
#endif

#if (defined(__GNUC__)) || (defined(__clang__))
#define typeof(x) __typeof__(x)
#define barrier() __asm__ __volatile__("":::"memory")
#if (defined(__arm__)) || (defined(__arm64__))
#if (defined(__ARM_ARCH_7A__) || defined(__arm64__))
#define rmb() __asm__ __volatile__ ("dsb sy":::"memory")
#define wmb() __asm__ __volatile__ ("dsb sy":::"memory")
#else
#define rmb()
#define wmb()
#endif
#else
#define rmb() __asm__ __volatile__("lfence":::"memory")
#define wmb() __asm__ __volatile__("sfence":::"memory")
#endif
#endif

typedef intptr_t (*notify_t) (void* uptr, intptr_t identy, void* any);
typedef void (*free_t) (void*);
static __attribute__((unused)) void no_free(void* addr){}

typedef struct {
    void* uptr;
    notify_t notify;
    free_t uptr_put;
} callback_t;

capi int64_t now();
capi uint32_t fnv1_hash32(const char* key, uint32_t bytes);

#if (!defined(zyl_malloc) || defined(NDEBUG))
#define debug_mem 0
#else
#define debug_mem 1
#endif

#if debug_mem
    capi void* debug_malloc(size_t n, const char* func, int line);
    capi void debug_free(void* ptr);
    capi size_t debug_mem_bytes();
    capi void debug_mem_stats(printf_t func_ptr);
    capi void my_tell(void* ptr);
    capi void check_memory(void* ptr);

    #define my_malloc(n) debug_malloc(n, __FUNCTION__, __LINE__)
    #define my_free debug_free
    #define mem_bytes debug_mem_bytes
    #define mem_stats debug_mem_stats
#else
    #define debug_malloc(x, y, z) malloc(x)
    #define my_malloc malloc
    #define my_free free
    #define mem_bytes() 0
    #define mem_stats(x) ((void) (0))
    #define my_tell(x) ((void) (0))
    #define check_memory(x) ((void) (0))
#endif

#define heap_alloc(x) (typeof(*x)*) my_malloc(sizeof(*x))
#define heap_alloc2(x, nb) (typeof(*x)*) my_malloc(sizeof(*x) + nb)
#define heap_free my_free

#define fileof(path) \
({ \
    const char* pch = strrchr(path, '/'); \
    if (pch == NULL) { \
        pch = path; \
    } else { \
        pch++; \
    } \
    pch; \
})

#ifdef __ANDROID__
    #include <android/log.h>
    #define log_vprint(fmt, ap) __android_log_vprint(ANDROID_LOG_ERROR, "zylthinking", fmt, ap)
#else
    #define log_vprint(fmt, ap) vfprintf(stderr, fmt, ap)
#endif

capi void logmsg(const char * __restrict fmt, ...);
#define logmsg2(ms, fmt, ...) \
do { \
    static uint32_t next = 0; \
    if (ms < next) { \
        break; \
    } \
    next = ms + 1000 * 3; \
    logmsg(fmt, ##__VA_ARGS__); \
} while (0)

#if 0
    #define mark(...) (void) 0
#else
    #define mark(fmt, ...) logmsg("%d@%s tid %d " fmt "\n", __LINE__, __FUNCTION__, systid(), ##__VA_ARGS__)
#endif

#if defined(NDEBUG)
    #define ctrace(x) do {x;} while (0)
    #define logmsg_d(...) (void) 0
#else
    #if 0
        #define ctrace(x) do {mark(#x " begin"); x; mark(#x " end");} while (0)
    #else
        #define ctrace(x) do {x;} while (0)
    #endif
    #define logmsg_d(...) logmsg(##__VA_ARGS__)
#endif

#define trace_interval(fmt, ...) \
do { \
    static uint32_t x = 0; \
    int cur = now(); \
    if (x == 0) { \
        x = cur; \
    } \
    logmsg("%d@%s: %d " fmt "\n", __LINE__, __FUNCTION__, cur - x, ##__VA_ARGS__); \
    x = cur; \
} while (0)

#define trace_change(x, msg) \
do { \
    static int64_t y = 0; \
    const char* message = msg; \
    if (message == NULL) { \
        message = #x; \
    } \
    if (y != x) { \
        logmsg("%d@%s tid %d %s %lld(%llx) -> %lld(%llx)\n", \
               __LINE__, __FUNCTION__, systid(), message, y, y, (int64_t) x, (int64_t) x); \
        y = (int64_t) x; \
    } \
} while (0)

#define trace_change2(x, fmt, ...) \
do { \
    static int64_t y = 0; \
    if (y != x) { \
        logmsg("%d@%s tid %d %lld(%llx) -> %lld(%llx) " fmt "\n", \
                __LINE__, __FUNCTION__, systid(), y, y, (int64_t) x, (int64_t) x, ##__VA_ARGS__); \
        y = (int64_t) x; \
    } \
} while (0)

#define logbuf(x, buf, len) \
do { \
    const static char* logpath = getenv(“buffile”); \
    static FILE* file = NULL; \
    if (logpath != NULL) { \
        if (file == NULL) { \
            char path[1204] = {0}; \
            sprintf(path, "%s%s", logpath, x); \
            file = fopen(path, "wb"); \
            if (file == NULL) { \
                logmsg("failed to open %s, errno: %d\n", path, errno); \
            } else { \
                logmsg("opened %s %p\n", path, file); \
            } \
        } \
        \
        if (file != NULL) { \
            fwrite(buf, 1, len, file); \
            fflush(file); \
        } \
    } else if (file != NULL) { \
        logmsg("close %p\n", file); \
        fclose(file); \
        file = NULL; \
    } \
} while (0)

#ifdef NDEBUG
#define assert1(...) ((void) 0)
#define assert2(...) ((void) 0)
#else

#ifndef WINVER
capi void backtrace_print(uintptr_t levels);
#else
#define backtrace_print(x) ((void) 0)
#endif

#define assert1(x) \
do { \
    if (!(x)) { \
        mark("of %s, assert failed", fileof(__FILE__)); \
        backtrace_print(16); \
        __builtin_trap(); \
    } \
} while (0)

#define assert2(x, fmt, ...) \
do { \
    if (!(x)) { \
        mark("of %s, assert failed: " fmt, fileof(__FILE__), ##__VA_ARGS__); \
        backtrace_print(16); \
        __builtin_trap(); \
    } \
} while (0)

#endif

#define debug_lock 2
typedef struct {
    intptr_t lck;
    uintptr_t tid;
    uintptr_t nr;
#if debug_lock
    const char* file;
    intptr_t line;
#endif
} lock_t;

#define lock_initial {0}
#define lock_initial_locked {1, 0, 1}
static __attribute__((unused)) lock_t lock_val = lock_initial;
#define lcktp NULL

#if (debug_lock == 2)
#ifdef __linux__
static struct timespec lckt = {
    .tv_sec = 1,
    .tv_nsec = 0
};
#undef lcktp
#define lcktp &lckt
#endif

#define locktrace_begin() uintptr_t tms = now();
#define lock_backtrace(lkp) \
do { \
    uintptr_t current = now(); \
    if (tms == 0) { \
        tms = current; \
    } \
    \
    if (current > tms + 3000) { \
        tms = current - 2000; \
        mark("locktrace: %d %s:%d", (int) lkp->lck, lkp->file, (int) lkp->line); \
    } \
} while (0)
#else
#define locktrace_begin() (void) 0
#define lock_backtrace(x) (void) 0
#endif

#if debug_lock
    #define log_lock(ptr, l, f) do {ptr->line = l; ptr->file = f;} while (0)
    #define log_unlock(ptr) do {ptr->line = -1; ptr->file = "";} while (0)
#else
    #define log_lock(ptr, l, f) (void) (0)
    #define log_unlock(ptr) (void) (0)
#endif

#ifdef __linux__
    #ifndef _GNU_SOURCE
    #define _GNU_SOURCE
    #endif
    #include <linux/futex.h>

    #define my_lock(lkp, re) \
    do {  \
        lock_t* ptr = lkp; \
        if (!__sync_bool_compare_and_swap(&ptr->lck, 0, 1)) { \
            if (ptr->lck == 2) { \
                syscall(__NR_futex, &ptr->lck, FUTEX_WAIT, 2, lcktp, NULL, 0); \
            } \
            \
            locktrace_begin(); \
            while (0 != __sync_lock_test_and_set(&ptr->lck, 2)) { \
                syscall(__NR_futex, &ptr->lck, FUTEX_WAIT, 2, lcktp, NULL, 0); \
                lock_backtrace(ptr); \
            } \
        } \
        assert2(ptr->lck != 0, "lck = %d", ptr->lck); \
        assert2(ptr->nr == 0, "lck = %d, nr = %d, %d@%s", ptr->lck, ptr->nr, ptr->line, ptr->file); \
        log_lock(ptr, __LINE__, __FILE__); \
        \
        assert1(ptr->tid == 0); \
        if (re) { \
            ptr->tid = systid(); \
        } \
        ++ptr->nr; \
    } while (0)

    #define unlock(lkp) \
    do { \
        lock_t* ptr = lkp; \
        assert2(ptr->lck != 0, "lck = %d, nr = %d", ptr->lck, ptr->nr); \
        --ptr->nr; \
        wmb(); \
        if (ptr->nr > 0) { \
            assert2(ptr->tid != 0, "tid != 0, ptr->nr = %d, lck = %d, %d@%s", ptr->nr, ptr->lck, ptr->line, ptr->file); \
        } else { \
            ptr->tid = 0; \
            /* wmb(); */ \
            log_unlock(ptr); \
            if (2 == __sync_lock_test_and_set(&ptr->lck, 0)) { \
                while (-1 == syscall(__NR_futex, &ptr->lck, FUTEX_WAKE, 1, NULL, NULL, 0)); \
            } \
        } \
    } while (0)

#else
    #define my_lock(lkp, re) \
    do {  \
        lock_t* ptr = lkp; \
        locktrace_begin(); \
        while (!__sync_bool_compare_and_swap((void **) &ptr->lck, (void *) 0, (void *) 1)) { \
            sched_yield();  \
            lock_backtrace(ptr); \
        } \
        log_lock(ptr, __LINE__, __FILE__); \
        \
        assert1(ptr->tid == 0); \
        if (re) { \
            ptr->tid = systid(); \
        } \
        ++ptr->nr; \
    } while (0)

    #define unlock(lkp) \
    do { \
        lock_t* ptr = lkp; \
        assert1(ptr->lck != 0); \
        --ptr->nr; \
        wmb(); \
        if (ptr->nr > 0) { \
            assert1(ptr->tid != 0); \
        } else { \
            ptr->tid = 0; \
            /* wmb(); */ \
            log_unlock(ptr); \
            ptr->lck = 0; \
        } \
    } while (0)
#endif

#define lock(lkp) my_lock(lkp, 0)

#define relock(lkp) \
do {  \
    lock_t* ptr = lkp; \
    /* this rmb() is here to assure to see ptr->tid = 0 in unlock */ \
    /* if thread exit after unlock(), then another thread is spwaned with same tid */ \
    /* on another cpu core and then call lock_recursive. */ \
    /* all the above happens so quickly that the other cpu core does not see ptr->tid = 0 */ \
    /* it is so impossible to happen that I comment the "correct" implemention. */ \
    /* rmb(); */ \
    \
    if (ptr->tid == systid()) { \
        /* if true, it's same thread, event in another cpu core, no mb() is needed. */ \
        ++ptr->nr; \
    } else { \
        my_lock(lkp, 1); \
    } \
} while (0)

static __attribute__((unused)) inline intptr_t my_try_lock(lock_t* lkp, uintptr_t re, uintptr_t line, const char* file)
{
    if (!__sync_bool_compare_and_swap((void **) &((lkp)->lck), (void *) 0, (void *) 1)) {
        return -1;
    }
    log_lock(lkp, line, file);

    assert1(lkp->tid == 0);
    if (re) {
        lkp->tid = systid();
    }
    ++lkp->nr;
    return 0;
}

#define try_lock(lkp) my_try_lock(lkp, 0, __LINE__, __FILE__)
#define retry_lock(lkp) my_try_lock(lkp, 1, __LINE__, __FILE__)

typedef struct {
    intptr_t nr;
} rwlock_t;

#define read_write_max 8000
#define rw_lock_initial {read_write_max}
static __attribute__((unused)) rwlock_t rw_lock_val = rw_lock_initial;

#define read_write_lock(lckp, val) \
do { \
    rwlock_t* lck = lckp; \
    do { \
        intptr_t n = __sync_sub_and_fetch(&lck->nr, val); \
        if (n >= 0) { \
            break; \
        } \
        __sync_add_and_fetch(&lck->nr, val); \
        sched_yield(); \
    } while (1); \
} while (0)

#define read_write_unlock(lckp, val) \
do { \
    rwlock_t* lck = lckp; \
    __sync_add_and_fetch(&lck->nr, val); \
} while (0)

#define read_lock(lckp) read_write_lock(lckp, 1)
#define write_lock(lckp) read_write_lock(lckp, read_write_max)
#define read_unlock(lckp) read_write_unlock(lckp, 1)
#define write_unlock(lckp) read_write_unlock(lckp, read_write_max)

#undef capi
#undef imex

#endif
