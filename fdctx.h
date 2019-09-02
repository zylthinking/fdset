
#ifndef fdctxpool_h
#define fdctxpool_h

#include "zyl.h"
#include "list_head.h"
#include "mbuf.h"
#include "my_handle.h"
#include "lkf.h"
#include "fdset_in.h"
#include <stdbool.h>

#ifdef __linux__
#include <sys/epoll.h>
#endif

#ifdef __APPLE__
#include <sys/event.h>
#endif

typedef struct {
    uint64_t born;
    uint64_t round;
} token_t;

#define tcp_key 1
#define udp_key 2
#define linux_key 1 << 24
#define freebsd_key 2 << 24

typedef struct {
    struct list_head entry;
    int32_t key;
    uint32_t (*event_mask)(struct fd_struct*, uint32_t);
    int32_t (*read) (int fd, struct my_buffer*, struct sockaddr_in*);
    int32_t (*write) (int fd, struct my_buffer*, struct sockaddr_in*);
} implement_t;

typedef struct {
    // mutx acts 3 roles with no racing
    lock_t mutx;
    my_handle* hset;
    my_handle* self;
    list_head set_entry;
    list_head timer;
    proc_context proc;
    token_t token;
    int32_t mask[2];

#ifdef __APPLE__
    struct kevent event[2];
#endif

    implement_t* imp;
    struct fd_struct* fds;
    struct my_buffer* read_mbuf;
    struct my_buffer* write_mbuf;
    struct sockaddr_in* addr;
} fd_contex;

typedef struct {
    lkf_node node;
    fd_contex* fdctx;
    intptr_t events;
    uint64_t round;
    void (*handler) (fd_contex*, intptr_t, uint64_t);
} proc_t;

static uint64_t atomic_inc_uint64()
{
    static uint64_t seq = 0;
    uint64_t n = 0;
    do {
        n = __sync_add_and_fetch(&seq, 1);
    } while (n == 0);
    return n;
}


#ifdef __cplusplus
extern "C" {
#endif
    fd_contex* fd_contex_get();
    void fd_contex_put(fd_contex* ctx);
    implement_t* implement_by_type(int32_t type);
    void implement_register(implement_t* imp);
#ifdef __cplusplus
}
#endif

#endif
