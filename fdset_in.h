
#ifndef fdset_in_h
#define fdset_in_h

#include "my_handle.h"
#include "mbuf.h"
#include <sys/cdefs.h>
#include <netinet/in.h>

#ifdef __linux__
#include <sys/epoll.h>
#elif defined __APPLE__
#include <sys/event.h>
#define EPOLLIN     1
#define EPOLLOUT    2
#endif

typedef struct fd_struct fd_struct;
typedef struct {
    int32_t (*push) (fd_struct*, my_buffer* mbuf, struct sockaddr_in* in);
    int32_t (*pull) (fd_struct*, my_buffer** mbuf, struct sockaddr_in** in);
    void (*detach) (fd_struct*);
    struct my_buffer* (*buffer_get) (fd_struct*, uint32_t bytes);
    int32_t (*dispose) (fd_struct*, my_buffer* mbuf);
    void (*notify) (fd_struct*, intptr_t* id);
} fds_ops;

struct fd_struct {
    int fd;
    int tcp0_udp1;
    int32_t mask;
    uint32_t bytes;
    fds_ops* fop;
    void* priv;
};

__BEGIN_DECLS

my_handle* fdset_attach_fd(void* fset, struct fd_struct* fds);
my_handle* fdset_make_handle(void* set, struct fd_struct* fds);
intptr_t* sched_handle_alloc(intptr_t id);
int fdset_sched(my_handle* handle, uint32_t ms, intptr_t* id);
void sched_handle_free(intptr_t* id);

// do not call it more than one time
int fdset_attach_handle(void* set, my_handle* handle);
int fdset_update_fdmask(my_handle* handle);
fd_struct* fd_struct_from(void* any);

struct task {
    my_handle* handle;
    void* mop;
    int64_t tms;
};

#define task_bytes ((uint32_t) sizeof(struct task))
#define task_get(mbuf) ((struct task *) (intptr_t) (roundup(((uintptr_t) mbuf->ptr[1] + mbuf->length), (uintptr_t) sizeof(char *))))
void proto_buffer_post(my_handle* handle, my_buffer* mbuf);

__END_DECLS
#endif
