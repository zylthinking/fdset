
#include "fdset_in.h"
#include "fdctx.h"
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <linux/futex.h>
#include <unistd.h>

#ifdef __ANDROID__
    #ifndef EPOLLRDHUP
    #define EPOLLRDHUP 0x2000
    #endif

    #ifndef EPOLLONESHOT
    #define EPOLLONESHOT (1 << 30)
    #endif
    #include <sys/socket.h>
#endif

static int check_connection(int fd)
{
    int error = 0;
    socklen_t len = sizeof(error);
    int n = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (n == -1 || error != 0) {
        mark("check_connection error = (%d)%d\n", n, error);
        return -1;
    }
    return 0;
}

static uint32_t epoll_event_mask(struct fd_struct* fds, uint32_t events)
{
    uint32_t mask = 0;
    if (mask & EPOLLHUP) {
        int n = check_connection(fds->fd);
        if (n == -1) {
            events |= EPOLLERR;
        }
    }

    if (events & EPOLLERR) {
        return EPOLLERR;
    }

    if (events & (EPOLLIN | EPOLLPRI | EPOLLRDNORM | EPOLLRDBAND | EPOLLRDHUP)) {
        mask |= EPOLLIN | (events & EPOLLRDHUP);
    }

    if (events & (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)) {
        mask |= EPOLLOUT;
    }
    return mask;
}

static int32_t tcp_read(int fd, struct my_buffer* mbuf, struct sockaddr_in* unused)
{
    (void) unused;

    while (mbuf->length > 0) {
        int n = (int) recv(fd, mbuf->ptr[1], mbuf->length, 0);
        if (n == 0) {
            errno = ESHUTDOWN;
            return -1;
        }

        if (n > 0) {
            mbuf->ptr[1] += n;
            mbuf->length -= n;
            continue;
        }

        if (EINTR == errno) {
            continue;
        }

        if (EWOULDBLOCK == errno) {
            errno = EAGAIN;
        }
        return -1;
    }
    return 0;
}

static int32_t udp_read(int fd, struct my_buffer* mbuf, struct sockaddr_in* addr)
{
    int n;
    do {
        socklen_t sz = sizeof(struct sockaddr_in);
        n = (int) recvfrom(fd, mbuf->ptr[1], mbuf->length, 0, (struct sockaddr *) addr, &sz);
    } while (n == -1 && errno == EINTR);

    if (n > 0) {
        mbuf->ptr[1] += n;
        mbuf->length = 0;
        n = 0;
    } else {
        errno = EAGAIN;
        n = -1;
    }
    return n;
}

static int32_t tcp_write(int fd, struct my_buffer* mbuf, struct sockaddr_in* unused)
{
    (void) unused;
    int n = 0, nr = 0;

    while (mbuf->length > 0) {
        n = (int) send(fd, mbuf->ptr[1], (size_t) mbuf->length, MSG_NOSIGNAL);
        if (n == -1) {
            if (EINTR == errno) {
                continue;
            }

            if (EWOULDBLOCK == errno) {
                errno = EAGAIN;
            }
            return -1;
        }

        if (__builtin_expect(n == 0, 0)) {
            if (++nr > 16) {
                n = -1;
                errno = EBADF;
                return -1;
            }
        } else {
            mbuf->length -= n;
            mbuf->ptr[1] += n;
            nr = 0;
        }
    }
    return 0;
}

static int32_t udp_write(int fd, struct my_buffer* mbuf, struct sockaddr_in* addr)
{
    do {
        int bytes = (int) sendto(fd, mbuf->ptr[1], mbuf->length, 0, (struct sockaddr *) addr, sizeof(*addr));
        if (bytes > 0) {
            mbuf->ptr[1] += mbuf->length;
            mbuf->length = 0;
            return 0;
        }

        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            errno = EAGAIN;
            break;
        }
    } while (errno == EINTR);
    return -1;
}

__attribute__((constructor))
static void init()
{
    static implement_t imp = {
        .key = tcp_key,
        .event_mask = epoll_event_mask,
        .read = tcp_read,
        .write = tcp_write
    };
    implement_register(&imp);

    static implement_t imp2 = {
        .key = udp_key,
        .event_mask = epoll_event_mask,
        .read = udp_read,
        .write = udp_write
    };
    implement_register(&imp2);
}
