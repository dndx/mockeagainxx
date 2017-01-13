/*
 * Copyright 2016-2017 <Datong Sun (dndx@idndx.com)>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include "utils.h"
#if __linux__
#include <sys/epoll.h>
#endif

enum {
    MOCKIN  = 0x01,
    MOCKOUT = 0x02
};

typedef struct {
    char              *matchbuf;
    char              *matchbuf_pos; /* next location to write */
    epoll_data_t       ep_data;
    unsigned           ep_seen; /* already returned by epoll? */
    unsigned           out_timeout:1;
    /* whether (E)POLLOUT events should be suppressed */
    unsigned           readable:1; /* do we think this file is read/writeable? */
    unsigned           writeable:1; /* primarily used by epoll in ET */
    unsigned           did_read:1;
    unsigned           did_write:1;
    unsigned           epollet:1; /* edge triggering? */
    unsigned           active:1;
    unsigned           is_stream_sock:1;
} mock_ctx_t;

#define DEFAULT_MAX_FDS 1024

static int          enabled; /* which mode(s) are enabled? */
static int          max_fd = -1;
static mock_ctx_t  *ctx;
static const char  *pattern;
static size_t       pattern_len;

static int (*socket_handle)(int domain, int type, int protocol);
static int (*poll_handle)(struct pollfd *ufds, unsigned int nfds,
                          int timeout);
static ssize_t (*writev_handle)(int fildes, const struct iovec *iov,
                                int iovcnt);
static ssize_t (*send_handle)(int sockfd, const void *buf, size_t len,
                              int flags);
static ssize_t (*read_handle)(int fd, void *buf, size_t count);
static ssize_t (*recv_handle)(int sockfd, void *buf, size_t len,
                              int flags);
static ssize_t (*recvfrom_handle)(int sockfd, void *buf, size_t len,
                                  int flags, struct sockaddr *src_addr,
                                  socklen_t *addrlen);
static int (*close_handle)(int fd);
static int (*ioctl_handle)(int fd, unsigned long request, ...);

/* stolen from https://gist.github.com/diabloneo/9619917 */
struct timespec timespec_diff(struct timespec *start, struct timespec *stop) {
    struct timespec result;

    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result.tv_sec = stop->tv_sec - start->tv_sec - 1;
        result.tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result.tv_sec = stop->tv_sec - start->tv_sec;
        result.tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return result;
}

void init_and_get_ctx(int fd) {
    mock_ctx_t *c = ctx + fd;
    char *matchbuf = c->matchbuf;

    memset(c, 0, sizeof(mock_ctx_t));

    c->active = c->is_stream_sock = 1;

    if (pattern) {
        memset(matchbuf, 0, pattern_len);
        c->matchbuf_pos = c->matchbuf = matchbuf;
    }

}

void ensure_room_for(int fd) {
    int i;

    if (fd <= max_fd) {
        /* nothing to do */
        return;
    }

    fd--;
    fd |= fd >> 1;
    fd |= fd >> 2;
    fd |= fd >> 4;
    fd |= fd >> 8;
    fd |= fd >> 16;
    fd++;

    debug("resizing ctx from %d to %d", max_fd, fd);

    ctx = realloc(ctx, (fd + 1) * sizeof(mock_ctx_t)); /* [0, fd] */
    if (!ctx) {
        free(ctx);
        fatal("realloc failed");
    }

    memset(ctx + max_fd + 1, 0, (fd - max_fd) * sizeof(mock_ctx_t));

    if (pattern) {
        for (i = max_fd + 1; i <= fd; i++) {
            ctx[i].matchbuf = malloc(pattern_len);
            if (!ctx[i].matchbuf) {
                fatal("malloc failed");
            }
        }
    }

    max_fd = fd;
}

/* write a byte to the ring buffer, if there is a match
 * after the write, set timeout flag */
void write_and_check_match(mock_ctx_t *c, char b) {
    size_t i;
    char *p;

    *(c->matchbuf_pos) = b;
    c->matchbuf_pos = c->matchbuf_pos == c->matchbuf + pattern_len - 1 ? \
                      c->matchbuf : c->matchbuf_pos + 1;

    fwrite(c->matchbuf, sizeof(char), pattern_len, stderr);
    fprintf(stderr, "\n");
    log("pos = %c", *(c->matchbuf_pos));
    for (i = 0, p = c->matchbuf_pos; i < pattern_len; i++) {
        if (pattern[i] != *p) {
            return;
        }

        p = p == c->matchbuf + pattern_len - 1 ? \
            c->matchbuf : p + 1;
    }

    log("write_and_check_match found a match");
    c->out_timeout = 1;
}

#if __linux__
static int (*accept4_handle)(int socket, struct sockaddr *address,
                             socklen_t *address_len, int flags);
static int (*epoll_wait_handle)(int epfd, struct epoll_event *events,
                                int nevents, int timeout);
static int (*epoll_ctl_handle)(int epfd, int op, int fd,
                              struct epoll_event *event);

int accept4(int socket, struct sockaddr *address,
            socklen_t *address_len, int flags) {
    int fd;
    mock_ctx_t *c;

    fd = accept4_handle(socket, address, address_len, flags);
    if (fd < 0) {
        return fd;
    }

    ensure_room_for(fd);
    c = ctx + fd;
    c->is_stream_sock = 1;

    if (flags & SOCK_NONBLOCK) {
        log("accept4 marked fd=%d for mocking", fd);
        init_and_get_ctx(fd);
    }

    return fd;
}

int close(int fd) {
    log("close fd = %d", fd);

    if (fd <= max_fd) {
        ctx[fd].active = 0;
    }

    return close_handle(fd);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    mock_ctx_t *c;
    log("epoll_ctl called, fd = %d, op = %d, events = %u", fd, op,
        event->events);

    if (fd > max_fd) {
        log("epoll_ctl fd = %d"
            " that is greater than max_fd = %d",
            fd, max_fd);
        goto end;
    }

    c = ctx + fd;
    c->ep_data = event->data; /* backup data field */
    event->data.fd = fd;

    if (op & (EPOLL_CTL_ADD | EPOLL_CTL_MOD)) {
        if (event->events & EPOLLET) {
            log("epoll_ctl fd = %d is using ET mode", fd);
            c->epollet = 1;
        } else {
            c->epollet = 0;
        }
    } else { /* EPOLL_CTL_DEL */
        c->epollet = 0;
    }

    c->readable = c->writeable = 0;

end:
    return epoll_ctl_handle(epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events,
               int nevents, int timeout) {
    mock_ctx_t         *c;
    struct epoll_event *tmp_events;
    int                 ret, i, j, fd, rdy = 0;
    struct timespec     start, end;

    log("epoll_wait called, timeout = %d", timeout);

    for (i = 0; i <= max_fd; i++) {
        ctx[i].ep_seen = 0;
    }

    for (i = 0; i <= max_fd; i++) { /* TODO: efficiency */
        c = ctx + i;
        if (c->active && c->epollet
            && (
                   (c->readable && c->did_read)
                   || (!c->out_timeout && c->writeable && c->did_write)
               )
           ) {
            rdy++;
            break;
        }
    }

    if (clock_gettime(CLOCK_REALTIME, &start)) {
        fatal("clock_gettime failed: %s", strerror(errno));
    }

    ret = epoll_wait_handle(epfd, events, nevents, rdy ? 0 : timeout);

    if (clock_gettime(CLOCK_REALTIME, &end)) {
        fatal("clock_gettime failed: %s", strerror(errno));
    }

    if (ret >= 0) {
        for (i = 0; i < ret; i++) {
            fd = events[i].data.fd;

            if (fd > max_fd) {
                log("epoll_wait returned fd = %d"
                    " that is greater than max_fd = %d",
                    fd, max_fd);
                continue;
            }

            c = ctx + fd;
            if (!c->active) {
                log("epoll_wait ignored inactive fd = %d", fd);
                continue;
            }

            log("epoll_wait: real epoll returned: fd = %d, events = %d",
                fd, events[i].events);

            if (c->out_timeout && (events[i].events & EPOLLOUT)) {
                log("epoll_wait is suppressing EPOLLOUT event"
                    " due to matched pattern");
                events[i].events &= ~EPOLLOUT;

                if (!events[i].events) {
                    ret--;
                    log("epoll_wait suppressed one returned");
                    continue;
                }
            }

            if (c->epollet) {
                c->writeable = c->writeable || (events[i].events & EPOLLOUT);
                c->readable = c->readable || (events[i].events & EPOLLIN);

                if (!c->out_timeout && c->writeable && c->did_write) {
                    events[i].events |= EPOLLOUT;
                }

                if (c->readable && c->did_read) {
                    events[i].events |= EPOLLIN;
                }
            } else {
                c->writeable = (events[i].events & EPOLLOUT) != 0;
                c->readable = (events[i].events & EPOLLIN) != 0;
            }

            c->ep_seen = 1;
        }

        for (rdy = 0, i = 0; i <= max_fd; i++) { /* TODO: efficiency */
            c = ctx + i;
            /*debug("fd = %d, active = %u, epollet = %u, ep_seen = %u,"
                    " did_read = %u, readable = %u, "
                  "did_write = %u, writeable = %u", i, c->active,
                  c->epollet, c->ep_seen, c->did_read, c->readable,
                  c->did_write, c->writeable); */
            if (c->active && c->epollet && !c->ep_seen
                && (
                       (c->did_read && c->readable)
                       || (!c->out_timeout && c->writeable && c->did_write)
                   )
               ) {
                rdy++;
            }
        }

        if (!(ret + rdy)) { /* nothing to return */
            log("epoll_wait suppressed all available events");
            if (timeout < 0) {
                log("epoll_wait sleeping indefinitely until signal arrives");
                ret = pause();
                /* errno = EINTR set by pause */
            } else {
                end = timespec_diff(&start, &end);

                timeout -= end.tv_sec * 1000 +
                           end.tv_nsec / 1000000;
                end.tv_sec = timeout / 1000;
                end.tv_nsec = (timeout % 1000) * 1000000;

                /* timeout could be < 0 or 0 if real epoll timedout */
                if (timeout > 0 && (end.tv_sec || end.tv_nsec)) {
                    ret = nanosleep(&end, NULL);
                    if (ret && errno != EINTR) {
                        fatal("nanosleep failed unexpectedly: %s"
                              " timeout: %d end.tv_sec: %ld end.tv_nsec: %ld",
                              strerror(errno), timeout,
                              end.tv_sec, end.tv_nsec);
                    }
                }
            }
        } else { /* we have something to return */
            log("epoll_wait returning %d events, %d from real epoll and %d"
                 " from emulated ET", ret + rdy, ret, rdy);
            tmp_events = calloc(ret + rdy, sizeof(struct epoll_event));
            if (!tmp_events) {
                fatal("malloc failed");
            }

            /* find all the events */
            for (i = 0, j = 0; j < ret; i++) {
                c = ctx + events[i].data.fd;

                if (events[i].events) {
                    memcpy(tmp_events + j, events + i,
                           sizeof(struct epoll_event));

                    c->did_read = 0;
                    c->did_write = c->did_write && c->out_timeout;

                    tmp_events[j].data = c->ep_data;
                    j++;
                }
            }

            /* ET case */
            for (c = ctx, i = 0; i < rdy; c++) {
                if (c->active && c->epollet && !c->ep_seen
                    && (
                           (c->did_read && c->readable)
                           || (!c->out_timeout && c->writeable && c->did_write)
                       )
                   ) {
                    /* constrict the event ourself */
                    if (c->readable) {
                        tmp_events[ret + i].events |= EPOLLIN;
                    }

                    if (!c->out_timeout && c->writeable) {
                        tmp_events[ret + i].events |= EPOLLOUT;
                    }

                    tmp_events[ret + i].data = c->ep_data;

                    log("epoll_wait constructed event that real epoll"
                         " did not return, fd = %ld, events = %d", c - ctx,
                         tmp_events[ret + i].events);

                    i++;
                    c->did_read = 0;
                    c->did_write = c->did_write && c->out_timeout;
                }
            }

            if (nevents > ret + rdy) {
                nevents = ret + rdy;
            }
            memcpy(events, tmp_events,
                   sizeof(struct epoll_event) * nevents);
            free(tmp_events);

            ret += rdy;
        }
    }

    return ret;

}
#endif /* __linux__ */

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    int ret;
    void *data;
    mock_ctx_t *c = ctx + fd;

    va_start(ap, request);
    data = va_arg(ap, void *);

    if (request == FIONBIO && c->is_stream_sock) {
        if (*((int *) data)) {
            log("ioctl marked fd=%d for mocking", fd);
            init_and_get_ctx(fd);
        } else {
            c->active = 0;
        }
    }

    ret = ioctl_handle(fd, request, data);

    va_end(ap);
    return ret;
}

int socket(int domain, int type, int protocol) {
    int fd;
    mock_ctx_t *c;

    fd = socket_handle(domain, type, protocol);

    if (fd < 0 || !(type & SOCK_STREAM)) {
        return fd;
    }

    ensure_room_for(fd);
    c = ctx + fd;
    c->is_stream_sock = 1;

    return fd;
}

int poll(struct pollfd *ufds, nfds_t nfds, int timeout) {
    struct timespec  start, end;
    int              ret, i, fd;
    mock_ctx_t      *c;

    log("poll() called");

    if (clock_gettime(CLOCK_REALTIME, &start)) {
        fatal("clock_gettime failed: %s", strerror(errno));
    }

    ret = poll_handle(ufds, nfds, timeout);

    if (clock_gettime(CLOCK_REALTIME, &end)) {
        fatal("clock_gettime failed: %s", strerror(errno));
    }

    if (ret > 0) {
        for (i = 0; i < nfds; i++) {
            fd = ufds[i].fd;

            if (fd > max_fd) {
                log("poll returned fd = %d that is greater than max_fd = %d",
                    fd, max_fd);
                continue;
            }

            c = ctx + fd;
            if (!c->active) {
                log("poll ignored inactive fd = %d", fd);
                continue;
            }

            if (c->out_timeout && (ufds[i].revents & POLLOUT)) {
                log("poll is suppressing POLLOUT event"
                    " due to matched pattern");
                ufds[i].revents &= ~POLLOUT;

                if (!ufds[i].revents) {
                    ret--;
                    continue;
                }
            }

            c->writeable = (ufds[i].revents & POLLOUT) != 0;
            c->readable = (ufds[i].revents & POLLIN) != 0;
            c->did_read = 0;
            c->did_write = c->did_write && c->out_timeout;
        }

        if (!ret) { /* we suppressed all available (write) events */
            log("poll suppressed all write events and no read events"
                " are available");
            if (timeout < 0) {
                log("poll sleeping indefinitely until signal arrives");
                ret = pause();
                /* errno = EINTR set by pause */
            } else {
                end = timespec_diff(&start, &end);

                timeout -= end.tv_sec * 1000 +
                           end.tv_nsec / 1000000;
                end.tv_sec = timeout / 1000;
                end.tv_nsec = (timeout % 1000) * 1000000;

                if (timeout > 0 && (end.tv_sec || end.tv_nsec)) {
                    ret = nanosleep(&end, NULL);
                    if (ret && errno != EINTR) {
                        fatal("nanosleep failed unexpectedly: %s",
                              strerror(errno));
                    }
                }
            }
        }
    }

    return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t       total_bytes = 0;
    struct iovec  new_iov = {NULL, 0};
    int           i, ret;
    mock_ctx_t   *c;

    if (fd > max_fd || !(enabled & MOCKOUT)) {
        log("writev mocking is not active, fd = %d", fd);
        goto skip;
    }

    c = ctx + fd;

    if (!c->active) {
        log("writev mocking is not active, fd = %d", fd);
        goto skip;
    }

    if (c->did_write) {
        log("writev is returning EAGAIN for fd = %d", fd);
        errno = EAGAIN;
        return -1;
    }

    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_base && iov[i].iov_len && !new_iov.iov_base) {
            new_iov.iov_base = iov[i].iov_base;
            new_iov.iov_len = 1; /* only write 1 byte */
        }

        total_bytes += iov[i].iov_len;
    }

    if (!new_iov.iov_base) {
        goto skip;
    }

    if (pattern) {
        write_and_check_match(c, *((char *) new_iov.iov_base));
    }

    log("writev writing 1 out of %zd bytes, fd = %d", total_bytes, fd);

    c->did_write = 1;

    ret = writev_handle(fd, &new_iov, 1);
    if (ret < 0 && errno == EAGAIN) {
        c->writeable = 0;
    }
    return ret;

skip:
    return writev_handle(fd, iov, iovcnt);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    mock_ctx_t   *c;
    int           ret;

    if (fd > max_fd || !(enabled & MOCKOUT)) {
        log("send mocking is not active");
        goto skip;
    }

    c = ctx + fd;

    if (!c->active) {
        log("send mocking is not active");
        goto skip;
    }

    if (c->did_write) {
        log("send is returning EAGAIN for fd = %d", fd);
        errno = EAGAIN;
        return -1;
    }

    if (!(buf && len)) {
        goto skip;
    }

    if (pattern) {
        write_and_check_match(c, *((char *) buf));
    }

    log("send writing 1 out of %zd bytes", len);

    c->did_write = 1;

    ret = send_handle(fd, buf, 1, flags);
    if (ret < 0 && errno == EAGAIN) {
        c->writeable = 0;
    }
    return ret;

skip:
    return send_handle(fd, buf, len, flags);
}

ssize_t read(int fd, void *buf, size_t len) {
    mock_ctx_t   *c;
    int           ret;

    if (fd > max_fd || !(enabled & MOCKIN)) {
        log("read mocking is not active");
        goto skip;
    }

    c = ctx + fd;

    if (!c->active) {
        log("read mocking is not active");
        goto skip;
    }

    if (c->did_read) {
        log("read is returning EAGAIN for fd = %d", fd);
        errno = EAGAIN;
        return -1;
    }

    log("read is reading 1 out of %zd bytes requested", len);

    ret = read_handle(fd, buf, 1);
    if (ret < 0 && errno == EAGAIN) {
        c->readable = 0;
    }

    c->did_read = 1;

    return ret;

skip:
    return read_handle(fd, buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    mock_ctx_t   *c;
    int           ret;

    if (fd > max_fd || !(enabled & MOCKIN)) {
        log("recv mocking is not active");
        goto skip;
    }

    c = ctx + fd;

    if (!c->active) {
        log("recv mocking is not active");
        goto skip;
    }

    if (c->did_read) {
        log("recv is returning EAGAIN for fd = %d", fd);
        errno = EAGAIN;
        return -1;
    }

    log("recv is reading 1 out of %zd bytes requested", len);

    ret = recv_handle(fd, buf, 1, flags);
    if (ret < 0 && errno == EAGAIN) {
        c->readable = 0;
    }

    c->did_read = 1;

    return ret;

skip:
    return recv_handle(fd, buf, len, flags);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    mock_ctx_t   *c;
    int           ret;

    if (fd > max_fd || !(enabled & MOCKIN)) {
        log("recvfrom mocking is not active");
        goto skip;
    }

    c = ctx + fd;

    if (!c->active) {
        log("recvfrom mocking is not active");
        goto skip;
    }

    if (c->did_read) {
        log("recvfrom is returning EAGAIN for fd = %d", fd);
        errno = EAGAIN;
        return -1;
    }

    log("recvfrom is reading 1 out of %zd bytes requested", len);

    ret = recvfrom_handle(fd, buf, 1, flags, src_addr, addrlen);
    if (ret < 0 && errno == EAGAIN) {
        c->readable = 0;
    }

    c->did_read = 1;

    return ret;

skip:
    return recvfrom_handle(fd, buf, len, flags, src_addr, addrlen);
}

__attribute__ ((__constructor__))
static void init(void) {
    const char *p;

    /* get function handles */
    socket_handle = dlsym(RTLD_NEXT, "socket");
    poll_handle = dlsym(RTLD_NEXT, "poll");
    writev_handle = dlsym(RTLD_NEXT, "writev");
    send_handle = dlsym(RTLD_NEXT, "send");
    read_handle = dlsym(RTLD_NEXT, "read");
    recv_handle = dlsym(RTLD_NEXT, "recv");
    recvfrom_handle = dlsym(RTLD_NEXT, "recvfrom");
    close_handle = dlsym(RTLD_NEXT, "close");
    ioctl_handle = dlsym(RTLD_NEXT, "ioctl");
#if __linux__
    accept4_handle = dlsym(RTLD_NEXT, "accept4");
    epoll_wait_handle = dlsym(RTLD_NEXT, "epoll_wait");
    epoll_ctl_handle = dlsym(RTLD_NEXT, "epoll_ctl");
    if (!(accept4_handle && epoll_wait_handle && epoll_ctl_handle)) {
        fatal("failed to initialize linux specific handles");
    }
#endif

    if (!(socket_handle && poll_handle && writev_handle && send_handle &&
          read_handle && recv_handle && recvfrom_handle && close_handle &&
          ioctl_handle)) {
        fatal("failed to initialize one or more glibc handles");
    }

    /* verbose? */
    p = getenv("MOCKEAGAIN_VERBOSE");
    if (p) {
        verbose = 1;
    }

    /* init enabled flag */
    p = getenv("MOCKEAGAIN");
    if (!p) {
        debug("MOCKEAGAIN environment missing, mocking is not active");
    } else {
        do {
            if (*p == 'r' || *p == 'R') {
                log("read mocking is enabled");
                enabled |= MOCKIN;
            } else if (*p == 'w' || *p == 'W') {
                log("write mocking is enabled");
                enabled |= MOCKOUT;
            }
        } while (*++p);
    }

    /* pattern */
    pattern = getenv("MOCKEAGAIN_WRITE_TIMEOUT_PATTERN");
    if (pattern) {
        pattern_len = strlen(pattern);
    }

    /* init_ctx */
    ensure_room_for(DEFAULT_MAX_FDS);

    debug("mockeagainxx init successful");
}
