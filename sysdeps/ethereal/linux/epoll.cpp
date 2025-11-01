#include <sys/epoll.h>
#include <errno.h>
#include <bits/ensure.h>


int epoll_create(int size) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
}

int epoll_wait(int epfd, struct epoll_event *event, int maxevents, int timeout) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
}