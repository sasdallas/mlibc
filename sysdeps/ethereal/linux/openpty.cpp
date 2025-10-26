
#include <asm/ioctls.h>
#include <bits/ensure.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

#include <mlibc/debug.hpp>

#include <sys/syscall.h>

DEFINE_SYSCALL5(openpty, SYS_OPENPTY, int*, int*, char*, const struct termios*, const struct winsize *);

int openpty(int *mfd, int *sfd, char *name, const struct termios *ios, const struct winsize *win) {
    int err = __syscall_openpty(mfd, sfd, name, ios, win);
    if (err < 0) {
        errno = -err;
        return -1;
    }

    return 0;
}