#include <sched.h>
#include <errno.h>
#include <bits/ensure.h>

int sched_getscheduler(pid_t pid) {
    MLIBC_MISSING_SYSDEP();
	errno = ENOSYS;
    return -1;
}