#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <bits/ensure.h>

ssize_t fgetxattr(int fd, const char *name, void *val, size_t size) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
}

int setxattr(const char *path, const char *name, const void *val, size_t size, int flags) {
    MLIBC_MISSING_SYSDEP();
    errno = ENOSYS;
    return -1;
} 