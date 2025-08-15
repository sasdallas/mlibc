#include <sys/syscall.h>
#include <sys/syscall_nums.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct __mmap_context {
    void *addr;
    size_t len;
    int prot;
    int flags;
    int filedes;
    off_t off;
};

DEFINE_SYSCALL1(exit, SYS_EXIT, int);
DEFINE_SYSCALL3(open, SYS_OPEN, const char *, int, mode_t);
DEFINE_SYSCALL3(write, SYS_WRITE, int, void *, size_t);
DEFINE_SYSCALL3(read, SYS_READ, int, void *, size_t);
DEFINE_SYSCALL1(mmap, SYS_MMAP, struct __mmap_context*);
DEFINE_SYSCALL2(munmap, SYS_MUNMAP, void *, size_t);
DEFINE_SYSCALL3(mprotect, SYS_MPROTECT, void *, size_t, int)
DEFINE_SYSCALL3(lseek, SYS_LSEEK, int, off_t, int);
DEFINE_SYSCALL1(close, SYS_CLOSE, int);
DEFINE_SYSCALL1(settls, SYS_SETTLS, uintptr_t);

namespace mlibc {

    void sys_libc_log(const char *message) {
        __syscall_write(1, (char*)message, strlen(message));
    }

    void sys_libc_panic() {
        sys_libc_log("\033[0;31mCRITICAL:\033[0m mlibc panic detected\n");
        sys_exit(1);
    }

    void sys_exit(int status) {
        __syscall_exit(status);
        sys_libc_panic();
        __builtin_unreachable();
    }

    int sys_read(int fd, void *buf, size_t n, ssize_t *bytes_read) {
        long err = __syscall_read(fd, buf, n);

        if (err < 0) {
            return err;
        }

        *bytes_read = err;
        return 0; 
    }

    int sys_write(int fd, void *buf, size_t n, ssize_t *bytes_written) {
        long err = __syscall_write(fd, buf, n);

        if (err < 0) {
            return err;
        }

        *bytes_written = err;
        return 0;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
        long error = __syscall_lseek(fd, offset, whence);

        if (error < 0) {
            return error;
        }

        *new_offset = error;
        return 0;
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        long error = __syscall_open(pathname, flags, mode);
        
        if (error < 0) {
            return error;
        }

        *fd = error;
        return 0;
    }

    int sys_close(int fd) {
        return __syscall_close(fd);
    }

    int sys_vm_map(void *addr, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        struct __mmap_context ctx = {
            .addr = addr,
            .len = size,
            .prot = prot,
            .flags = flags,
            .filedes = fd,
            .off = offset,
        };

        long ret = __syscall_mmap(&ctx);
        if ((int)ret < 0) {
            *window = MAP_FAILED;
            return (int)ret;
        }

        *window = (void*)ret;
        return 0;
    }

    int sys_vm_unmap(void *pointer, size_t size) {
        return __syscall_munmap(pointer, size);
    }

    int sys_vm_protect(void *pointer, size_t size, int prot) {
        return __syscall_mprotect(pointer, size, prot);
    }

    int sys_anon_allocate(size_t size, void **pointer) {
        return sys_vm_map(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0, pointer);
    }

    int sys_anon_free(void *pointer, size_t size) {
        return sys_vm_unmap(pointer, size);
    }

    int sys_tcb_set(void *pointer) {
        return __syscall_settls((uintptr_t)pointer);
    }
    
};