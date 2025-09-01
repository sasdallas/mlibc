#include <asm/ioctls.h>
#include <bits/ensure.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <sys/syscall.h>
#include <sys/syscall_nums.h>
#include <sys/ioctl_ethereal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <termios.h>
#include <string.h>

struct __mmap_context {
    void *addr;
    size_t len;
    int prot;
    int flags;
    int filedes;
    off_t off;
};

// !!!: This USED to be required, but its still here?
struct sockopt_params {
    int socket;
    int level;
    int option_name;
    const void *option_value;
    socklen_t option_len;
};

struct __pselect_context {
    int nfds;
    fd_set *readfds;
    fd_set *writefds;
    fd_set *errorfds;
    const struct timespec *timeout;
    const sigset_t *sigmask;
};


/* System call definitions */
DEFINE_SYSCALL1(exit, SYS_EXIT, int);
DEFINE_SYSCALL3(open, SYS_OPEN, const char *, int, mode_t);
DEFINE_SYSCALL3(write, SYS_WRITE, int, const void*, size_t);
DEFINE_SYSCALL3(read, SYS_READ, int, const void*, size_t);
DEFINE_SYSCALL1(mmap, SYS_MMAP, struct __mmap_context*);
DEFINE_SYSCALL2(munmap, SYS_MUNMAP, void *, size_t);
DEFINE_SYSCALL3(mprotect, SYS_MPROTECT, void *, size_t, int);
DEFINE_SYSCALL3(lseek, SYS_LSEEK, int, off_t, int);
DEFINE_SYSCALL1(close, SYS_CLOSE, int);
DEFINE_SYSCALL1(settls, SYS_SETTLS, uintptr_t);
DEFINE_SYSCALL3(ioctl, SYS_IOCTL, int, unsigned long, void*);
DEFINE_SYSCALL0(getpid, SYS_GETPID);
DEFINE_SYSCALL0(getgid, SYS_GETGID);
DEFINE_SYSCALL0(getuid, SYS_GETUID);
DEFINE_SYSCALL0(geteuid, SYS_GETEUID);
DEFINE_SYSCALL0(getegid, SYS_GETEGID);
DEFINE_SYSCALL0(gettid, SYS_GETTID);
DEFINE_SYSCALL0(getppid, SYS_GETPPID);
DEFINE_SYSCALL1(getpgid, SYS_GETPGID, pid_t);
DEFINE_SYSCALL3(wait, SYS_WAIT, pid_t, int*, int);
DEFINE_SYSCALL3(execve, SYS_EXECVE, const char*, const char **, char**);
DEFINE_SYSCALL0(fork, SYS_FORK);
DEFINE_SYSCALL2(dup2, SYS_DUP2, int, int);
DEFINE_SYSCALL3(poll, SYS_POLL, struct pollfd*, nfds_t, int);
DEFINE_SYSCALL1(setuid, SYS_SETUID, uid_t);
DEFINE_SYSCALL1(setgid, SYS_SETGID, gid_t);
DEFINE_SYSCALL0(setsid, SYS_SETSID);
DEFINE_SYSCALL1(seteuid, SYS_SETEUID, uid_t);
DEFINE_SYSCALL1(setegid, SYS_SETEGID, gid_t);
DEFINE_SYSCALL2(setpgid, SYS_SETPGID, pid_t, pid_t);
DEFINE_SYSCALL2(getcwd, SYS_GETCWD, char*, size_t);
DEFINE_SYSCALL1(chdir, SYS_CHDIR, const char*)
DEFINE_SYSCALL1(fchdir, SYS_FCHDIR, int);
DEFINE_SYSCALL3(readdir, SYS_READDIR, struct dirent*, int, unsigned long);
DEFINE_SYSCALL3(read_entries, SYS_READ_ENTRIES, int, void*, size_t);
DEFINE_SYSCALL2(stat, SYS_STAT, const char*, struct stat*);
DEFINE_SYSCALL2(fstat, SYS_FSTAT, int, struct stat*);
DEFINE_SYSCALL2(lstat, SYS_LSTAT, const char*, struct stat*);
DEFINE_SYSCALL4(socketpair, SYS_SOCKETPAIR, int, int, int, int*);
DEFINE_SYSCALL3(socket, SYS_SOCKET, int, int, int);
DEFINE_SYSCALL3(recvmsg, SYS_RECVMSG, int, struct msghdr*, int);
DEFINE_SYSCALL3(sendmsg, SYS_SENDMSG, int, const struct msghdr*, int);
DEFINE_SYSCALL2(listen, SYS_LISTEN, int, int);
DEFINE_SYSCALL5(getsockopt, SYS_GETSOCKOPT, int, int, int, void*, socklen_t*);
DEFINE_SYSCALL1(setsockopt, SYS_SETSOCKOPT, struct sockopt_params*);
DEFINE_SYSCALL3(accept, SYS_ACCEPT, int, struct sockaddr*, socklen_t *);
DEFINE_SYSCALL3(bind, SYS_BIND, int, const struct sockaddr*, socklen_t);
DEFINE_SYSCALL3(connect, SYS_CONNECT, int, const struct sockaddr*, socklen_t);
DEFINE_SYSCALL3(getpeername, SYS_GETPEERNAME, int, struct sockaddr*, socklen_t*);
DEFINE_SYSCALL3(getsockname, SYS_GETSOCKNAME, int, struct sockaddr*, socklen_t*);
DEFINE_SYSCALL1(usleep, SYS_USLEEP, useconds_t);
DEFINE_SYSCALL3(sigprocmask, SYS_SIGPROCMASK, int, const sigset_t*, sigset_t*);
DEFINE_SYSCALL3(sigaction, SYS_SIGACTION, int, const struct sigaction*, struct sigaction*);
DEFINE_SYSCALL2(kill, SYS_KILL, pid_t, int);
DEFINE_SYSCALL1(pselect, SYS_PSELECT, struct __pselect_context*);
DEFINE_SYSCALL1(pipe, SYS_PIPE, int*);
DEFINE_SYSCALL2(gethostname, SYS_GETHOSTNAME, char*, size_t);
DEFINE_SYSCALL2(sethostname, SYS_SETHOSTNAME, const char *, size_t);
DEFINE_SYSCALL2(gettimeofday, SYS_GETTIMEOFDAY, struct timeval*, void*);
DEFINE_SYSCALL2(settimeofday, SYS_SETTIMEOFDAY, struct timeval*, void*);
DEFINE_SYSCALL1(uname, SYS_UNAME, struct utsname *);
DEFINE_SYSCALL2(mkdir, SYS_MKDIR, const char *, mode_t);
DEFINE_SYSCALL2(access, SYS_ACCESS, const char *, int);
DEFINE_SYSCALL3(readlink, SYS_READLINK, const char*, char*, size_t);
DEFINE_SYSCALL4(ptrace, SYS_PTRACE, enum __ptrace_request, pid_t, void*, void*);
DEFINE_SYSCALL3(setitimer, SYS_SETITIMER, int, const struct itimerval*, struct itimerval*);


namespace mlibc {

    void sys_libc_log(const char *message) {
        __syscall_write(2, (char*)message, strlen(message));
        __syscall_write(2, "\n", 1);
    }

    void sys_libc_panic() {
        sys_libc_log("\n\033[0;31mINTERNAL ERROR:\033[0m mlibc panic detected!\n");
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
            return -err;
        }

        *bytes_read = err;
        return 0; 
    }

    int sys_write(int fd, const void *buf, size_t n, ssize_t *bytes_written) {
        ssize_t err = __syscall_write(fd, buf, n);

        if (err < 0) {
            return -err;
        }

        *bytes_written = err;
        return 0;
    }

    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
        long error = __syscall_lseek(fd, offset, whence);

        if (error < 0) {
            return -error;
        }

        *new_offset = error;
        return 0;
    }

    int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
        int error = __syscall_open(pathname, flags, mode);
        
        if (error < 0) {
            return -error;
        }

        *fd = error;
        return 0;
    }

    int sys_close(int fd) {
        return -__syscall_close(fd);
    }

    int sys_mkdir(const char *path, mode_t mode) {
        return -__syscall_mkdir(path, mode);
    }

    int sys_vm_map(void *addr, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        struct __mmap_context ctx;
        ctx.addr = addr;
        ctx.len = size;
        ctx.prot = prot;
        ctx.flags = flags;
        ctx.filedes = fd;
        ctx.off = offset;

        long ret = __syscall_mmap(&ctx);
        if (ret < 0) {
            mlibc::infoLogger() << "mlibc: mmap failed due to error " << ret << frg::endlog;
            *window = MAP_FAILED;
            return -(ret);
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
        return sys_vm_map(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, pointer);
    }

    int sys_anon_free(void *pointer, size_t size) {
        return sys_vm_unmap(pointer, size);
    }

    int sys_tcb_set(void *pointer) {
        return __syscall_settls((uintptr_t)pointer);
    }
  
    int sys_clock_get(int clock, time_t *secs, long *nanos) {
        struct timeval t;
        long err;
        switch (clock) {
            case CLOCK_REALTIME:    
                err = __syscall_gettimeofday(&t, NULL);
                if (err < 0) return -err;
                *secs = t.tv_sec;
                *nanos = t.tv_usec * 1000;
                return 0;

            default:
                mlibc::infoLogger() << "mlibc: clock ID " << clock << " not implemented" << frg::endlog;
                return ENOSYS;
        }
    }

    int sys_access(const char *path, int mode) {
        return -__syscall_access(path, mode);
    }

    int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
        long error = __syscall_wait(pid, status, flags);

        if (error < 0)  {
            return -error;
        }

        *ret_pid = (pid_t)error;
        return 0;
    }

    int sys_execve(const char *path, char *const argv[], char *const envp[]) {
        long error = __syscall_execve(path, (const char**)argv, (char**)envp);
        if (error < 0) {
            return -error;
        }
       
        return 0;
    }

    int sys_fork(pid_t *child) {
        long error = __syscall_fork();
        if (error < 0) return -error;
        *child = error;
        return 0;
    }

    int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
        long err = __syscall_ioctl(fd, request, arg);
        if (err < 0) {
            return -err;
        }

        *result = err;
        return 0;
    }

    int sys_isatty(int fd) {
        int is_tty = 0;
        long error = __syscall_ioctl(fd, IOCTLTTYIS, &is_tty);

        if (error < 0) {
            return ENOTTY;
        }

        return 0;
    }

    int sys_ptsname(int fd, char *buffer, size_t length) {
        long error = __syscall_ioctl(fd, IOCTLTTYNAME, buffer);

        mlibc::infoLogger() << "ethereal: sys_ptsname returned \"" << buffer << "\"" << frg::endlog;

        if (error < 0) return -error;
        return 0;
    }

    /* DUP */

    int sys_dup2(int fd, int flags, int newfd) {
        long error = __syscall_dup2(fd, newfd);
        if (error < 0) return -error;
        return 0;
    }

    int sys_dup(int fd, int flags, int *newfd) {
        int ret = __syscall_dup2(fd, -1);
        if (ret < 0) return -ret;
        *newfd = ret;
        return 0;
    }

    /* POLL + SELECT */

    int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
        long error = __syscall_poll(fds, count, timeout);
        if (error < 0) return -error;
        *num_events = error;
        return 0;
    }

    int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
        struct __pselect_context ctx = {
            .nfds = num_fds,
            .readfds = read_set,
            .writefds = write_set,
            .errorfds = except_set,
            .timeout = timeout,
            .sigmask = sigmask,
        };

        long err = __syscall_pselect(&ctx);
        if (err < 0) return -err;
        *num_events = err;
        return 0;
    }

    /* ID */

    gid_t sys_getgid() { return __syscall_getgid(); }
    gid_t sys_getegid() { return __syscall_getegid(); }
    uid_t sys_getuid() { return __syscall_getuid(); }
    uid_t sys_geteuid() { return __syscall_geteuid(); }
    pid_t sys_getpid() { return __syscall_getpid(); }
    pid_t sys_gettid() { return __syscall_gettid(); }
    pid_t sys_getppid() { return __syscall_getppid(); }
    pid_t sys_getpgid(pid_t pid, pid_t *pgid) {
        long err = __syscall_getpgid(pid);
        if (err < 0) return -err;
        *pgid = err;
        return 0;
    }

    int sys_setpgid(pid_t pid, pid_t pgid) {
        long err = __syscall_setpgid(pid, pgid);
        return -err;
    }

    int sys_setsid(pid_t *sid) {
        long error = __syscall_setsid();
        if (error < 0) return -error;
        *sid = error;
        return 0;
    }

    /* FUTEX */

    int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
        sys_libc_log("mlibc: sys_futex_wait is stub\n");
        // sys_libc_panic();
        return 0;
    } 

    int sys_futex_wake(int *pointer) {
        sys_libc_log("mlibc: sys_futex_wake is stub\n");
        // sys_libc_panic();
        return 0;
    }

    /* CWD */
    
    int sys_getcwd(char *buffer, size_t size) {
        // !!!
        memset(buffer, 0, size);

        // getcwd
        long err = __syscall_getcwd(buffer, size);
        if (err < 0) return -(err);
        return 0;
    }

    int sys_chdir(const char *path) {
        return -(__syscall_chdir(path));
    }
    
    int sys_fchdir(int fd) {
        return -(__syscall_fchdir(fd));
    }
    
    /* READLINK */
    int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) {
        long err = __syscall_readlink(path, (char*)buffer, max_size);
        if (err < 0) return -err;
        *length = err;
        return 0;
    }

    /* Directories */
    int sys_open_dir(const char *path, int *handle) {
        return sys_open(path, O_DIRECTORY, 0, handle);
    }

    int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
        // mlibc requires us to read a ton of entries at once for some reason, maybe just compatibility
        // Anyways repeated readdir calls go
        long err = __syscall_read_entries(handle, buffer, max_size);
        if (err < 0) return -(err);
        
        *bytes_read = err;
        return 0;
    }

    /* Stat */
    int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
        if (fsfdt == fsfd_target::fd) {
            // Targeting file descriptor, fstat.
            return -(__syscall_fstat(fd, statbuf));
        } else if (fsfdt == fsfd_target::path) {
            return -(__syscall_lstat(path, statbuf));
        } else if (fsfdt == fsfd_target::fd_path) {
            mlibc::infoLogger() << "mlibc: fsfd_target::fd_path unimplemented" << frg::endlog;
            return ENOSYS;
        } else {
            mlibc::panicLogger() << "mlibc: fsfd_target is invalid" << frg::endlog;
            __builtin_unreachable();
        }
    }

    /* SOCKETS */
    int sys_socket(int family, int type, int protocol, int *fd) {
        long err = __syscall_socket(family, type, protocol);
        if (err < 0) return -err;
        *fd = err;
        return 0;
    }

    
    int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length) {
        long err = __syscall_sendmsg(fd, hdr, flags);
        if (err < 0) return -err;
        *length = err;
        return 0;
    }

    ssize_t sys_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
        struct iovec iov = {
            .iov_base = (void*)buffer,
            .iov_len = size,
        };
    
        struct msghdr msg_hdr = {
            .msg_name = (void*)sock_addr,
            .msg_namelen = addr_length,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
        };

        return sys_msg_send(fd, &msg_hdr, flags, length);
    }

    int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length) {
        long err = __syscall_recvmsg(fd, hdr, flags);
        if (err < 0) return -err;
        *length = err;
        return 0;
    }

    ssize_t sys_recvfrom(int fd, void *buffer, size_t size, int flags, struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = size
        };
    
        struct msghdr message = {
            .msg_name = sock_addr,
            .msg_namelen = addr_length ? *addr_length : 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    
        ssize_t result = sys_msg_recv(fd, &message, flags, length);
        if (addr_length) *addr_length = message.msg_namelen;    // Update result
        return result;
    }

    int sys_listen(int fd, int backlog) {
        long err = __syscall_listen(fd, backlog);
        return -(err);
    }

    int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) {
        long err = __syscall_getsockopt(fd, layer, number, buffer, size);
        return -err;
    } 
        
    int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) {
        struct sockopt_params params = {
            .socket = fd,
            .level = layer,
            .option_name = number,
            .option_value = buffer,
            .option_len = size
        };

        return -(__syscall_setsockopt(&params));
    }


    int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
        long err = (__syscall_accept(fd, addr_ptr, addr_length));
        if (err < 0) return -err;
        *newfd = err;
        return 0;
    }

    int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        long err = (__syscall_bind(fd, addr_ptr, addr_length));
        return -err;
    }

    int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
        long err = __syscall_connect(fd, addr_ptr, addr_length);
        return -err;
    }

    int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) {
        socklen_t len = max_addr_length;
        long err = __syscall_getsockname(fd, addr_ptr, &len);
        if (err < 0) return -err;
        *actual_length = len;
        return 0;
    }

    int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) {
        socklen_t len = max_addr_length;
        long err = __syscall_getpeername(fd, addr_ptr, &len);
        if (err < 0) return -err;
        *actual_length = len;
        return 0;
    }

    /* SLEEP */
    int sys_sleep(time_t *secs, long *nanos) {
        useconds_t usec = (*secs * 1000000) + (*nanos/1000);
        __syscall_usleep(usec);
        return 0;
    }

    /* SIGNAL */

    int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
        long err = __syscall_sigprocmask(how, set, retrieve);
        return -err;
    }
    
    int sys_sigaction(int signum, const struct sigaction *__restrict act,
		struct sigaction *__restrict oact) {
        long err = __syscall_sigaction(signum, act, oact);
        return -err;
    }

    int sys_kill(int pid, int sig) {
        long err = __syscall_kill(pid, sig);
        return -err;
    }

    /* TERMIOS */

    int sys_tcgetattr(int fd, struct termios *attr) {
        return -__syscall_ioctl(fd, TCGETS, attr);
    }

    int sys_tcsetattr(int fd, int optional, const struct termios *attr) {
        switch (optional) {
            case TCSADRAIN:
                return -__syscall_ioctl(fd, TCSETSW, (void*)attr);
            case TCSAFLUSH:
                return -__syscall_ioctl(fd, TCSETSF, (void*)attr);
            case TCSANOW:
            default:
                return -__syscall_ioctl(fd, TCSETS, (void*)attr);
        }
    }

    /* PIPE */

    int sys_pipe(int *fds, int flags) {
        long ret = __syscall_pipe(fds);
        return -ret;
    }

    /* HOSTNAME */
    int sys_gethostname(char *buffer, size_t bufsize) {
        return -(__syscall_gethostname(buffer, bufsize));
    }

    int sys_sethostname(const char *buffer, size_t bufsize) {
        return -(__syscall_sethostname(buffer, bufsize));
    }

    /* FCNTL */
    int sys_fcntl(int fd, int request, va_list args, int *result) {
        mlibc::infoLogger() << "mlibc: fcntl is unimplemented, received request " << request << " for fd " << fd << frg::endlog;
        return ENOSYS;
    }

    /* UNAME */
    int sys_uname(struct utsname *buf) {
        return -(__syscall_uname(buf));
    }

    /* FSYNC */
    int sys_fsync(int fd) {
        // mlibc::infoLogger() << "mlibc: fsync is unimplemented" << frg::endlog;
        return 0;
    }

    /* RANDOM */
    #ifndef MLIBC_BUILDING_RTLD
    int sys_getentropy(void *buffer, size_t length) {
        int fd;
        if (sys_open("/device/random", O_RDONLY, 0, &fd)) {
            mlibc::panicLogger() << "mlibc: /device/random: " << strerror(errno) << frg::endlog;
        }

        ssize_t bytes;
        int err = sys_read(fd, buffer, length, &bytes); 
        if (err) {
            mlibc::infoLogger() << "mlibc: reading from /device/random failed: " << strerror(errno) << frg::endlog;
            return err;
        }

        sys_close(fd);
        return 0;
    }
    #endif

    /* PTRACE */
    int sys_ptrace(long req, pid_t pid, void *addr, void *data, long *out) {
        long err = __syscall_ptrace((enum __ptrace_request)req, pid, addr, data);
        if (err < 0) return -err;
        *out = err;
        return 0;
    }

    /* IO */
    int sys_unlinkat(int fd, const char *path, int flags) {
        mlibc::infoLogger() << "mlibc: sys_unlinkat is unimplemented" << frg::endlog;
        return 0;
    }

    /* SETITIMER */
    int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
        long ret = __syscall_setitimer(which, new_value, old_value);
        return ret;
    }
};