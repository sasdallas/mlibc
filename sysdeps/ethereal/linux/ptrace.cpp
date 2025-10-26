// Taken from mlibc linux option
#include <sys/ptrace.h>
#include <stdarg.h>
#include <errno.h>

#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/syscall.h>


DEFINE_SYSCALL4(ptrace, SYS_PTRACE, enum __ptrace_request, pid_t, void*, void*);

int sys_ptrace(long req, pid_t pid, void *addr, void *data, long *out) {
	long err = __syscall_ptrace((enum __ptrace_request)req, pid, addr, data);
	if (err < 0) return -err;
	*out = err;
	return 0;
}

long ptrace(int req, ...) {
	va_list ap;

	va_start(ap, req);
	auto pid = va_arg(ap, pid_t);
	auto addr = va_arg(ap, void *);
	auto data = va_arg(ap, void *);
	va_end(ap);

	long ret;
	if(req > 0 && req < 4) {
		data = &ret;
	}

	long out;
	if(int e = sys_ptrace(req, pid, addr, data, &out); e) {
		errno = e;
		return -1;
	} else if(req > 0 && req < 4) {
		errno = 0;
		return ret;
	}

	return out;
}

