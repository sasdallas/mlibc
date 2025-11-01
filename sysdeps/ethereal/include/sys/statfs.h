#ifndef _SYS_STATFS_H
#define _SYS_STATFS_H

#ifdef __cplusplus
extern "C" {
#endif

#define __MLIBC_LINUX_OPTION 1
#include <abi-bits/statfs.h>
#undef __MLIBC_LINUX_OPTION

#ifndef __MLIBC_ABI_ONLY

int statfs(const char *__path, struct statfs *__buf);
int fstatfs(int __fd, struct statfs *__buf);
int fstatfs64(int __fd, struct statfs64 *__buf);

#endif /* !__MLIBC_ABI_ONLY */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_STATFS_H */

