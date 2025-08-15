/**
 * @file libpolyhedron/include/sys/syscall.h
 * @brief System call
 * 
 * 
 * @copyright
 * This file is part of the Hexahedron kernel, which is apart of the Ethereal Operating System.
 * It is released under the terms of the BSD 3-clause license.
 * Please see the LICENSE file in the main repository for more details.
 * 
 * Copyright (C) 2024 Samuel Stuart
 */


extern "C" {

#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

/* System call instruction */
#define SYSCALL_INSTRUCTION "syscall"
#define SYSCALL_CLOBBERS    "rcx", "r11", "memory"


/* Syscall macros */
#define DEFINE_SYSCALL0(name, num) \
    extern "C" long __syscall_##name() { \
        long __return_value = num;\
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#define DEFINE_SYSCALL1(name, num, p1_type) \
    extern "C" long __syscall_##name(p1_type p1) { \
        long __return_value = num;\
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value), "D"((long)(p1)) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#define DEFINE_SYSCALL2(name, num, p1_type, p2_type) \
    extern "C" long __syscall_##name(p1_type p1, p2_type p2) { \
        long __return_value = num;\
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value), "D"((long)(p1)), "S"((long)(p2)) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#define DEFINE_SYSCALL3(name, num, p1_type, p2_type, p3_type) \
    extern "C" long __syscall_##name(p1_type p1, p2_type p2, p3_type p3) { \
        long __return_value = num;\
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value), "D"((long)(p1)), "S"((long)(p2)), "d"((long)(p3)) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#define DEFINE_SYSCALL4(name, num, p1_type, p2_type, p3_type, p4_type) \
    extern "C" long __syscall_##name(p1_type p1, p2_type p2, p3_type p3, p4_type p4) { \
        long __return_value = num;\
        register long _p4 __asm__("r10") = (long)p4; \
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value), "D"((long)(p1)), "S"((long)(p2)), "d"((long)(p3)), "r"((long)(_p4)) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#define DEFINE_SYSCALL5(name, num, p1_type, p2_type, p3_type, p4_type, p5_type) \
    extern "C" long __syscall_##name(p1_type p1, p2_type p2, p3_type p3, p4_type p4, p5_type p5) { \
        long __return_value = num;\
        register long _p4 __asm__("r10") = (long)p4; \
        register long _p5 __asm__("r8") = (long)p5; \
        asm volatile (SYSCALL_INSTRUCTION \
            : "=a"(__return_value) \
            : "a"(__return_value), "D"((long)(p1)), "S"((long)(p2)), "d"((long)(p3)), "r"((long)(_p4)), "r"((long)(_p5)) : SYSCALL_CLOBBERS); \
        return __return_value;  \
    }

#endif

};