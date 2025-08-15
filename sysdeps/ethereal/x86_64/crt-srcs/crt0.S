.section .text
.global _start
_start:
    popq %rsi       // argc
    popq %rdx       // argv
    popq %rcx       // envp
    addq $8, %rsp   // auxv

    // The kernel is stupid and doesn't usually align our stack
    // So align the stack to 16-byte boundary (SSE instructions and whatnot need this)
    and $0xFFFFFFFFFFFFFFF0, %rsp

    // Rebuild the stack frame that mlibc expects
    pushq %rcx
    pushq %rdx
    pushq %rsi

    mov %rsp, %rdi
    mov $main, %rsi
    call __mlibc_entry
.section .note.GNU-stack,"",%progbits