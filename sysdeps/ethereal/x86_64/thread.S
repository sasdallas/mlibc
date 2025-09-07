
/* Based off of Ironclad sysdeps */
.global __mlibc_thread_entry
__mlibc_thread_entry:
    pop %rdi
    pop %rsi
    pop %rdx

    call __mlibc_thread_main
