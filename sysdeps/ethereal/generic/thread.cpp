#include <bits/ensure.h>
#include <mlibc/tcb.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>


/* Based on Ironclad sysdeps */
extern "C" void __mlibc_thread_main(void *(*main)(void*), Tcb *tcb, void *arg) {
    while (__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED) == 0) {
        mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);
    } 

    if (mlibc::sys_tcb_set(tcb)) __ensure(!"sys_tcb_set() failed");

    tcb->invokeThreadFunc(reinterpret_cast<void*>(main), arg);

    __atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);

    mlibc::sys_futex_wake(&tcb->didExit);
    mlibc::sys_thread_exit();
}