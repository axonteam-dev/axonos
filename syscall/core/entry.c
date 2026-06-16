#include "syscall_internal.h"


uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    uint64_t ret = syscall_do_inner(num, a1, a2, a3, a4, a5, a6);
    syscall_deferred_unblocks();
    return ret;
}

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    /* Record user rip/rsp for int0x80 path so fork/vfork can find return site. */
    syscall_user_return_rip = regs->rip;
    syscall_user_rsp_saved = regs->rsp;
    if (syscall_user_return_rip == 0) {
        debug_dump_kernel_syscall_stack();
    }
    /* Match Linux x86_64 syscall ABI: args 4–6 are r10, r8, r9 (same as SYSCALL path in syscall.S). */
    regs->rax = syscall_do(regs->rax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
    /* If userspace called exit/exit_group via int0x80 path, do not iret back to ring3. */
    if (syscall_exit_to_shell_flag) {
        syscall_return_to_shell();
    }
}

void syscall_init(void) {
    /* register handler on vector 0x80 */
    idt_set_handler(0x80, isr_syscall);

    /* Enable x86_64 SYSCALL instruction for userland. */
    uint64_t efer = msr_read_u64(MSR_EFER);
    efer |= 1ULL; /* EFER.SCE */
    msr_write_u64(MSR_EFER, efer);
    /* STAR: kernel CS selector in bits 47:32, SS = CS+8 */
    uint64_t star = ((uint64_t)(KERNEL_CS & 0xFFFFu)) << 32;
    msr_write_u64(MSR_STAR, star);
    msr_write_u64(MSR_LSTAR, (uint64_t)(uintptr_t)syscall_entry64);
    /* On SYSCALL entry, clear IF and DF to avoid reentrancy and broken string ops.
       IF bit = 9, DF bit = 10 in RFLAGS. */
    msr_write_u64(MSR_FMASK, (1ULL << 9) | (1ULL << 10));

    klogprintf("syscall: int0x80+SYSCALL ok; mmap cap < USER_STACK_TOP=0x%llx; stub loads lz4 payload — replace full axonos.elf (build=mmap-mod-2026-05-15)\n",
        (unsigned long long)(uint64_t)USER_STACK_TOP);
}


