#include "syscall_internal.h"

/* Saved user RSP for syscall_entry64 (legacy/debug helper). */
uint64_t syscall_user_rsp_saved = 0;
/* Legacy global syscall stack top (kept for fallback/debug paths). */
uint64_t syscall_kernel_rsp0 = 0;
/* Per-APIC-id syscall stack tops. syscall_entry64 picks stack from this table. */
uint64_t syscall_kernel_rsp0_by_apic[256] = { 0 };

static inline int syscall_lapic_id(void) {
    return (int)((*(volatile uint32_t *)(uintptr_t)0xFEE00020ULL) >> 24) & 0xFF;
}

void syscall_bind_kstack_for_thread(thread_t *t) {
    int apic = syscall_lapic_id();
    uint64_t sp = 0;
    if (t && t->syscall_kstack_top)
        sp = t->syscall_kstack_top;
    else if (syscall_kernel_rsp0)
        sp = syscall_kernel_rsp0;
    else
        sp = syscall_kernel_rsp0_by_apic[apic];
    if (!sp) return;
    syscall_kernel_rsp0_by_apic[apic] = sp;
    syscall_kernel_rsp0 = sp;
}

/* Saved user RIP for SYSCALL path (RCX at syscall entry). Used by fork/vfork helpers. */
uint64_t syscall_user_return_rip = 0;
/* Last userspace-visible return value from syscall_do before signal delivery. */
uint64_t syscall_user_return_rax = 0;
/* Saved callee-saved user registers captured by syscall_entry64.
   vfork needs these to resume the parent code path correctly in the child. */
uint64_t syscall_user_saved_rbx = 0;
uint64_t syscall_user_saved_rbp = 0;
uint64_t syscall_user_saved_r12 = 0;
uint64_t syscall_user_saved_r13 = 0;
uint64_t syscall_user_saved_r14 = 0;
uint64_t syscall_user_saved_r15 = 0;
/* Caller-saved regs snapshot (some libc/syscall stubs may rely on these immediately after SYSCALL). */
uint64_t syscall_user_saved_rdi = 0;
uint64_t syscall_user_saved_rsi = 0;
uint64_t syscall_user_saved_rdx = 0;
uint64_t syscall_user_saved_r8  = 0;
uint64_t syscall_user_saved_r9  = 0;
uint64_t syscall_user_saved_r10 = 0;
uint64_t syscall_user_saved_rcx = 0;
uint64_t syscall_user_saved_r11 = 0;
/* Set to non-zero when user called exit/exit_group; handled in syscall_entry64. */
uint64_t syscall_exit_to_shell_flag = 0;
/* When non-zero, assembly entry will skip overwriting saved rax slot so trampoline-patched
   values remain in the syscall stack. apply_exec_trampoline sets this before returning. */
uint64_t syscall_exec_trampoline_active = 0;
/* per-thread saved values copied from syscall_entry64 globals at syscall start */
