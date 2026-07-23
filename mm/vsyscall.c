#include <vsyscall.h>
#include <mmio.h>
#include <stdint.h>

/* Avoid syscall.h here (needs thread_t); Linux x86_64 numbers only. */
enum {
    VSYS_NR_gettimeofday = 96,
    VSYS_NR_time         = 201,
    VSYS_NR_getcpu       = 309,
};

extern uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6);

static int vsys_uread_u64(uint64_t uaddr, uint64_t *out) {
    if (!out) return -1;
    if (uaddr < 0x200000ULL || uaddr + 8ULL > (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    *out = *(volatile uint64_t *)(uintptr_t)uaddr;
    return 0;
}

/*
 * Linux vsyscall=emulate: user CALL/JMP to 0xffffffffff600xxx faults; we run the
 * matching syscall and return to the address the CALL pushed.
 */
int vsyscall_try_emulate(cpu_registers_t *regs) {
    if (!regs) return 0;
    uint64_t rip = regs->rip;
    if (rip < VSYSCALL_PAGE || rip >= VSYSCALL_PAGE_END)
        return 0;

    uint64_t off = rip - VSYSCALL_PAGE;
    uint64_t nr;
    if (off < 0x400ULL)
        nr = (uint64_t)VSYS_NR_gettimeofday;
    else if (off < 0x800ULL)
        nr = (uint64_t)VSYS_NR_time;
    else if (off < 0xc00ULL)
        nr = (uint64_t)VSYS_NR_getcpu;
    else
        return 0;

    uint64_t ret = 0;
    if (vsys_uread_u64(regs->rsp, &ret) != 0)
        return 0;
    if (ret < 0x10000ULL || ret >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return 0;

    regs->rsp += 8;
    regs->rax = syscall_do(nr, regs->rdi, regs->rsi, regs->rdx,
                           regs->r10, regs->r8, regs->r9);
    regs->rip = ret;
    return 1;
}
