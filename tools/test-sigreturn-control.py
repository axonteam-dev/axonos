#!/usr/bin/env python3
"""Exercise rt_sigreturn's actual restore code for syscall and IRQ signal frames."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("        case SYS_rt_sigreturn: {")
body = source[start:source.index("        case SYS_resolve:", start)]
rebuild_start = source.index("static void rebuild_syscall_frame(thread_t *t) {")
rebuild = source[rebuild_start:source.index("\n}\n", rebuild_start) + 3]
types_start = source.index("#pragma pack(push, 1)", source.index("/* Linux x86_64 rt_sigframe"))
types = source[types_start:source.index("#pragma pack(pop)", types_start) + len("#pragma pack(pop)")]
prepare_start = source.index("void syscall_prepare_iret_frame(")
prepare = source[prepare_start:source.index("\n}\n", prepare_start) + 3]
program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define MMIO_IDENTITY_LIMIT UINT64_MAX
enum { SYS_rt_sigreturn = 15, SYS_resolve = 1000 };
typedef struct {
    uint64_t saved_user_r8, saved_user_r9, saved_user_r10, saved_user_r11;
    uint64_t saved_user_r12, saved_user_r13, saved_user_r14, saved_user_r15;
    uint64_t saved_user_rdi, saved_user_rsi, saved_user_rbp, saved_user_rbx;
    uint64_t saved_user_rdx, saved_user_rcx, saved_user_rip, saved_user_rsp;
    uint64_t saved_sig_mask;
    uint64_t sigreturn_rcx, sigreturn_r11;
    uint8_t sigreturn_restore_gprs;
    uint64_t *saved_syscall_frame;
} thread_t;
static uint64_t syscall_user_rsp_saved_pc[1];
static int syscall_cpu_idx(void) { return 0; }
static thread_t *current;
static thread_t *thread_current(void) { return current; }
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int copy_from_user_raw(void *to, const void *from, size_t n) {
    memcpy(to, from, n); return 0;
}
''' + types + "\n" + rebuild + "\n" + prepare + r'''
_Static_assert(offsetof(k_ucontext_t, uc_stack_ss_flags) == 24, "Linux stack_t flags offset");
_Static_assert(offsetof(k_ucontext_t, uc_stack_ss_size) == 32, "Linux stack_t size offset");
static uint64_t restore(thread_t *cur) {
    switch (SYS_rt_sigreturn) {
''' + body + r'''
    }
    return 0;
}
int main(void) {
    k_ucontext_t uc; memset(&uc, 0, sizeof(uc));
    uint64_t frame[16] = {0};
    thread_t task = {.saved_syscall_frame = frame};
    uc.uc_mcontext.rip = 0x401234;
    uc.uc_mcontext.rsp = 0x5fff0000;
    uc.uc_mcontext.eflags = 0x202;
    uc.uc_mcontext.rcx = 0x123; /* arbitrary RCX at IRQ interruption */
    uc.uc_mcontext.r11 = 0xdeadbeef; /* not RFLAGS */
    uc.uc_mcontext.rax = 77;
    uc.uc_mcontext.rdx = 0x9988;
    uc.uc_sigmask[0] = 0x80;
    task.saved_user_rsp = (uintptr_t)&uc;
    assert(restore(&task) == 77);
    assert(frame[13] == uc.uc_mcontext.rip);
    assert(frame[4] == uc.uc_mcontext.eflags);
    assert(frame[12] == uc.uc_mcontext.rdx);
    assert(frame[15] == uc.uc_mcontext.rsp);
    assert(task.saved_sig_mask == 0x80);
    assert(syscall_user_rsp_saved_pc[0] == uc.uc_mcontext.rsp);
    current = &task;
    frame[14] = 77; /* syscall.S stores rt_sigreturn's restored RAX here */
    uint64_t area[25];
    memcpy(area + 5, frame, sizeof(frame));
    syscall_prepare_iret_frame(area + 5, area);
    assert(area[13] == uc.uc_mcontext.rcx); /* restored general RCX, not RIP */
    assert(area[4] == uc.uc_mcontext.r11); /* restored general R11, not RFLAGS */
    assert(area[14] == 77);
    assert(area[15] == uc.uc_mcontext.rip && area[16] == 0x1b);
    assert(area[17] == uc.uc_mcontext.eflags && area[18] == uc.uc_mcontext.rsp && area[19] == 0x23);
    assert(!task.sigreturn_restore_gprs);
    /* The ordinary syscall-delivery case still resumes the same RIP/flags. */
    uc.uc_mcontext.rcx = uc.uc_mcontext.rip;
    uc.uc_mcontext.r11 = uc.uc_mcontext.eflags;
    task.saved_user_rsp = (uintptr_t)&uc;
    assert(restore(&task) == 77 && frame[13] == uc.uc_mcontext.rip && frame[4] == 0x202);
    memcpy(area + 5, frame, sizeof(frame));
    syscall_prepare_iret_frame(area + 5, area);
    assert(area[13] == uc.uc_mcontext.rcx && area[4] == uc.uc_mcontext.r11);
    /* Normal syscalls still preserve the ordinary GPR image and return value. */
    for (unsigned i = 0; i < 16; i++) frame[i] = 0x100 + i;
    frame[13] = 0x401234; frame[4] = 0x202; frame[15] = 0x5fff0000;
    memcpy(area + 5, frame, sizeof(frame));
    syscall_prepare_iret_frame(area + 5, area);
    for (unsigned i = 0; i < 15; i++) assert(area[i] == frame[i]);
    assert(area[15] == frame[13] && area[17] == frame[4] && area[18] == frame[15]);
    puts("PASS: rt_sigreturn restores IRQ-time RCX/R11 separately from IRET RIP/RFLAGS; normal GPRs unchanged");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sigreturn-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
