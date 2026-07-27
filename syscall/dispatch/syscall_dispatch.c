#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <thread.h>
#include <fpu.h>
#include <fs.h>
#include <mmio.h>
#include <heap.h>
#include <syscall.h>
#include <gdt.h>
#include <paging.h>
#include <exec.h>
#include <pit.h>
#include <ext2.h>
#include <devfs.h>
#include <procfs.h>
#include <sysfs.h>
#include <rtc.h>
#include <spinlock.h>
#include <fat32.h>
#include <e1000.h>
#include <usb.h>
#include <usbdevfs.h>
#include <net_tcp.h>
#include <dns.h>
#include <mm.h>
#include <smp.h>
#include <loadavg.h>
#include <console.h>
#include <font.h>
#include <ramfs.h>
#include <dhcp.h>
#include <debug.h>
#include <klog.h>
#include <fbdev.h>
#include <uapi_linux_fb.h>
#include <power.h>
#include <iothread.h>
#include <stdio.h>
#include <user_vma.h>
#include <user_as.h>

/* Opt-in TCP connect/RX console traces (VGA paint is expensive under VMware). */
#ifndef NET_TCP_TRACE
#define NET_TCP_TRACE 0
#endif
#include <user_map.h>
#include <process.h>
#include <sysinfo.h>
#include <user_mmap.h>
#include <user_brk.h>
#include <user_mm.h>

#define mark_user_identity_range_2m_sys user_map_mark_identity_2m

#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif

/* Linux x86_64 struct stat size; ensures st_mode at correct offset for S_ISREG etc. */
#define STAT_COPY_SIZE 144
#define NET_FRAME_BUF 2048

/* Verbose DNS tracing for threads named "wget" — off by default: heavy klog+fs_write
 * and per-byte kprintf were implicated in heap stress / reentrancy under VMware. */
#ifndef AXON_WGET_DNS_TRACE
#define AXON_WGET_DNS_TRACE 0
#endif

#define ECONNRESET 104

extern void kprintf(const char *fmt, ...);
extern int syscall_pipe_watch_active;

/* Helper exported from core/elf.c */
extern uint64_t virt_to_phys(uint64_t va);

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

__attribute__((noreturn)) void syscall_return_to_shell(void) {
    syscall_exit_to_shell_flag = 0;
    thread_set_current_user(NULL);
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif

static void exit_group_reap_peer_threads(thread_t *cur);
static void sysv_shm_detach_all_for_tid(uint64_t tid);
static void thread_set_pending_signal(thread_t *t, int signum);
static void thread_close_all_fds(thread_t *cur);
static int force_sigkill_thread_group(thread_t *any);

/* True if a signal is pending that should interrupt a blocking syscall.
 * SIGKILL/SIGSTOP are never maskable (Linux). */
static int thread_has_interrupt_signal(thread_t *t) {
    if (!t) return 0;
    uint64_t blocked = t->saved_sig_mask;
    blocked &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (19 - 1))); /* SIGSTOP=19 */
    return (t->pending_signals & ~blocked) != 0;
}

void syscall_user_fatal_exit(int signo) {
    /* Exception handlers run in the context of the faulting thread. Prefer
       thread_current(); current_user can be stale after scheduler handoffs and
       killing it here can terminate PID1 when a child process segfaults. */
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (cur && cur->ring == 3) {
        process_t *proc = cur->process;
        thread_t *leader = (proc && proc->leader) ? proc->leader : cur;
        int status = signo & 0x7f; /* WIFSIGNALED / WTERMSIG */
        {
            thread_t *cu = thread_get_current_user();
            qemu_debug_printf("fatal-exit: signo=%d cur_tid=%llu cur_name=%s parent=%d pgid=%d current_user=%llu/%s\n",
                signo,
                (unsigned long long)(cur->tid ? cur->tid : 1),
                cur->name[0] ? cur->name : "(noname)",
                cur->parent_tid,
                cur->pgid,
                (unsigned long long)(cu && cu->tid ? cu->tid : 0),
                (cu && cu->name[0]) ? cu->name : "(none)");
            kprintf("fatal-exit: sig=%d tid=%llu name=%s parent=%d pgid=%d cu=%llu/%s\n",
                signo,
                (unsigned long long)(cur->tid ? cur->tid : 1),
                cur->name[0] ? cur->name : "(noname)",
                cur->parent_tid,
                cur->pgid,
                (unsigned long long)(cu && cu->tid ? cu->tid : 0),
                (cu && cu->name[0]) ? cu->name : "(none)");
        }
        /*
         * Linux default for synchronous SIGSEGV/SIGILL/SIGBUS: kill the whole
         * thread group (do_group_exit). Releasing only the faulting CLONE_THREAD
         * member's mm left the leader running on a freed address space and
         * wedged the shell (no prompt after curl's DNS worker #PF).
         */
        if (leader->attached_tty >= 0)
            devfs_tty_leave_alt_screen(leader->attached_tty);
        {
            int nt = thread_get_count();
            for (int i = 0; i < nt; i++) {
                thread_t *t = thread_get_by_index(i);
                if (!t || t->ring != 3 || t->state == THREAD_TERMINATED)
                    continue;
                int same = 0;
                if (proc && t->process == proc)
                    same = 1;
                else if (!proc && t == cur)
                    same = 1;
                if (!same)
                    continue;
                devfs_tty_remove_waiter_from_all_ttys(
                    (int)(t->tid ? t->tid : 1));
                if (t->waiter_tid >= 0) {
                    int w = t->waiter_tid;
                    t->waiter_tid = -1;
                    thread_unblock(w);
                }
                t->pending_signals = 0;
                t->exit_status = status;
                t->state = THREAD_TERMINATED;
                sysv_shm_detach_all_for_tid((uint64_t)(t->tid ? t->tid : 1));
                if (t->mm_ptemplate) {
                    mm_release(t->mm_ptemplate);
                    t->mm_ptemplate = NULL;
                }
                if (t->mm && t->mm != mm_kernel()) {
                    mm_t *m = t->mm;
                    t->mm = NULL;
                    if (t == cur)
                        (void)mm_switch_away_from(m);
                    mm_release(m);
                }
            }
        }
        user_vma_remove_all_for_tid((uint64_t)(leader->tid ? leader->tid : 1));
        thread_close_all_fds(leader);
        process_release_vfork_parent(proc, PROCESS_VFORK_FATAL);
        process_mark_zombie(proc, status);
        if (proc) {
            process_t *init_process = NULL;
            int init_tid = thread_get_init_user_tid();
            thread_t *init_thread = init_tid >= 0 ? thread_get(init_tid) : NULL;
            if (init_thread)
                init_process = init_thread->process;
            process_reparent_children(proc, init_process);
        }
        if (leader->parent_tid >= 0) {
            thread_t *pt = thread_get(leader->parent_tid);
            if (pt) {
                thread_set_pending_signal(pt, SIGCHLD);
                thread_unblock((int)(pt->tid ? pt->tid : 1));
                if (leader->attached_tty >= 0 &&
                    pt->attached_tty == leader->attached_tty)
                    devfs_set_tty_fg_pgrp(leader->attached_tty, pt->pgid);
            }
        }
        if (leader->waiter_tid >= 0)
            thread_unblock(leader->waiter_tid);
    }
    thread_set_current_user(NULL);
    thread_schedule();
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

extern void syscall_entry64(void);
/* helper entry for kernel-created user threads (defined in cpu/thread.c) */
extern void user_thread_entry(void);

static int fork_rip_validate_return(thread_t *cur, uint64_t rip);
static uint64_t fork_rip_find_fork_return(thread_t *cur, uint64_t hint);

static void fork_assign_child_return_rip(thread_t *parent, thread_t *child);
static int user_read_u64(const void *uaddr, uint64_t *out);
static int user_read_u8(const void *uaddr, uint8_t *out);

/* Close every fd, collapsing aliases so a wrong refcount cannot double-free. */
static void thread_close_all_fds(thread_t *cur) {
    if (!cur) return;
    process_t *proc = cur->process;
    /*
     * Authoritative table is process->fds. CLONE_THREAD workers open DNS/TCP
     * sockets into that table while leader->fds[n] stays NULL. Walking only
     * the leader's mirror left those sockets in ksock_registry after curl
     * exit — they stole the next curl's UDP DNS replies → error 6.
     */
    if (proc) {
        for (int i = 0; i < PROCESS_MAX_FD && i < THREAD_MAX_FD; i++) {
            struct fs_file *f = proc->fds[i];
            if (!f) continue;
            int n = 0;
            for (int j = i; j < PROCESS_MAX_FD && j < THREAD_MAX_FD; j++) {
                if (proc->fds[j] != f) continue;
                proc->fds[j] = NULL;
                proc->fd_cloexec[j] = 0;
                n++;
            }
            int nt = thread_get_count();
            for (int ti = 0; ti < nt; ti++) {
                thread_t *t = thread_get_by_index(ti);
                if (!t || t->process != proc) continue;
                for (int j = 0; j < THREAD_MAX_FD; j++)
                    if (t->fds[j] == f)
                        t->fds[j] = NULL;
            }
            for (int k = 0; k < n; k++)
                fs_file_free(f);
        }
    }
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        struct fs_file *f = cur->fds[i];
        if (!f) continue;
        int n = 0;
        for (int j = i; j < THREAD_MAX_FD; j++) {
            if (cur->fds[j] == f) {
                cur->fds[j] = NULL;
                n++;
            }
        }
        for (int k = 0; k < n; k++)
            fs_file_free(f);
    }
}

static int fork_user_stack_va_ok(const thread_t *t, uint64_t va) {
    if (va < 0x200000ULL)
        return 0;
    if (t && t->user_stack_base && t->user_stack_limit &&
        va >= t->user_stack_base && va <= t->user_stack_limit)
        return 1;
    return va < 0x80000000ULL;
}

static void fork_child_init_fpstate(void) {
    /* Linux lazy-FPU: first SSE in _Fork child (movups @ libc+0xd437f) #NM's if
     * CR0.TS is still set after our kernel-thread iretq path. clts alone is not
     * always enough; reset x87+SSE control word like a fresh task. */
    asm volatile("clts");
    asm volatile("fninit");
    uint32_t mxcsr = 0x1f80u;
    asm volatile("ldmxcsr %0" :: "m"(mxcsr));
}

static int copy_from_user_raw(void *kdst, const void *usrc, size_t n);
static int copy_to_user_safe(void *uptr, const void *kptr, size_t n);

static void fork_prepare_child_before_iretq(thread_t *child) {
    if (!child || !child->mm) return;
    /*
     * Fork setup already made the return-code mapping user accessible before
     * applying COW. Re-marking it here used to add PG_RW to PG_SOFT_COW leaves,
     * allowing nested fork children to modify their parent's pages directly.
     */
    mm_switch(child->mm);
}

static void fork_build_gpr_snap_from_thread(thread_t *t) {
    if (!t) return;
    t->fork_gpr_snap[0] = t->saved_user_r15;
    t->fork_gpr_snap[1] = t->saved_user_r14;
    t->fork_gpr_snap[2] = t->saved_user_r13;
    t->fork_gpr_snap[3] = t->saved_user_r12;
    t->fork_gpr_snap[4] = t->saved_user_r11;
    t->fork_gpr_snap[5] = t->saved_user_r10;
    t->fork_gpr_snap[6] = t->saved_user_r9;
    t->fork_gpr_snap[7] = t->saved_user_r8;
    t->fork_gpr_snap[8] = t->saved_user_rdi;
    t->fork_gpr_snap[9] = t->saved_user_rsi;
    t->fork_gpr_snap[10] = t->saved_user_rbp;
    t->fork_gpr_snap[11] = t->saved_user_rbx;
    /* Keep saved_user_rdx: glibc clone3 puts start_routine in %rdx (and arg in %r8).
     * Fork/_Fork paths zero saved_user_rdx before calling this. */
    t->fork_gpr_snap[12] = t->saved_user_rdx;
    t->fork_gpr_snap[13] = t->fork_child_user_rip ? t->fork_child_user_rip : t->saved_user_rcx;
    t->fork_gpr_snap[14] = 0;
    t->fork_gpr_snap[15] = t->saved_user_rsp;
}

static void fork_copy_child_regs_from_snapshot(thread_t *child, thread_t *parent, uint64_t child_rip) {
    if (!child || !parent) return;
    uint64_t *snap = parent->syscall_frame_kbuf;
    if (!snap && parent->saved_syscall_frame)
        snap = parent->saved_syscall_frame;
    if (!snap) return;
    if (!child_rip)
        child_rip = parent->fork_child_trap_rip ? parent->fork_child_trap_rip : snap[13];
    child->saved_user_r15 = snap[0];
    child->saved_user_r14 = snap[1];
    child->saved_user_r13 = snap[2];
    child->saved_user_r12 = snap[3];
    child->saved_user_r11 = snap[4];
    child->saved_user_r10 = snap[5];
    child->saved_user_r9  = snap[6];
    child->saved_user_r8  = snap[7];
    child->saved_user_rdi = snap[8];
    child->saved_user_rsi = snap[9];
    child->saved_user_rbp = snap[10];
    child->saved_user_rbx = snap[11];
    /* glibc's _Fork wrapper carries the child result through EDX across its
     * set_robust_list syscall. Keep both authoritative copies at zero. */
    child->saved_user_rdx = 0;
    child->saved_user_rcx = child_rip;
    child->saved_user_rsp = snap[15];
    memcpy(child->fork_gpr_snap, snap, 16 * sizeof(uint64_t));
    child->fork_gpr_snap[13] = child_rip;
    child->fork_gpr_snap[12] = 0; /* _Fork child entered with xor %edx,%edx */
    child->fork_gpr_snap[14] = 0; /* child clone/fork return is always 0 */
    child->fork_child_user_rip = child_rip;
    child->saved_user_rip = child_rip;
    child->user_rip = child_rip;
    child->user_stack = snap[15];
}

static void fork_assign_child_return_rip(thread_t *parent, thread_t *child) {
    if (!parent || !child) return;
    /* Child must resume at the same RIP the parent syscall iretq will use.
     * Do not scan/replace: fork_rip_find_fork_return() can pick a stale gconv site. */
    uint64_t rip = parent->fork_child_trap_rip;
    if (!rip && parent->saved_syscall_frame)
        rip = parent->saved_syscall_frame[13];
    if (!rip && parent->syscall_frame_kbuf)
        rip = parent->syscall_frame_kbuf[13];
    if (!rip)
        rip = parent->fork_locked_syscall_rip;
    /* Linux fork child returns via fork_child_return_entry: full GPR restore + rax=0
     * + iretq to syscall return RIP. Do NOT use user_thread_entry/enter_user_mode here:
     * enter_user_mode_asm zeroes callee-saved regs (rbp, rbx, …) before iretq. */
    fork_copy_child_regs_from_snapshot(child, parent, rip);
    child->user_rip = rip;
    if (parent->name[0] && strstr(parent->name, "openrc")) {
        devel_printf("fork-parent-rip: child=%llu rip=0x%llx trap=0x%llx rsp=0x%llx rbp=0x%llx kbuf_rbp=0x%llx\n",
            (unsigned long long)(child->tid ? child->tid : 1),
            (unsigned long long)rip,
            (unsigned long long)parent->fork_child_trap_rip,
            (unsigned long long)child->saved_user_rsp,
            (unsigned long long)child->saved_user_rbp,
            (unsigned long long)(parent->syscall_frame_kbuf ? parent->syscall_frame_kbuf[10] : 0));
    }
}

static void fork_sync_after_robust_list(thread_t *child) {
    if (!child || child->parent_tid < 0) return;
    /* Child just wrote robust_list/cleartid into its private COW pages.
     * mm_fork_sync_from_parent() copies *parent* bytes back into the child and
     * both burns heap (up to ~100 4K pages per fork) and can undo the writes
     * glibc _Fork child made at libc+0xd437f. Log only. */
    if (child->name[0] && strstr(child->name, "openrc")) {
        uint64_t resume_rip = child->saved_user_rcx;
        if (child->syscall_frame_kbuf)
            resume_rip = child->syscall_frame_kbuf[13];
        devel_printf("fork-post-robust-sync: child=%llu robust=0x%llx cleartid=0x%llx resume_rip=0x%llx\n",
            (unsigned long long)(child->tid ? child->tid : 1),
            (unsigned long long)child->robust_list_head,
            (unsigned long long)child->clear_child_tid,
            (unsigned long long)resume_rip);
    }
}

/* glibc _Fork child finished set_robust_list; drop fork-child tracing hooks. */
static void fork_child_finish_post_robust(thread_t *child) {
    if (!child) return;
    fork_sync_after_robust_list(child);

    thread_t *pt = (child->parent_tid > 0) ? thread_get(child->parent_tid) : NULL;
    int parent_is_openrc = pt && pt->name[0] && strstr(pt->name, "openrc");
    int child_is_openrc = child->name[0] && strstr(child->name, "openrc");

    /*
     * ALWAYS force edx=0 on the live SYSCALL frame. glibc _Fork does
     *   set_robust_list; mov %edx,%eax; ret
     * BusyBox init uses vfork+exec for /bin/mount; if edx is clobbered the
     * child takes the parent path in a shared VM and busybox init loops the
     * same sysinit action forever (mount → reap status=0 → mount → …).
     */
    if (child->saved_syscall_frame) {
        uint64_t *live = child->saved_syscall_frame;
        live[12] = 0;
        child->saved_user_rdx = 0;
        if (child->syscall_frame_kbuf)
            child->syscall_frame_kbuf[12] = 0;
        static int edx0_left = 32;
        if (edx0_left-- > 0)
            devel_printf("fork-child-edx0: tid=%llu live_rdx=0x%llx rip=0x%llx rsp=0x%llx name=%s\n",
                (unsigned long long)(child->tid ? child->tid : 1),
                (unsigned long long)live[12],
                (unsigned long long)live[13],
                (unsigned long long)live[15],
                child->name[0] ? child->name : "?");
    }
    if (syscall_pipe_watch_active && child->mm) {
        uint64_t bss = 0x63e978ULL, stk = child->saved_user_rsp;
        uint64_t bss_pa = 0, stk_pa = 0, bss_w = 0, stk_w = 0;
        int bss_r = mm_va_leaf_pa(child->mm, bss, &bss_pa);
        int stk_r = mm_va_leaf_pa(child->mm, stk, &stk_pa);
        int bss_wr = mm_user_leaf_pa(child->mm, bss, 1, &bss_w);
        int stk_wr = mm_user_leaf_pa(child->mm, stk, 1, &stk_w);
        devel_printf("fork-child-pte: tid=%llu bss_r=%d pa=0x%llx wr=%d "
                "stk_r=%d pa=0x%llx wr=%d cr3=0x%llx\n",
            (unsigned long long)(child->tid ? child->tid : 1),
            bss_r, (unsigned long long)bss_pa, bss_wr,
            stk_r, (unsigned long long)stk_pa, stk_wr,
            (unsigned long long)(child->mm->cr3 ? child->mm->cr3 : 0));
    }

    /*
     * Keep fork_child_user_rip only for openrc's run_program child (parent is
     * openrc) so the SIG_DFL / exec path stays traced. Everyone else (linuxrc
     * → mount, etc.) clears the marker after _Fork.
     */
    if (child_is_openrc && parent_is_openrc && child->mm) {
        {
            uint64_t canary = 0, insn = 0;
            int can_ok = 0, insn_ok = 0;
            uint64_t fs = child->user_fs_base;
            uint64_t rip = child->saved_syscall_frame ? child->saved_syscall_frame[13]
                                                    : (child->syscall_frame_kbuf
                                                           ? child->syscall_frame_kbuf[13]
                                                           : child->saved_user_rcx);
            uint64_t ursp = child->saved_syscall_frame ? child->saved_syscall_frame[15]
                                                      : child->saved_user_rsp;
            if (fs >= 0x200000ULL && fs + 0x30ULL < (uint64_t)MMIO_IDENTITY_LIMIT)
                can_ok = (user_read_u64((const void *)(uintptr_t)(fs + 0x28ULL), &canary) == 0);
            if (rip >= 0x200000ULL && rip + 8ULL < (uint64_t)MMIO_IDENTITY_LIMIT)
                insn_ok = (user_read_u64((const void *)(uintptr_t)rip, &insn) == 0);
            devel_printf("fork-child-pre-ret: tid=%llu rip=0x%llx rsp=0x%llx fs=0x%llx can=0x%llx can_ok=%d insn=0x%llx insn_ok=%d cr3=0x%llx\n",
                (unsigned long long)(child->tid ? child->tid : 1),
                (unsigned long long)rip,
                (unsigned long long)ursp,
                (unsigned long long)fs,
                (unsigned long long)canary, can_ok,
                (unsigned long long)insn, insn_ok,
                (unsigned long long)(child->mm ? child->mm->cr3 : 0));
        }
        return;
    }

    child->fork_child_user_rip = 0;
}

__attribute__((noreturn)) static void fork_child_return_entry(void) {
    thread_t *self = thread_current();
    if (self) {
        static int fork_child_entry_dbg_left = 24;
        if (fork_child_entry_dbg_left-- > 0) {
            devel_printf("fork-child-entry: tid=%llu name=%s parent=%d state=%d\n",
                (unsigned long long)(self->tid ? self->tid : 1),
                self->name[0] ? self->name : "(noname)",
                self->parent_tid, self->state);
        }
    }
    if (self && self->name[0] && strstr(self->name, "openrc")) {
        static int fork_child_run_dbg_left = 16;
        if (fork_child_run_dbg_left-- > 0) {
            devel_printf("fork-child-run: tid=%llu rip=0x%llx rsp=0x%llx fs=0x%llx\n",
                (unsigned long long)(self->tid ? self->tid : 1),
                (unsigned long long)self->fork_child_user_rip,
                (unsigned long long)self->saved_user_rsp,
                (unsigned long long)self->user_fs_base);
        }
    }
    if (!self) {
        for (;;) asm volatile("sti; hlt" ::: "memory");
    }
    self->ring = 3;
    thread_set_current_user(self);
    if (self->kernel_stack)
        tss_set_rsp0(self->kernel_stack);
    syscall_bind_kstack_for_thread(self);
    set_user_fs_base(self->user_fs_base);
    fork_prepare_child_before_iretq(self);

    if (!self->fork_gpr_snap[13] && !self->fork_gpr_snap[0])
        fork_build_gpr_snap_from_thread(self);
    if (self->fork_child_user_rip)
        self->fork_gpr_snap[13] = self->fork_child_user_rip;
    /*
     * Linux ABI:
     * - fork/_Fork/vfork child: edx=0 (glibc xor edx,edx / result in eax).
     * - clone3/__clone pthread child: rdx=start_routine must survive iretq.
     * Only the pthread path sets clone_preserve_rdx — never guess from stack.
     */
    if (self->clone_preserve_rdx)
        self->fork_gpr_snap[12] = self->saved_user_rdx;
    else
        self->fork_gpr_snap[12] = 0;
    self->clone_preserve_rdx = 0;
    self->fork_gpr_snap[14] = 0;
    /* Linux child syscall return: IF=1, no AC/TF/VM garbage from parent frame. */
    self->fork_gpr_snap[4] = 0x202ULL;
    self->saved_syscall_frame = self->fork_gpr_snap;

    fork_child_init_fpstate();

    {
        static int fork_child_iretq_dbg_left = 4;
        if (fork_child_iretq_dbg_left-- > 0)
            devel_printf("fork-child-iretq: tid=%llu rip=0x%llx rsp=0x%llx fs=0x%llx cr3=0x%llx\n",
                (unsigned long long)(self->tid ? self->tid : 1),
                (unsigned long long)self->fork_gpr_snap[13],
                (unsigned long long)self->fork_gpr_snap[15],
                (unsigned long long)self->user_fs_base,
                (unsigned long long)(self->mm ? self->mm->cr3 : 0));
    }

    if (self->name[0] && strstr(self->name, "openrc")) {
        static int fork_child_enter_dbg_left = 16;
        if (fork_child_enter_dbg_left-- > 0) {
            devel_printf("fork-child-enter: tid=%llu name=%s rip=0x%llx rsp=0x%llx rbp=0x%llx fs=0x%llx mmcr3=0x%llx\n",
                (unsigned long long)(self->tid ? self->tid : 1),
                self->name,
                (unsigned long long)self->fork_gpr_snap[13],
                (unsigned long long)self->fork_gpr_snap[15],
                (unsigned long long)self->fork_gpr_snap[10],
                (unsigned long long)self->user_fs_base,
                (unsigned long long)(self->mm ? self->mm->cr3 : 0));
        }
        static int fork_child_ret_dbg_left = 16;
        if (fork_child_ret_dbg_left-- > 0) {
            uint64_t tcb_ptr = 0;
            if (self->user_fs_base >= 0x200000ULL)
                (void)user_read_u64((const void *)(uintptr_t)(self->user_fs_base + 0x10ULL), &tcb_ptr);
            devel_printf("fork-child-syscall-ret: tid=%llu rip=0x%llx rsp=0x%llx r14=0x%llx tcb=0x%llx rax=0\n",
                (unsigned long long)(self->tid ? self->tid : 1),
                (unsigned long long)self->fork_gpr_snap[13],
                (unsigned long long)self->fork_gpr_snap[15],
                (unsigned long long)self->fork_gpr_snap[1],
                (unsigned long long)tcb_ptr);
        }
    }
    syscall_child_return_from_frame(self->fork_gpr_snap);
    __builtin_unreachable();
}

static inline int user_range_ok(const void *uaddr, size_t nbytes);
static inline int user_recv_range_ok(const void *uaddr, size_t nbytes);
static int copy_from_user_raw(void *kdst, const void *usrc, size_t n);
static int copy_to_user_safe(void *uptr, const void *kptr, size_t n);
static size_t user_strnlen_bounded(const char *s, size_t max);
static thread_t *syscall_thread_from_kstack(void);
static thread_t *syscall_resolve_thread(void);

static inline uint64_t msr_read_u64(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void msr_write_u64(uint32_t msr, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(v >> 32);
    asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static thread_t *uaccess_thread(void) {
    thread_t *t = thread_current();
    if (!t || t->ring != 3)
        t = thread_get_current_user();
    return t;
}

static void uaccess_clear(thread_t *t) {
    if (!t) return;
    t->uaccess_begin = 0;
    t->uaccess_end = 0;
    t->uaccess_resume_rip = 0;
    t->uaccess_active = 0;
}

static int uaccess_arm(thread_t *t, const void *uptr, size_t n, void *resume_rip, int recv_range) {
    if (!t || !resume_rip) return -1;
    if (recv_range) {
        if (!user_recv_range_ok(uptr, n)) return -1;
    } else {
        if (!user_range_ok(uptr, n)) return -1;
    }
    t->uaccess_begin = (uintptr_t)uptr;
    t->uaccess_end = (uintptr_t)uptr + n;
    t->uaccess_resume_rip = (uint64_t)(uintptr_t)resume_rip;
    t->uaccess_active = 1;
    asm volatile("" ::: "memory");
    return 0;
}

int syscall_try_handle_uaccess_fault(uint64_t fault_addr, uint64_t *resume_rip_out) {
    thread_t *t = uaccess_thread();
    uintptr_t fault = (uintptr_t)fault_addr;
    if (!t || !t->uaccess_active) return 0;
    if (fault < t->uaccess_begin || fault >= t->uaccess_end) return 0;
    if (resume_rip_out) *resume_rip_out = t->uaccess_resume_rip;
    uaccess_clear(t);
    return 1;
}

/* Debug helper: dump kernel syscall stack region around syscall_kernel_rsp0 */
static void debug_dump_kernel_syscall_stack(void) {
    extern uint64_t syscall_kernel_rsp0;
    uint64_t base = (uint64_t)syscall_kernel_rsp0;
    if (base == 0) return;
    if (base >= (uint64_t)MMIO_IDENTITY_LIMIT) return;
}

/* Apply per-thread exec trampoline by patching kernel syscall stack saved return RIP
   and adjusting saved user RSP. Returns 0 on success, -1 on failure. */
static int apply_exec_trampoline(thread_t *t) {
    if (!t || !t->exec_trampoline_flag) return -1;
    if (!t->saved_syscall_frame) return -1;
    uintptr_t base = (uintptr_t)t->saved_syscall_frame;
    uintptr_t rcx_slot = base + 13u * sizeof(uint64_t); /* frame[13] saved rcx (user RIP) */
    uintptr_t rax_slot = base + 14u * sizeof(uint64_t); /* frame[14] saved rax */
    uintptr_t rsp_slot = base + 15u * sizeof(uint64_t); /* frame[15] saved user RSP */

    /* safety: ensure writing within identity map */
    if (rcx_slot + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    if (rax_slot + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    if (rsp_slot + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;

    /* Write the desired return RIP into saved rcx slot so iret will use it */
    *(uint64_t*)(uintptr_t)rcx_slot = (uint64_t)t->exec_trampoline_rip;

    /* syscall_entry64 returns through the saved frame, not the legacy global. */
    *(uint64_t*)(uintptr_t)rsp_slot = (uint64_t)t->exec_trampoline_rsp;
    syscall_user_rsp_saved = t->exec_trampoline_rsp;

    /* Also set saved rax so final popped rax becomes our chosen value */
    *(uint64_t*)(uintptr_t)rax_slot = (uint64_t)t->exec_trampoline_rax;

    /* memory barrier */
    asm volatile("mfence" ::: "memory");

    /* clear flag (we consumed it) */
    t->exec_trampoline_flag = 0;

    /* notify assembly entry to preserve patched slots */
    syscall_exec_trampoline_active = 1;

    return 0;
}

/* Snapshot user registers from syscall entry stack frame into current thread.
   Frame layout matches syscall_entry64 push order (rsp points to saved r15). */
void syscall_snapshot_user_regs(uint64_t *frame) {
    if (!frame) return;
    /* Same ownership rules as syscall_resolve_thread(): a stale APIC bind can
     * land this frame on a blocked wait4 parent's kstack. */
    thread_t *cur = syscall_resolve_thread();
    if (!cur)
        cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur) return;
    /*
     * A user page must never be backed by either kernel stack.  SYSCALL has
     * already pushed frame[0..15] when we get here, so an overlap explains a
     * saved user return address changing between CALL and the first C-side
     * uaccess.  Diagnose the allocator/ownership violation itself; never
     * repair the user return slot.
     */
    if (cur->mm && cur->mm != mm_kernel()) {
        uint64_t user_rsp = frame[15];
        uint64_t ra_va = user_rsp + 0x148ULL;
        uint64_t ra_leaf = 0;
        if (user_rsp >= 0x200000ULL &&
            ra_va < (uint64_t)MMIO_IDENTITY_LIMIT &&
            mm_va_leaf_pa(cur->mm, ra_va, &ra_leaf) == 0) {
            uint64_t ra_pa = (ra_leaf & ~0xFFFULL) | (ra_va & 0xFFFULL);
            uint64_t frame_lo = (uint64_t)(uintptr_t)frame;
            uint64_t frame_hi = frame_lo + 16ULL * sizeof(uint64_t);
            uint64_t sc_lo = (uint64_t)(uintptr_t)cur->syscall_kstack_raw;
            uint64_t sc_hi = cur->syscall_kstack_top;
            uint64_t k_hi = cur->kernel_stack;
            uint64_t k_lo = k_hi >= (64ULL << 10) ? k_hi - (64ULL << 10) : 0;
            int frame_overlap = ra_pa >= frame_lo && ra_pa < frame_hi;
            int syscall_overlap = sc_lo && ra_pa >= sc_lo && ra_pa < sc_hi;
            int kernel_overlap = k_lo && ra_pa >= k_lo && ra_pa < k_hi;
            if (frame_overlap || syscall_overlap || kernel_overlap) {
                int value_slot = -1;
                for (int i = 0; i < 16; ++i) {
                    if (frame[i] >= MM_ASH_WATCH_LO &&
                        frame[i] < MM_ASH_WATCH_HI) {
                        value_slot = i;
                        break;
                    }
                }
                kprintf("MM-FATAL user-stack/kernel-stack alias tid=%d "
                        "user_rsp=0x%llx ra_va=0x%llx ra_pa=0x%llx "
                        "frame=%p..%p syscall=%p..%p kernel=%p..%p "
                        "frame_hit=%d sc_hit=%d k_hit=%d heap_value_slot=%d\n",
                        (int)(cur->tid ? cur->tid : 1),
                        (unsigned long long)user_rsp,
                        (unsigned long long)ra_va,
                        (unsigned long long)ra_pa,
                        (void *)(uintptr_t)frame_lo,
                        (void *)(uintptr_t)frame_hi,
                        (void *)(uintptr_t)sc_lo,
                        (void *)(uintptr_t)sc_hi,
                        (void *)(uintptr_t)k_lo,
                        (void *)(uintptr_t)k_hi,
                        frame_overlap, syscall_overlap, kernel_overlap,
                        value_slot);
            }
        }
    }
    if (!cur->syscall_frame_kbuf) {
        uint64_t *kbuf = (uint64_t *)kmalloc(16 * sizeof(uint64_t));
        if (kbuf) cur->syscall_frame_kbuf = kbuf;
    }
    if (cur->syscall_frame_kbuf)
        memcpy(cur->syscall_frame_kbuf, frame, 16 * sizeof(uint64_t));
    /* The return path in syscall.S restores registers and builds the iretq frame
     * from this live per-thread syscall-stack frame. Keep saved_syscall_frame
     * pointing at the live frame so rebuild_syscall_frame(), exec trampolines and
     * signal delivery patch the state that will actually be returned to ring 3. */
    cur->saved_syscall_frame = frame;
    cur->active_syscall_frame = (syscall_frame_t *)frame;
    /* Indexes into frame */
    cur->saved_user_r15 = frame[0];
    cur->saved_user_r14 = frame[1];
    cur->saved_user_r13 = frame[2];
    cur->saved_user_r12 = frame[3];
    cur->saved_user_r11 = frame[4];
    cur->saved_user_r10 = frame[5];
    cur->saved_user_r9  = frame[6];
    cur->saved_user_r8  = frame[7];
    cur->saved_user_rdi = frame[8];
    cur->saved_user_rsi = frame[9];
    cur->saved_user_rbp = frame[10];
    cur->saved_user_rbx = frame[11];
    cur->saved_user_rdx = frame[12];
    cur->saved_user_rcx = frame[13];
    cur->saved_user_rip = frame[13];
    cur->syscall_entry_rip = frame[13];
    cur->fork_locked_syscall_rip = frame[13];
    /* saved rax is frame[14] */
    cur->saved_user_rsp = frame[15]; /* pushed before regs */
}

/* Copy live per-CPU syscall stack frame into per-thread saved_user_* (Linux-like:
   another thread's syscall must not clobber this frame before we return to user). */
void syscall_frame_refresh(thread_t *t) {
    if (!t || !t->saved_syscall_frame) return;
    uint64_t *frame = t->saved_syscall_frame;
    t->saved_user_r15 = frame[0];
    t->saved_user_r14 = frame[1];
    t->saved_user_r13 = frame[2];
    t->saved_user_r12 = frame[3];
    t->saved_user_r11 = frame[4];
    t->saved_user_r10 = frame[5];
    t->saved_user_r9  = frame[6];
    t->saved_user_r8  = frame[7];
    t->saved_user_rdi = frame[8];
    t->saved_user_rsi = frame[9];
    t->saved_user_rbp = frame[10];
    t->saved_user_rbx = frame[11];
    t->saved_user_rdx = frame[12];
    t->saved_user_rcx = frame[13];
    t->saved_user_rip = frame[13];
    t->saved_user_rsp = frame[15];
}

void syscall_deferred_unblocks(void) {
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur) return;
    thread_t *child = cur->fork_child_to_publish;
    if (!child) return;
    int tid = (int)(child->tid ? child->tid : 1);
    {
        if (child) {
            uint64_t rip = 0;
            if (cur->saved_syscall_frame)
                rip = cur->saved_syscall_frame[13];
            if (!rip)
                rip = cur->fork_child_trap_rip;
            if (!rip && cur->syscall_frame_kbuf)
                rip = cur->syscall_frame_kbuf[13];
            /* Only refresh the child's GPR snapshot while it is still blocked on
             * fork_child_return_entry. Re-copying after the child has run user code
             * would stomp fork_gpr_snap[14] and other state.
             * Linux vfork/CLONE_VM: never re-arm fork_child_user_rip — that marker
             * enables Soft_COW identity patches which mutate the shared mm and
             * hang/corrupt the child at execve(/bin/mount).
             *
             * CLONE_THREAD with its own child_stack already has correct rsp/tls in
             * fork_gpr_snap. Re-copying from the parent replaces rsp with the
             * parent's stack; __clone then pops garbage and SIGILL at ~0xf3. */
            if (rip && (child->state == THREAD_BLOCKED || child->state == THREAD_SLEEPING)) {
                int shared_mm =
                    (child->mm && cur->mm && child->mm == cur->mm);
                int vfork_like =
                    (cur->vfork_waiting || cur->fork_request_vfork);
                int own_stack =
                    child->saved_user_rsp != 0 &&
                    child->saved_user_rsp != cur->saved_user_rsp;
                if (!own_stack) {
                    fork_copy_child_regs_from_snapshot(child, cur, rip);
                    if (vfork_like || shared_mm)
                        child->fork_child_user_rip = 0;
                } else if (shared_mm) {
                    /* pthread/CLONE_THREAD: keep prepared rsp/tls; no Soft_COW. */
                    child->fork_child_user_rip = 0;
                    child->fork_gpr_snap[14] = 0;
                    child->fork_gpr_snap[15] = child->saved_user_rsp;
                    if (rip)
                        child->fork_gpr_snap[13] = rip;
                    child->user_rip = child->fork_gpr_snap[13];
                    child->saved_user_rip = child->fork_gpr_snap[13];
                }
            }
            if (cur->name[0] && strstr(cur->name, "openrc")) {
                devel_printf("fork-defer-rip: child=%d rip=0x%llx tramp=0x%llx rsp=0x%llx rbp=0x%llx kbuf_rbp=0x%llx\n",
                    tid,
                    (unsigned long long)rip,
                    (unsigned long long)(child ? child->user_rip : 0),
                    (unsigned long long)(child ? child->saved_user_rsp : 0),
                    (unsigned long long)(child ? child->saved_user_rbp : 0),
                    (unsigned long long)(cur->syscall_frame_kbuf ? cur->syscall_frame_kbuf[10] : 0));
            }
        }
    }
    cur->fork_child_trap_rip = 0;
    /* Child stays blocked until syscall_publish_deferred_fork_child() —
     * called before cond_resched / iretq (Linux wake_up_new_task). */
}

/*
 * Finish a deferred wake (CLONE_THREAD safety net / old paths).
 * Normal fork/vfork now calls wake_up_new_task before clone returns (Linux).
 */
int syscall_publish_deferred_fork_child(void) {
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur) return 0;
    thread_t *child = cur->fork_child_to_publish;
    if (!child) return 0;
    int tid = (int)(child->tid ? child->tid : 1);
    cur->fork_child_to_publish = NULL;
    thread_unblock_fork_child(tid);
    thread_request_resched();
    return 1;
}

/*
 * Linux kernel/fork.c wake_up_new_task(): child is runnable before the parent
 * continues. Per-thread syscall stacks make an immediate wake safe; the old
 * "defer until ring3/timer" gate was not Linux semantics and delayed vfork/ls.
 */
static void fork_wake_up_new_task(thread_t *parent, thread_t *child)
{
    if (!parent || !child)
        return;
    int ctid = (int)(child->tid ? child->tid : 1);
    /* Refresh child GPRs from the parent's syscall snapshot while blocked. */
    parent->fork_child_to_publish = child;
    syscall_deferred_unblocks();
    parent->fork_child_to_publish = NULL;
    thread_unblock_fork_child(ctid);
}

/* Linux wait_for_vfork_done: block parent until child execs or exits. */
uint64_t syscall_maybe_vfork_wait(uint64_t parent_ret) {
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur || !cur->vfork_waiting)
        return parent_ret;

    if (cur->vfork_saved_ret)
        parent_ret = cur->vfork_saved_ret;
    else
        cur->vfork_saved_ret = parent_ret;
    int parent_tid = (int)(cur->tid ? cur->tid : 1);
    if (cur->name[0] && strstr(cur->name, "linuxrc"))
        devel_printf("vfork-wait: parent=%d ret=%llu rdi=0x%llx\n", parent_tid,
                (unsigned long long)parent_ret,
                (unsigned long long)cur->saved_user_rdi);

    if (cur->state != THREAD_BLOCKED && !thread_block_current_atomic())
        thread_block(parent_tid);
    /* Safety net: child should already be runnable from wake_up_new_task. */
    if (cur->fork_child_to_publish) {
        thread_t *child = cur->fork_child_to_publish;
        cur->fork_child_to_publish = NULL;
        child->fork_child_user_rip = 0;
        syscall_bind_kstack_for_thread(child);
        thread_unblock_fork_child((int)(child->tid ? child->tid : 1));
    }
    while (cur->vfork_waiting) {
        if (cur->state != THREAD_BLOCKED && !thread_block_current_atomic())
            thread_block(parent_tid);
        if (cur->vfork_waiting)
            thread_yield();
    }

    if (cur->mm) {
        mm_switch(cur->mm);
    }
    parent_ret = cur->vfork_saved_ret ? cur->vfork_saved_ret : parent_ret;
    cur->vfork_saved_ret = 0;

    thread_set_current(cur);
    thread_set_current_user(cur);
    syscall_bind_kstack_for_thread(cur);
    if (cur->mm)
        mm_switch(cur->mm);
    if (cur->user_fs_base)
        set_user_fs_base(cur->user_fs_base);

    if (cur->name[0] && strstr(cur->name, "linuxrc"))
        devel_printf("vfork-resume: parent=%d ret=%llu rdi=0x%llx rip=0x%llx\n",
                parent_tid,
                (unsigned long long)parent_ret,
                (unsigned long long)cur->saved_user_rdi,
                (unsigned long long)cur->saved_user_rcx);
    return parent_ret;
}

void syscall_restore_user_fs_before_iretq(void) {
    /*
     * Prefer the thread that owns this return path. Full resolve_thread can
     * adopt a RUNNING vfork child (new mm after exec) and load its FS into the
     * parent right before iretq — BusyBox then runs with mount's TLS.
     */
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur || cur->ring != 3)
        cur = syscall_resolve_thread();
    if (!cur || cur->ring != 3)
        return;
    if (cur->mm)
        mm_switch(cur->mm);
    syscall_bind_kstack_for_thread(cur);
    if (cur->user_fs_base)
        set_user_fs_base(cur->user_fs_base);
}

/*
 * Final syscall-return ABI fixup. syscall_entry64's live frame is authoritative
 * for iretq, while fork/signal code updates the owning thread's saved register
 * image. Reconcile the non-clobbered third argument register after every C
 * helper has run. Linux SYSCALL only clobbers rax, rcx and r11; in particular,
 * rdx must survive set_robust_list so glibc's clone child remains on the child
 * branch.
 */
void syscall_finalize_user_frame(uint64_t *frame) {
    if (!frame)
        return;
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur || cur->ring != 3)
        return;
    frame[12] = cur->saved_user_rdx;
    if (cur->saved_syscall_frame)
        cur->saved_syscall_frame[12] = cur->saved_user_rdx;
    if (cur->syscall_frame_kbuf)
        cur->syscall_frame_kbuf[12] = cur->saved_user_rdx;
}

void syscall_epilogue_probe(uint64_t *frame) {
    if (!frame || !syscall_pipe_watch_active)
        return;
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3 || cur->parent_tid < 0)
        return;
    static int probes_left = 8;
    if (probes_left-- <= 0)
        return;
    devel_printf("sysret-probe: tid=%d rip=0x%llx rsp=0x%llx "
            "rflags=0x%llx rax=0x%llx rdx=0x%llx cr3=0x%llx\n",
            (int)(cur->tid ? cur->tid : 1),
            (unsigned long long)frame[13],
            (unsigned long long)frame[15],
            (unsigned long long)frame[4],
            (unsigned long long)frame[14],
            (unsigned long long)frame[12],
            (unsigned long long)paging_read_cr3());
}

/* Debug only — never poke BusyBox .data (dielock/syslog) by absolute VA. */
static void linuxrc_trace_post_getpid(thread_t *t, uint64_t ret) {
    if (!t || !t->name[0] || !strstr(t->name, "linuxrc"))
        return;
    if (!t->fork_child_user_rip)
        return;
    devel_printf("linuxrc-post-getpid: tid=%llu ret=0x%llx rsp=0x%llx\n",
        (unsigned long long)(t->tid ? t->tid : 1),
        (unsigned long long)ret,
        (unsigned long long)t->saved_user_rsp);
}

/* Authoritative user RIP for fork/clone child return.
 * Use per-thread sources only: the global syscall_user_saved_rcx is per-CPU and
 * races on SMP. Validate post-syscall glue via copy_from_user_raw and require a
 * nearby fork/clone/clone3/vfork syscall so gconv false positives are rejected. */
static int fork_rip_read(thread_t *cur, uint64_t uaddr, void *kdst, size_t n) {
    if (!cur || !kdst || n == 0) return -1;
    if (uaddr < 0x200000ULL || uaddr + n > (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (!user_range_ok((const void *)(uintptr_t)uaddr, n)) return -1;
    return copy_from_user_raw(kdst, (const void *)(uintptr_t)uaddr, n);
}

static int fork_rip_syscall_nr_is_forkish(uint32_t nr) {
    return nr == 57 || nr == 56 || nr == 435 || nr == 58;
}

static int fork_rip_is_post_syscall_glue(thread_t *cur, uint64_t rip) {
    uint8_t p[6];
    if (rip < 0x200000ULL || rip + sizeof(p) > (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    if (fork_rip_read(cur, rip, p, sizeof(p)) != 0) return 0;
    /* glibc INLINE_SYSCALL: cmp rax, -4096 */
    if (p[0] == 0x48 && p[1] == 0x3d && p[2] == 0x00 && p[3] == 0xf0 && p[4] == 0xff && p[5] == 0xff)
        return 1;
    /* musl / alternate: cmp rax, imm8 */
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xf8)
        return 1;
    return 0;
}

static int fork_rip_is_fork_family_syscall(thread_t *cur, uint64_t syscall_ip) {
    uint8_t prefix[12];
    if (syscall_ip < 0x200000ULL || syscall_ip < 12) return 0;
    if (fork_rip_read(cur, syscall_ip - 12, prefix, sizeof(prefix)) != 0) return 0;
    for (int back = 1; back <= 10; back++) {
        int off = 12 - back;
        if (off < 0 || off + 5 >= (int)sizeof(prefix)) continue;
        if (prefix[off] != 0xb8) continue;
        uint32_t nr = (uint32_t)prefix[off + 1]
            | ((uint32_t)prefix[off + 2] << 8)
            | ((uint32_t)prefix[off + 3] << 16)
            | ((uint32_t)prefix[off + 4] << 24);
        if (fork_rip_syscall_nr_is_forkish(nr)) return 1;
    }
    return 0;
}

static int fork_rip_validate_return(thread_t *cur, uint64_t rip) {
    if (!rip || !fork_rip_is_post_syscall_glue(cur, rip)) return 0;
    for (unsigned back = 2; back <= 24; back++) {
        if (rip < back + 2) break;
        uint64_t syscall_ip = rip - back;
        uint8_t insn[2];
        if (fork_rip_read(cur, syscall_ip, insn, 2) != 0) continue;
        if (insn[0] == 0x0f && insn[1] == 0x05)
            return fork_rip_is_fork_family_syscall(cur, syscall_ip);
    }
    return 0;
}

static uint64_t fork_rip_find_fork_return(thread_t *cur, uint64_t hint) {
    if (!cur || !hint || hint < 0x200000ULL) return 0;
    if (fork_rip_validate_return(cur, hint)) return hint;
    for (unsigned back = 2; back <= 512; back++) {
        if (hint < back + 2) break;
        uint64_t cand = hint - back;
        uint8_t insn[2];
        if (fork_rip_read(cur, cand, insn, 2) != 0) continue;
        if (insn[0] != 0x0f || insn[1] != 0x05) continue;
        uint64_t after = cand + 2;
        if (fork_rip_validate_return(cur, after)) return after;
    }
    return 0;
}

static uint64_t fork_child_ret_rip(thread_t *cur) {
    if (!cur) return 0;
    uint64_t locked_rip = cur->fork_locked_syscall_rip;
    uint64_t entry_rip = cur->syscall_entry_rip;
    uint64_t kbuf_rip = cur->syscall_frame_kbuf ? cur->syscall_frame_kbuf[13] : 0;
    uint64_t live_rip = cur->saved_syscall_frame ? cur->saved_syscall_frame[13] : 0;
    uint64_t int80_rip = syscall_user_return_rip;
    uint64_t cands[5] = { locked_rip, live_rip, kbuf_rip, entry_rip, int80_rip };

    for (int i = 0; i < 5; i++) {
        if (cands[i] && fork_rip_validate_return(cur, cands[i]))
            return cands[i];
    }
    for (int i = 0; i < 5; i++) {
        if (!cands[i]) continue;
        uint64_t fixed = fork_rip_find_fork_return(cur, cands[i]);
        if (fixed) return fixed;
    }
    return 0;
}

static int clone_ensure_user_va(mm_t *mm, uint64_t va, int write) {
    uint64_t pa = 0;
    if (!mm || va < 0x1000ull || va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    if (mm_user_leaf_pa(mm, va, write, &pa) == 0)
        return 0;
    /*
     * Linux copy_thread: stack/TLS VMAs may be demand-paged. Forcing present
     * here matches populate-on-clone expectations without requiring MAP_POPULATE.
     * musl timer helper pthread_create failed with EFAULT → timer_create EAGAIN
     * → vim E1286 flood when opening kernel logs.
     */
    (void)user_vma_fault_lazy_anon(va);
    if (mm_user_leaf_pa(mm, va, write, &pa) == 0)
        return 0;
    /* Exclusive stack top: try the last byte of the page below. */
    if ((va & 0xfffu) == 0 && va >= 0x1000ull) {
        (void)user_vma_fault_lazy_anon(va - 1u);
        if (mm_user_leaf_pa(mm, va - 1u, write, &pa) == 0)
            return 0;
    }
    {
        uint64_t lo = va & ~0xFFFULL;
        uint64_t hi = lo + 0x1000ULL;
        /* If VA is the exclusive end of a mapping, commit the previous page. */
        if ((va & 0xfffu) == 0 && va >= 0x1000ull) {
            lo = (va - 1u) & ~0xFFFULL;
            hi = lo + 0x1000ULL;
        }
        mm_t *k = mm_kernel();
        if (mm->pml4 && k && k->pml4 && mm->pml4 != k->pml4) {
            mm_t *share = k;
            if (mm_privatize_identity_range_blank(mm, lo, hi) == 0 &&
                mm_make_private_range_noyield(mm, lo, hi, 0, share) == 0 &&
                (mm_user_leaf_pa(mm, va, write, &pa) == 0 ||
                 ((va & 0xfffu) == 0 && va >= 0x1000ull &&
                  mm_user_leaf_pa(mm, va - 1u, write, &pa) == 0)))
                return 0;
        } else {
            uint64_t va2m = lo & ~((uint64_t)PAGE_SIZE_2M - 1ull);
            if (map_page_2m(va2m, va2m, PG_PRESENT | PG_RW | PG_US) == 0 &&
                (mm_user_leaf_pa(mm, va, write, &pa) == 0 ||
                 ((va & 0xfffu) == 0 && va >= 0x1000ull &&
                  mm_user_leaf_pa(mm, va - 1u, write, &pa) == 0)))
                return 0;
        }
    }
    return -1;
}

static uint64_t fork_caller_user_rip(thread_t *cur) {
    if (!cur) return 0;
    uint64_t rip = 0;
    if (cur->fork_child_trap_rip)
        rip = cur->fork_child_trap_rip;
    else if (cur->saved_syscall_frame && cur->saved_syscall_frame[13])
        rip = cur->saved_syscall_frame[13];
    else if (cur->syscall_frame_kbuf && cur->syscall_frame_kbuf[13])
        rip = cur->syscall_frame_kbuf[13];
    else
        rip = fork_child_ret_rip(cur);
    if (cur->name[0] && strstr(cur->name, "openrc")) {
        devel_printf("fork-ret-rip: pick=0x%llx trap=0x%llx frame13=0x%llx kbuf13=0x%llx tid=%d\n",
            (unsigned long long)rip,
            (unsigned long long)cur->fork_child_trap_rip,
            (unsigned long long)(cur->saved_syscall_frame ? cur->saved_syscall_frame[13] : 0),
            (unsigned long long)(cur->syscall_frame_kbuf ? cur->syscall_frame_kbuf[13] : 0),
            (int)(cur->tid ? cur->tid : 1));
    }
    return rip;
}

static void rebuild_syscall_frame(thread_t *t) {
    if (!t || !t->saved_syscall_frame) return;
    uint64_t *frame = t->saved_syscall_frame;
    frame[0]  = t->saved_user_r15;
    frame[1]  = t->saved_user_r14;
    frame[2]  = t->saved_user_r13;
    frame[3]  = t->saved_user_r12;
    frame[4]  = t->saved_user_r11;
    frame[5]  = t->saved_user_r10;
    frame[6]  = t->saved_user_r9;
    frame[7]  = t->saved_user_r8;
    frame[8]  = t->saved_user_rdi;
    frame[9]  = t->saved_user_rsi;
    frame[10] = t->saved_user_rbp;
    frame[11] = t->saved_user_rbx;
    frame[12] = t->saved_user_rdx;
    /*
     * frame[13] is the RIP consumed by the final iretq.  Context-restoring
     * syscalls (notably rt_sigreturn) must replace it with the interrupted
     * user RIP.  Leaving the restorer's post-SYSCALL RIP here resumes at
     * __restore_rt+9 and can fall through into an unrelated libc function.
     */
    frame[13] = t->saved_user_rcx;
    /* leave frame[14] (saved rax) to be overwritten by syscall_entry64 */
    frame[15] = t->saved_user_rsp;
}

/* Restore entry snapshot into the live syscall return frame.
 * wait4 can block/resume; if any path scribbles on live slots, userspace may
 * return with corrupted arg/base registers and crash immediately after syscall. */
static void syscall_restore_live_frame_from_snapshot(thread_t *t, const char *tag) {
    if (!t || !t->saved_syscall_frame || !t->syscall_frame_kbuf) return;
    uint64_t *live = t->saved_syscall_frame;
    uint64_t *snap = t->syscall_frame_kbuf;
    int repaired = 0;
    for (int i = 0; i <= 13; i++) {
        if (live[i] != snap[i]) {
            live[i] = snap[i];
            repaired = 1;
        }
    }
    if (live[15] != snap[15]) {
        live[15] = snap[15];
        repaired = 1;
    }
    if (repaired) {
        devel_printf("syscall-frame-restore: tid=%llu tag=%s rip=0x%llx rsp=0x%llx\n",
            (unsigned long long)(t->tid ? t->tid : 1),
            tag ? tag : "?",
            (unsigned long long)snap[13],
            (unsigned long long)snap[15]);
    }
    syscall_frame_refresh(t);
}

/* Keep stack layout consistent with core/elf.c user_stack_top_for_tid().
   Duplicated here because elf.c helper is static. */
/* Match core/elf.c: Linux process-local stack VA (same in every mm). */
static uintptr_t user_stack_top_for_tid_like_exec(uint64_t tid) {
    (void)tid;
    return (uintptr_t)USER_STACK_TOP;
}

/* TLS layout matches core/elf.c (stack slot, not brk/heap). */
static void fork_tls_layout_for_tid(uint64_t tid, uintptr_t stack_top,
        uintptr_t *tls_region, uintptr_t *fs_base, uintptr_t *pthread_fake) {
    if (!tls_region || !fs_base || !pthread_fake) return;
    if (!stack_top)
        stack_top = user_stack_top_for_tid_like_exec(tid);
    *tls_region = stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
    *fs_base = *tls_region + 0x1000u;
    *pthread_fake = *tls_region + 0x2000u;
}

/* Relocate user pointers from parent stack slice/slot into the child's copy. */
static int user_read_u64(const void *uaddr, uint64_t *out);
static int user_write_u64(void *uaddr, uint64_t value);

static uint64_t fork_reloc_user_ptr(uint64_t val,
    uintptr_t slice_lo, uintptr_t slice_hi, uintptr_t child_slice_base,
    uintptr_t slot_lo, uintptr_t slot_hi, uintptr_t child_slot_base) {
    uintptr_t vv = (uintptr_t)val;
    if ((vv & 7u) != 0) return val;
    if (vv >= slice_lo && vv < slice_hi)
        return (uint64_t)(child_slice_base + (vv - slice_lo));
    if (slot_hi > slot_lo && vv >= slot_lo && vv < slot_hi)
        return (uint64_t)(child_slot_base + (vv - slot_lo));
    return val;
}

static void fork_reloc_range_u64(uintptr_t base, uintptr_t nbytes,
    uintptr_t slice_lo, uintptr_t slice_hi, uintptr_t child_slice_base,
    uintptr_t slot_lo, uintptr_t slot_hi, uintptr_t child_slot_base) {
    if (nbytes < 8) return;
    uintptr_t end = base + nbytes;
    if (end < base || end > (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    for (uintptr_t pp = base; pp + 8 <= end; pp += 8) {
        uint64_t v = *(uint64_t *)(uintptr_t)pp;
        uint64_t nv = fork_reloc_user_ptr(v, slice_lo, slice_hi, child_slice_base,
            slot_lo, slot_hi, child_slot_base);
        if (nv != v)
            *(uint64_t *)(uintptr_t)pp = nv;
    }
}

/* Relocate stack copy: adjust pointers into parent stack slice/slot and parent TLS. */
static void fork_reloc_child_stack_u64(uintptr_t base, uintptr_t nbytes,
    uintptr_t stack_lo, uintptr_t stack_hi, uintptr_t child_stack_base,
    uintptr_t slot_lo, uintptr_t slot_hi, uintptr_t child_slot_base,
    uintptr_t tls_lo, uintptr_t tls_hi, uintptr_t child_tls_base) {
    if (nbytes < 8) return;
    uintptr_t end = base + nbytes;
    if (end < base || end > (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    for (uintptr_t pp = base; pp + 8 <= end; pp += 8) {
        uint64_t v = *(uint64_t *)(uintptr_t)pp;
        uint64_t nv = fork_reloc_user_ptr(v, stack_lo, stack_hi, child_stack_base,
            slot_lo, slot_hi, child_slot_base);
        if (tls_hi > tls_lo)
            nv = fork_reloc_user_ptr(nv, tls_lo, tls_hi, child_tls_base, 0, 0, 0);
        if (nv != v)
            *(uint64_t *)(uintptr_t)pp = nv;
    }
}

/* Map every parent-stack-slot pointer in a buffer to the child's stack slot. */
static int fork_reloc_parent_slot_only(uintptr_t base, uintptr_t nbytes,
        uintptr_t parent_slot_lo, uintptr_t parent_slot_hi, uintptr_t child_slot_lo) {
    int changed = 0;
    if (nbytes < 8 || parent_slot_hi <= parent_slot_lo) return 0;
    uintptr_t end = base + nbytes;
    if (end < base || end > (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    for (uintptr_t pp = base; pp + 8 <= end; pp += 8) {
        uint64_t v = *(uint64_t *)(uintptr_t)pp;
        uintptr_t vv = (uintptr_t)v;
        if ((vv & 7u) != 0) continue;
        if (vv >= parent_slot_lo && vv < parent_slot_hi) {
            uint64_t nv = (uint64_t)(child_slot_lo + (vv - parent_slot_lo));
            if (nv != v) {
                *(uint64_t *)(uintptr_t)pp = nv;
                changed++;
            }
        }
    }
    return changed;
}

static int fork_stack_count_parent_slot_ptrs(const void *base, uintptr_t nbytes,
        uintptr_t parent_slot_lo, uintptr_t parent_slot_hi) {
    int n = 0;
    if (nbytes < 8 || parent_slot_hi <= parent_slot_lo) return 0;
    const uintptr_t end = (uintptr_t)base + nbytes;
    if (end < (uintptr_t)base) return 0;
    for (uintptr_t pp = (uintptr_t)base; pp + 8 <= end; pp += 8) {
        uint64_t v = 0;
        memcpy(&v, (const void *)(uintptr_t)pp, sizeof(v));
        uintptr_t vv = (uintptr_t)v;
        if ((vv & 7u) == 0 && vv >= parent_slot_lo && vv < parent_slot_hi)
            n++;
    }
    return n;
}

static uint64_t fork_reloc_syscall_reg(uint64_t val, uintptr_t parent_lo, uintptr_t parent_hi,
    uintptr_t child_rsp, uintptr_t parent_slot_lo, uintptr_t parent_stack_top, uintptr_t child_slot_lo,
    uintptr_t parent_tls_lo, uintptr_t child_tls_base) {
    uint64_t nv = fork_reloc_user_ptr(val, parent_lo, parent_hi, child_rsp,
        parent_slot_lo, parent_stack_top, child_slot_lo);
    if (parent_tls_lo)
        nv = fork_reloc_user_ptr(nv, parent_tls_lo, parent_tls_lo + 0x3000u, child_tls_base, 0, 0, 0);
    return nv;
}

/* Copy parent TLS image into child slot (canonical stack-slot VAs only). */
static int fork_copy_parent_tls(uintptr_t child_tls, uintptr_t parent_tls, mm_t *child_mm, mm_t *parent_mm) {
    if (!child_tls || !parent_tls || parent_tls + 0x3000u > (uintptr_t)MMIO_IDENTITY_LIMIT ||
        child_tls + 0x3000u > (uintptr_t)MMIO_IDENTITY_LIMIT)
        return -1;
    uint8_t snap[0x3000];
    mm_switch(parent_mm);
    if (copy_from_user_raw(snap, (const void *)(uintptr_t)parent_tls, sizeof(snap)) != 0) {
        mm_switch(child_mm);
        return -1;
    }
    mm_switch(child_mm);
    if (copy_to_user_safe((void *)(uintptr_t)child_tls, snap, sizeof(snap)) != 0)
        return -1;
    return 0;
}

/* glibc/BusyBox static TLS bootstrap (same layout as core/elf.c execve). */
static void fork_seed_glibc_tls(uintptr_t tls_region, uintptr_t fs_base, uintptr_t pthread_fake) {
    if (tls_region + 0x3000u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    uint64_t guard = 0x8b13f00d2a11c0deULL;
    guard &= ~0xFFULL;
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x00u) = (uint64_t)fs_base;
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x08u) = (uint64_t)(fs_base + 0x800u);
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x10u) = (uint64_t)fs_base;
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x28u) = guard;
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x30u) = guard ^ 0x5a5a5a5a5a5a5a5aULL;
    *(volatile uint64_t *)(uintptr_t)(fs_base - 0x78u) = (uint64_t)pthread_fake;
    {
        const uintptr_t c_str = tls_region + 0x2800u;
        if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            *(volatile uint8_t *)(uintptr_t)(c_str + 0) = (uint8_t)'C';
            *(volatile uint8_t *)(uintptr_t)(c_str + 1) = 0;
            for (int si = 0; si < 32; si++)
                *(uint64_t *)(uintptr_t)(pthread_fake + 0x80u + (uintptr_t)(si * 8u)) = 0;
            *(uint64_t *)(uintptr_t)(pthread_fake + 0x80u + (uintptr_t)(5u * 8u)) = (uint64_t)c_str;
        }
    }
    /* Same path as vfork: ensure slots are visible to user-mode reads via %fs. */
    (void)user_write_u64((void *)(uintptr_t)(fs_base - 0x78u), (uint64_t)pthread_fake);
    {
        const uintptr_t c_str = tls_region + 0x2800u;
        const uintptr_t specific5_slot = pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
        if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT)
            (void)user_write_u64((void *)(uintptr_t)specific5_slot, (uint64_t)c_str);
    }
}

/* Linux-like fork behavior: keep parent's FS base when it is already set up.
   Applies to glibc and BusyBox: both expect the same %fs/TCB VA after fork(). */
static inline int fork_should_keep_parent_fs(thread_t *cur, uint64_t parent_fs_base) {
    (void)cur;
    const uint64_t user_min = 0x00200000ULL;
    if (parent_fs_base < user_min) return 0;
    if (parent_fs_base >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

static void fork_stop_child(thread_t *child) {
    if (!child) return;
    int tid = (int)(child->tid ? child->tid : 1);
    process_t *process = child->process;
    process_t *parent = process ? process->parent : NULL;
    child->process = NULL;
    if (process)
        process->leader = NULL;
    /*
     * An unpublished fork failure is not a zombie: userspace never received
     * its PID and therefore cannot wait for it. Remove the scheduler slot and
     * release all thread/mm resources immediately.
     */
    thread_stop(tid);
    (void)thread_reap(tid);
    if (process && parent)
        (void)process_discard(parent, process);
}

void axon_user_dbg(thread_t *cur, const char *tag, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
#if AXON_FORK_DEBUG
    /* Serial only — never write fork traces to the interactive tty. That was
     * not Linux behavior and each fs_write() to fbcon made post-fork stalls. */
    qemu_debug_printf("%s[%d] %s tid=%llu a=0x%llx b=0x%llx c=0x%llx\n",
        tag ? tag : "dbg", step, msg ? msg : "",
        (unsigned long long)(cur && cur->tid ? cur->tid : 0),
        a, b, c);
#else
    (void)cur; (void)tag; (void)step; (void)msg; (void)a; (void)b; (void)c;
#endif
}

#if AXON_FORK_DEBUG
static void fork_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    axon_user_dbg(cur, "fork", step, msg, a, b, c);
}
#else
static inline void fork_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    (void)cur; (void)step; (void)msg; (void)a; (void)b; (void)c;
}
#endif

#if AXON_FORK_DEBUG
static void clone3_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    axon_user_dbg(cur, "clone3", step, msg, a, b, c);
}
#else
static inline void clone3_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    (void)cur; (void)step; (void)msg; (void)a; (void)b; (void)c;
}
#endif

#if 0
/* Removed legacy shared-mm vfork snapshot restore. */
/* Restore parent's userspace stack snapshot for a vfork child.
   In AxonOS we block the parent until the child exits; however the child still
   runs in the same address space and may temporarily modify the parent's stack
   frames above the saved RSP. To avoid post-vfork corruption (seen as #GP with
   non-canonical RBP in busybox sh), we snapshot that region in SYS_vfork and
   restore it right before waking the parent on SYS_exit/SYS_exit_group. */
static void vfork_restore_parent_stack(thread_t *child) {
    if (!child) return;
    if (!child->vfork_parent_stack_backup) return;
    uintptr_t dst = (uintptr_t)child->vfork_parent_saved_rsp;
    uint64_t len64 = child->vfork_parent_stack_backup_len;
    if (dst != 0 && len64 != 0) {
        uintptr_t end = dst + (uintptr_t)len64;
        if (end > dst && end <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            memcpy((void*)dst, child->vfork_parent_stack_backup, (size_t)len64);
        } else {
            /* bad dst/len */
        }
    }
    /* Restore complete; free snapshot to avoid unbounded memory leak across vfork-heavy workloads
       (busybox shell utilities like wget/adduser/addgroup). */
    kfree(child->vfork_parent_stack_backup);
    child->vfork_parent_stack_backup = NULL;
    child->vfork_parent_saved_rsp = 0;
    child->vfork_parent_stack_backup_len = 0;
}
#endif

/* forward for user brk state used in vfork restore */
static uintptr_t user_brk_cur;

/* CLONE_VM shares mm with parent; fork+exec does not — never publish child brk/mmap
 * into the parent on exit or the shell heap cursor jumps into nc's VA range (#GP). */
static void exit_propagate_brk_mmap_to_parent(thread_t *cur) {
    if (!cur || cur->parent_tid < 0 || cur->user_stack_base == 0)
        return;
    thread_t *pt = thread_get(cur->parent_tid);
    if (!pt || !cur->mm || !pt->mm || cur->mm != pt->mm)
        return;
    if (pt->user_brk_cur < cur->user_brk_cur)
        pt->user_brk_cur = cur->user_brk_cur;
    if (pt->user_mmap_next < cur->user_mmap_next)
        pt->user_mmap_next = cur->user_mmap_next;
}

#if 0
static void vfork_restore_parent_memory(thread_t *child) {
    if (!child) return;
    if (!child->vfork_parent_mem_backup) return;
    uintptr_t base = (uintptr_t)child->vfork_parent_mem_backup_base;
    uint64_t len64 = child->vfork_parent_mem_backup_len;
    if (base != 0 && len64 != 0) {
        uintptr_t end = base + (uintptr_t)len64;
        if (end > base && end <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            memcpy((void*)base, child->vfork_parent_mem_backup, (size_t)len64);
            thread_t *pt = NULL;
            if (child->vfork_parent_tid >= 0) pt = thread_get(child->vfork_parent_tid);
            if (pt) {
                pt->user_brk_cur = (uintptr_t)child->vfork_parent_brk_saved;
            } else {
                user_brk_cur = (uintptr_t)child->vfork_parent_brk_saved;
            }
        } else {
            /* bad base/len */
        }
    }
    kfree(child->vfork_parent_mem_backup);
    child->vfork_parent_mem_backup = NULL;
    child->vfork_parent_mem_backup_len = 0;
    child->vfork_parent_mem_backup_base = 0;
    child->vfork_parent_brk_saved = 0;
}

void exec_vfork_release_parent(thread_t *child) {
    if (!child || child->vfork_parent_tid < 0)
        return;
    vfork_restore_parent_memory(child);
    vfork_restore_parent_stack(child);
    thread_unblock(child->vfork_parent_tid);
    child->vfork_parent_tid = -1;
}
#endif

/* exit_group tears down only schedulable threads in the same process.
 * waiters[] is only 8 slots; excess blocks the shell's read(stdin) after wget returns. */
static void exit_group_reap_peer_threads(thread_t *cur) {
    if (!cur || cur->ring != 3) return;
    int nt = thread_get_count();
    for (int i = 0; i < nt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t == cur) continue;
        if (t->ring != 3) continue;
        if (t->state == THREAD_TERMINATED) continue;
        if (t->process != cur->process) continue;
        devfs_tty_remove_waiter_from_all_ttys((int)(t->tid ? t->tid : 1));
        if (t->waiter_tid >= 0) {
            int w = t->waiter_tid;
            t->waiter_tid = -1;
            thread_unblock(w);
        }
        /*
         * Drop this peer's fd refs. Same rules as non-leader SYS_exit:
         * inherit (leader still mirrors) → one fs_file_free; worker-opened
         * process slot → leave for leader thread_close_all_fds; orphan → free.
         */
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            t->fds[fd] = NULL;
            if (!f)
                continue;
            if (cur->process && cur->process->fds[fd] == f) {
                thread_t *lead = cur->process->leader;
                if (lead && lead != t && lead->fds[fd] == f)
                    fs_file_free(f);
                continue;
            }
            fs_file_free(f);
        }
        t->exit_status = 9; /* WTERMSIG: SIGKILL */
        t->state = THREAD_TERMINATED;
    }
}

/*
 * Linux SIGKILL: terminate the whole thread group immediately from the killer's
 * context. Do not wait for the victim to return from poll/sleep and run
 * maybe_deliver — that left udhcpc alive after kill -9 (pending set, never applied).
 */
static int force_sigkill_thread_group(thread_t *any) {
    if (!any || any->ring != 3 || any->state == THREAD_TERMINATED)
        return 0;
    process_t *proc = any->process;
    thread_t *leader = (proc && proc->leader) ? proc->leader : any;
    int sig = SIGKILL;

    /* Reap every user thread in the group (including leader). */
    int nt = thread_get_count();
    for (int i = 0; i < nt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3 || t->state == THREAD_TERMINATED) continue;
        int same = 0;
        if (proc && t->process == proc)
            same = 1;
        else if (!proc && t == any)
            same = 1;
        if (!same) continue;
        devfs_tty_remove_waiter_from_all_ttys((int)(t->tid ? t->tid : 1));
        if (t->waiter_tid >= 0) {
            int w = t->waiter_tid;
            t->waiter_tid = -1;
            thread_unblock(w);
        }
        t->pending_signals = 0;
        t->exit_status = sig;
        t->state = THREAD_TERMINATED;
    }

    if (leader->attached_tty >= 0)
        devfs_tty_leave_alt_screen(leader->attached_tty);
    thread_close_all_fds(leader);
    if (leader->parent_tid >= 0) {
        thread_t *pt = thread_get(leader->parent_tid);
        if (pt) {
            thread_set_pending_signal(pt, SIGCHLD);
            thread_unblock((int)(pt->tid ? pt->tid : 1));
            if (leader->attached_tty >= 0 && pt->attached_tty == leader->attached_tty)
                devfs_set_tty_fg_pgrp(leader->attached_tty, pt->pgid);
        }
    }
    process_release_vfork_parent(proc, PROCESS_VFORK_FATAL);
    process_mark_zombie(proc, sig);
    if (proc) {
        process_t *init_process = NULL;
        int init_tid = thread_get_init_user_tid();
        thread_t *init_thread = init_tid >= 0 ? thread_get(init_tid) : NULL;
        if (init_thread)
            init_process = init_thread->process;
        process_reparent_children(proc, init_process);
    }
    if (leader->waiter_tid >= 0)
        thread_unblock(leader->waiter_tid);
    return 1;
}

enum {
    MSR_EFER  = 0xC0000080u,
    MSR_STAR  = 0xC0000081u,
    MSR_LSTAR = 0xC0000082u,
    MSR_FMASK = 0xC0000084u,
    MSR_FS_BASE = 0xC0000100u,
};

/* Helper: copy up to `max` bytes from user pointer `uptr` into newly allocated buffer. */
static void *copy_from_user_safe(const void *uptr, size_t count, size_t max, size_t *out_copied) {
    if (!uptr || count == 0) { if (out_copied) *out_copied = 0; return NULL; }
    size_t to_copy = count < max ? count : max;
    void *buf = kmalloc(to_copy);
    if (!buf) { if (out_copied) *out_copied = 0; return NULL; }
    if (copy_from_user_raw(buf, uptr, to_copy) != 0) {
        kfree(buf);
        if (out_copied) *out_copied = 0;
        return NULL;
    }
    if (out_copied) *out_copied = to_copy;
    return buf;
}

/* Minimal errno set (Linux). glibc expects negative errno in RAX on failure. */
#define EPERM   1
#define ENOENT  2
#define EBADF   9
#define E2BIG   7
#define EFAULT  14
#define EINVAL  22
/* Linux MAX_ARG_STRLEN: one argv/env string may be up to 32 pages.
 * A 4KiB cap broke `bash -c "$(curl …/install.sh)"` (script ~34KiB) —
 * execve silently truncated the -c payload → syntax error near 'fi'. */
#ifndef MAX_ARG_STRLEN
#define MAX_ARG_STRLEN (132u * 1024u)
#endif
#define ENOTTY  25
#define ESRCH   3
#define ENOSYS  38
#define ENOMEM  12
#define ERANGE  34
#define EMFILE  24
#define ENOEXEC 8
/* no child processes */
#define ECHILD  10
/* filename too long */
#define ENAMETOOLONG 36
#define EAGAIN  11
#define EINTR   4
#define EPIPE   32
#define EIO     5
#define EEXIST  17
#define EADDRINUSE 98
#define EADDRNOTAVAIL 99
#define EACCES  13
#define EBUSY   16
#define ENOTDIR 20
#define ENOSPC  28
#define EIDRM   43
#define EAFNOSUPPORT 97
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define EDESTADDRREQ 89
#define ENETDOWN 100
#define ENETUNREACH 101
#define EHOSTUNREACH 113
#define ENOTCONN 107
#define EISCONN 106
#define ENODEV   19
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define EALREADY 114
#define EINPROGRESS 115
#ifndef ECONNRESET
#define ECONNRESET 104
#endif

/* Pipe: kernel buffer + two fd ends. driver_private = pipe_t*,
 * fs_private = PIPE_END_READ / PIPE_END_WRITE (see fs.h). */
/* Linux keeps PIPE_BUF at 4 KiB for atomicity but normally gives each pipe a
 * 64 KiB ring. Archive pipelines must not block/wake on every single page. */
#define PIPE_BUF_SIZE 4096
#define PIPE_CAPACITY (64u * 1024u)
#define PIPE_RW_CHUNK (64u * 1024u)
typedef struct pipe {
    uint64_t id;
    uint8_t *buf;
    size_t size;
    size_t head;   /* write position */
    size_t tail;   /* read position */
    int refcount;  /* 2 when both ends open */
    int reader_waiter_tid;
    int writer_waiter_tid;
    spinlock_t lock;
} pipe_t;
static uint64_t pipe_next_id;
static int pipe_trace_left = 160;
int syscall_pipe_watch_active;
int syscall_pipe_watch_owner_tid;

static ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur);
static ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur);

/* Linux eventfd(2): 64-bit counter used by curl's async DNS waiter. */
enum {
    EFD_SEMAPHORE_K = 00000001,
    EFD_CLOEXEC_K   = 02000000,
    EFD_NONBLOCK_K  = 00004000
};
typedef struct eventfd {
    uint64_t count;
    int nonblock;
    int semaphore;
    int reader_waiter_tid;
    int writer_waiter_tid;
    spinlock_t lock;
} eventfd_t;

void eventfd_fs_file_destroy(struct fs_file *f) {
    if (!f || f->type != FS_TYPE_EVENTFD) return;
    eventfd_t *e = (eventfd_t *)f->driver_private;
    f->driver_private = NULL;
    if (e) {
        unsigned long fl = 0;
        acquire_irqsave(&e->lock, &fl);
        if (e->reader_waiter_tid >= 0) {
            thread_unblock(e->reader_waiter_tid);
            e->reader_waiter_tid = -1;
        }
        if (e->writer_waiter_tid >= 0) {
            thread_unblock(e->writer_waiter_tid);
            e->writer_waiter_tid = -1;
        }
        release_irqrestore(&e->lock, fl);
        kfree(e);
    }
    if (f->path) {
        kfree((void *)f->path);
        f->path = NULL;
    }
    kfree(f);
}

static ssize_t eventfd_read_bytes(eventfd_t *e, void *buf, size_t cnt, thread_t *cur) {
    if (!e || !buf) return -EINVAL;
    if (cnt < 8) return -EINVAL;
    for (;;) {
        unsigned long fl = 0;
        acquire_irqsave(&e->lock, &fl);
        if (e->count == 0) {
            if (e->nonblock) {
                release_irqrestore(&e->lock, fl);
                return -EAGAIN;
            }
            int tid = (int)(cur && cur->tid ? cur->tid : 1);
            e->reader_waiter_tid = tid;
            release_irqrestore(&e->lock, fl);
            thread_block(tid);
            thread_yield();
            continue;
        }
        uint64_t val;
        if (e->semaphore) {
            val = 1;
            e->count--;
        } else {
            val = e->count;
            e->count = 0;
        }
        int wtid = e->writer_waiter_tid;
        e->writer_waiter_tid = -1;
        release_irqrestore(&e->lock, fl);
        memcpy(buf, &val, 8);
        if (wtid >= 0) thread_unblock(wtid);
        return 8;
    }
}

static ssize_t eventfd_write_bytes(eventfd_t *e, const void *buf, size_t cnt, thread_t *cur) {
    if (!e || !buf) return -EINVAL;
    if (cnt < 8) return -EINVAL;
    uint64_t add = 0;
    memcpy(&add, buf, 8);
    if (add == (uint64_t)-1) return -EINVAL;
    for (;;) {
        unsigned long fl = 0;
        acquire_irqsave(&e->lock, &fl);
        if (e->count > (uint64_t)-1 - add) {
            if (e->nonblock) {
                release_irqrestore(&e->lock, fl);
                return -EAGAIN;
            }
            int tid = (int)(cur && cur->tid ? cur->tid : 1);
            e->writer_waiter_tid = tid;
            release_irqrestore(&e->lock, fl);
            thread_block(tid);
            thread_yield();
            continue;
        }
        e->count += add;
        int rtid = e->reader_waiter_tid;
        e->reader_waiter_tid = -1;
        release_irqrestore(&e->lock, fl);
        if (rtid >= 0) thread_unblock(rtid);
        return 8;
    }
}

void pipe_release_end(struct fs_file *f) {
    if (!f || f->type != FS_TYPE_PIPE || !f->driver_private) return;
    pipe_t *p = (pipe_t *)f->driver_private;
    unsigned long fl = 0;
    acquire_irqsave(&p->lock, &fl);
    p->refcount--;
    int ref = p->refcount;
    uint64_t id = p->id;
    /* Wake waiter on the other end so they see EOF or EPIPE */
    if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
    if (p->writer_waiter_tid >= 0) { thread_unblock(p->writer_waiter_tid); p->writer_waiter_tid = -1; }
    release_irqrestore(&p->lock, fl);
    if (pipe_trace_left-- > 0)
        devel_printf("pipe: release id=%llu end=%c file=%p fref=%d pref=%d\n",
                (unsigned long long)id,
                fs_pipe_is_write_end(f) ? 'W' : 'R',
                (void *)f, f->refcount, ref);
    if (ref == 0) {
        f->driver_private = NULL;
        kfree(p->buf);
        kfree(p);
    } else {
        f->driver_private = NULL; /* end closed; pipe still held by peer */
    }
}

static ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur) {
    if (!p || !buf || cnt == 0) return -EINVAL;
    unsigned long fl = 0;
    for (;;) {
        acquire_irqsave(&p->lock, &fl);
        size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
        if (used > 0) {
            size_t n = used < cnt ? used : cnt;
            size_t tail = p->tail;
            /* Copy ring -> kernel buffer entirely under lock: another thread must not move
               tail/head while we read, or memcpy runs on stale indices and corrupts data. */
            size_t first = (tail + n <= p->size) ? n : (p->size - tail);
            memcpy(buf, p->buf + tail, first);
            if (first < n) memcpy((char*)buf + first, p->buf, n - first);
            p->tail = (tail + n) % p->size;
            if (p->writer_waiter_tid >= 0) { thread_unblock(p->writer_waiter_tid); p->writer_waiter_tid = -1; }
            release_irqrestore(&p->lock, fl);
            if (pipe_trace_left-- > 0)
                devel_printf("pipe: read id=%llu tid=%d n=%zu\n",
                        (unsigned long long)p->id,
                        cur ? (int)(cur->tid ? cur->tid : 1) : -1, n);
            return (ssize_t)n;
        }
        if (p->refcount < 2) {
            int ref = p->refcount;
            release_irqrestore(&p->lock, fl);
            if (pipe_trace_left-- > 0)
                devel_printf("pipe: EOF id=%llu tid=%d pref=%d\n",
                        (unsigned long long)p->id,
                        cur ? (int)(cur->tid ? cur->tid : 1) : -1, ref);
            return 0;
        }
        p->reader_waiter_tid = cur ? (int)cur->tid : -1;
        int waiter = p->reader_waiter_tid;
        int ref = p->refcount;
        uint64_t id = p->id;
        if (waiter >= 0)
            thread_block(waiter);
        release_irqrestore(&p->lock, fl);
        if (pipe_trace_left-- > 0)
            devel_printf("pipe: read-wait id=%llu tid=%d pref=%d\n",
                    (unsigned long long)id, waiter, ref);
        if (waiter >= 0)
            thread_yield();
    }
}

static ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur) {
    if (!p || !buf || cnt == 0) return -EINVAL;
    unsigned long fl = 0;
    size_t written = 0;
    const char *src = (const char *)buf;
    while (written < cnt) {
        acquire_irqsave(&p->lock, &fl);
        size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
        size_t free = (p->size - 1) > used ? (p->size - 1 - used) : 0;
        if (free > 0) {
            size_t n = (cnt - written) < free ? (cnt - written) : free;
            size_t head = p->head;
            size_t to_end = p->size - head;
            if (n <= to_end) {
                memcpy(p->buf + head, src + written, n);
            } else {
                memcpy(p->buf + head, src + written, to_end);
                memcpy(p->buf, src + written + to_end, n - to_end);
            }
            p->head = (head + n) % p->size;
            written += n;
            uint64_t id = p->id;
            if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
            release_irqrestore(&p->lock, fl);
            if (pipe_trace_left-- > 0)
                devel_printf("pipe: write id=%llu tid=%d n=%zu total=%zu\n",
                        (unsigned long long)id,
                        cur ? (int)(cur->tid ? cur->tid : 1) : -1,
                        n, written);
            continue;
        }
        if (p->refcount < 2) { release_irqrestore(&p->lock, fl); return written > 0 ? (ssize_t)written : -EPIPE; }
        p->writer_waiter_tid = cur ? (int)cur->tid : -1;
        int waiter = p->writer_waiter_tid;
        if (waiter >= 0)
            thread_block(waiter);
        release_irqrestore(&p->lock, fl);
        if (waiter >= 0)
            thread_yield();
    }
    return (ssize_t)written;
}

/* ---------- Minimal IPv4/ICMP raw socket backend (for ping) ---------- */
#define SYSCALL_FTYPE_SOCKET  0x534F434Bu
#define SYSCALL_FTYPE_EPOLL   0x45504F4Cu  /* 'EPOL' */

#define AF_UNIX_LOCAL         1
#define AF_INET_LOCAL         2
#define AF_UNSPEC             0   /* treat as AF_INET for getaddrinfo fallback */
#define AF_INET6              10  /* Linux value; we stub to AF_INET */
#define AF_NETLINK_LOCAL      16
#define AF_PACKET_LOCAL       17  /* Linux PF_PACKET — udhcpc / raw L2 */
#define SOCK_STREAM_LOCAL     1
#define SOCK_DGRAM_LOCAL      2
#define SOCK_RAW_LOCAL        3
#define SOCK_SEQPACKET_LOCAL  5
#define SOCK_CLOEXEC_LINUX    02000000
/* Linux: SOCK_NONBLOCK == O_NONBLOCK (glibc sets this in socket type / fcntl). */
#define O_NONBLOCK_LINUX      0x800
/* F_GETFL must include accmode; 0 breaks glibc fdopen/wget (bogus "out of memory"). */
#define O_RDWR_LINUX          2
#define IPPROTO_ICMP_LOCAL    1
#define IPPROTO_TCP_LOCAL     6
#define IPPROTO_UDP_LOCAL     17
#define IPPROTO_RAW_LOCAL     255 /* ioctl-only fd (busybox udhcpc) */
#define NETLINK_ROUTE_LOCAL   0

#define ETH_TYPE_IPV4         0x0800
#define ETH_TYPE_ARP          0x0806
#define ETH_P_ALL_HOST        0x0003

typedef struct unix_stream_conn {
    uint8_t q01[8192];
    size_t q01_head;
    size_t q01_tail;
    size_t q01_count;
    uint8_t q10[8192];
    size_t q10_head;
    size_t q10_tail;
    size_t q10_count;
    int closed[2];
    int refs;
    spinlock_t lock;
} unix_stream_conn_t;

typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t csum;
} udp_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t doff_res;
    uint8_t flags;
    uint16_t wnd;
    uint16_t csum;
    uint16_t urg;
} tcp_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} arp_hdr_t;

typedef struct {
    int sock_domain;
    /* socket(AF_INET6) is IPv4 internally; getsockname must still report v4-mapped sockaddr_in6. */
    int ipv6_stub;
    /* Linux IPV6_V6ONLY (default 0 = /proc/sys/net/ipv6/bindv6only). */
    int ipv6_only;
    /* AF_UNIX: Linux PF_UNIX stream/seqpacket (pathname + abstract). */
    int unix_domain_stub;
    int unix_bound;
    int unix_listening;
    int unix_abstract;          /* sun_path[0]=='\0' abstract namespace */
    int unix_path_len;          /* bytes in unix_path (abstract may embed NULs) */
    int unix_backlog;           /* sk_max_ack_backlog after listen() */
    char unix_path[108];
    /* AF_UNIX stream endpoint/listener state */
    struct unix_stream_conn *unix_conn;
    int unix_end; /* 0 or 1 endpoint index inside unix_conn */
    struct fs_file *unix_accept_q[16];
    int unix_accept_head;
    int unix_accept_tail;
    int unix_accept_count;
    spinlock_t unix_accept_lock;
    int type_base;
    int protocol;
    /* AF_PACKET: ethertype in host order (0x0800); ifindex from bind(sockaddr_ll). */
    uint16_t packet_proto_host;
    int packet_ifindex;
    /* Linux-like AF_PACKET receive queue (drop oldest when full). */
    uint8_t *packet_rxq;       /* PACKET_RXQ_DEPTH * PACKET_RXQ_FRAME */
    size_t *packet_rxq_len;    /* PACKET_RXQ_DEPTH lengths */
    int packet_rxq_r;
    int packet_rxq_w;
    int packet_rxq_n;
    int connected;
    uint32_t peer_ip_be;
    uint16_t peer_port;
    uint16_t local_port;
    int rx_has_pending;
    size_t rx_pending_len;
    size_t rx_pending_off;
    uint32_t rx_pending_src_ip_be;
    uint16_t rx_pending_src_port;
    uint8_t rx_pending[2048];
    uint32_t last_dst_ip_be;
    uint16_t last_echo_id;
    uint16_t last_echo_seq;
    uint16_t next_echo_seq;
    uint32_t last_rx_src_ip_be;
    uint16_t last_rx_echo_id;
    uint16_t last_rx_echo_seq;
    uint64_t last_rx_echo_ms;
    int last_req_ts_fmt;
    size_t last_req_len;
    uint8_t last_req[2048];
    uint32_t nl_pid;
    uint32_t nl_groups;
    uint32_t nl_peer_pid;
    uint8_t nl_rx[8192];
    size_t nl_rx_len;
    size_t nl_rx_off;
    /* glibc tries TCP :53 first; many routers RST -> ECONNREFUSED. Fake connect and use UDP for DNS. */
    int dns_tcp_udp_bridge;
    int nonblock; /* O_NONBLOCK: recv must not fake-EAGAIN after an internal short timeout */
    int async; /* FIOASYNC / O_ASYNC — SIGIO enable (nginx channel); delivery optional */
    int owner; /* F_SETOWN: pid (>0) or -pgid; SIGIO/SIGURG recipient */
    int sigio_signum; /* F_SETSIG; 0 = default SIGIO */
    int reuseaddr; /* SO_REUSEADDR / SO_REUSEPORT */
    int tcp_listening; /* INET stream socket in listen() state */
    net_tcp_conn_t tcp;
    int kref; /* references from fs_file handles sharing this ksock */
    int registry_slot;
} ksock_net_t;

#define KSOCK_REGISTRY_MAX 512
static ksock_net_t *g_ksock_registry[KSOCK_REGISTRY_MAX];
static spinlock_t g_ksock_registry_lock = { 0 };

static int ksock_register(ksock_net_t *s) {
    if (!s)
        return -1;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    if (s->registry_slot > 0 &&
        s->registry_slot <= KSOCK_REGISTRY_MAX &&
        g_ksock_registry[s->registry_slot - 1] == s) {
        release_irqrestore(&g_ksock_registry_lock, flags);
        return 0;
    }
    for (int i = 0; i < KSOCK_REGISTRY_MAX; ++i) {
        if (g_ksock_registry[i])
            continue;
        g_ksock_registry[i] = s;
        s->registry_slot = i + 1;
        release_irqrestore(&g_ksock_registry_lock, flags);
        return 0;
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    return -1;
}

typedef struct {
    int active;
    ksock_net_t *listener;
    uint32_t peer_ip_be;
    uint16_t peer_port;
    uint8_t peer_mac[6];
    uint32_t last_synack_tick;
    net_tcp_conn_t tcp;
} tcp_syn_wait_t;

#define TCP_SYN_WAIT_SLOTS 16
/*
 * net_tcp_conn_t contains large packet buffers. Keeping sixteen instances in
 * .bss pushed the kernel over 0x400000, where Linux x86-64 static ET_EXEC
 * binaries are linked. Retain the same slot count, but allocate slots lazily.
 */
static tcp_syn_wait_t *g_tcp_syn_wait[TCP_SYN_WAIT_SLOTS];
static spinlock_t g_tcp_syn_wait_lock = { 0 };

static int net_tcp_dispatch_incoming(const uint8_t *frame, size_t n);
static ksock_net_t *net_tcp_find_listener(uint16_t port);
static int lo_tcp_stream_connect(ksock_net_t *client, uint32_t dst_ip_be, uint16_t dport, thread_t *t);

/* Parse sockaddr_un from user memory into a kernel path buffer.
   Returns 0 on success, or Linux errno value on failure.
   out_len receives sun_path byte count (abstract names may embed NULs). */
static int unix_sockaddr_path_from_user(const void *addr_u, size_t addrlen, char *out, size_t out_cap,
                                        int *out_len, int *is_abstract) {
    if (!out || out_cap == 0) return EFAULT;
    memset(out, 0, out_cap);
    if (out_len) *out_len = 0;
    if (is_abstract) *is_abstract = 0;
    /* Linux unix_validate_addr: family + optional path. */
    if (!addr_u || addrlen < sizeof(uint16_t)) return EINVAL;
    if (!user_range_ok(addr_u, addrlen)) return EFAULT;
    uint16_t fam = 0;
    if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return EFAULT;
    if (fam != AF_UNIX_LOCAL) return EAFNOSUPPORT;

    size_t path_len = addrlen - sizeof(uint16_t);
    if (path_len > out_cap) path_len = out_cap;
    if (path_len == 0) {
        /* addrlen == sizeof(short) → autobind; not implemented → EINVAL like unbound. */
        return EINVAL;
    }
    if (copy_from_user_raw(out, (const uint8_t *)addr_u + sizeof(uint16_t), path_len) != 0)
        return EFAULT;
    if (out_len) *out_len = (int)path_len;
    if (out[0] == '\0') {
        if (is_abstract) *is_abstract = 1;
        return 0;
    }
    /* Pathname: ensure C string for VFS helpers (Linux accepts non-NUL-terminated sun_path). */
    if (path_len < out_cap)
        out[path_len] = '\0';
    else
        out[out_cap - 1] = '\0';
    return 0;
}

static int unix_path_equal(const ksock_net_t *s, const char *path, int path_len, int is_abs) {
    if (!s || !path || path_len <= 0) return 0;
    if (s->unix_abstract != (is_abs ? 1 : 0)) return 0;
    if (s->unix_path_len != path_len) return 0;
    return memcmp(s->unix_path, path, (size_t)path_len) == 0;
}

static void unix_ensure_parent_dirs(const char *path) {
    if (!path || path[0] != '/') return;
    char tmp[108];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) return;
    memcpy(tmp, path, n + 1);
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return;
    *slash = '\0';
    for (size_t i = 1; tmp[i]; i++) {
        if (tmp[i] != '/') continue;
        tmp[i] = '\0';
        (void)fs_mkdir(tmp);
        tmp[i] = '/';
    }
    (void)fs_mkdir(tmp);
}

static int unix_acceptq_push(ksock_net_t *listener, struct fs_file *pending_f) {
    if (!listener || !pending_f) return -1;
    unsigned long fl = 0;
    acquire_irqsave(&listener->unix_accept_lock, &fl);
    int cap = (int)(sizeof(listener->unix_accept_q) / sizeof(listener->unix_accept_q[0]));
    int maxq = listener->unix_backlog > 0 ? listener->unix_backlog : cap;
    if (maxq > cap) maxq = cap;
    if (listener->unix_accept_count >= maxq) {
        release_irqrestore(&listener->unix_accept_lock, fl);
        return -1;
    }
    listener->unix_accept_q[listener->unix_accept_tail] = pending_f;
    listener->unix_accept_tail = (listener->unix_accept_tail + 1) % cap;
    listener->unix_accept_count++;
    release_irqrestore(&listener->unix_accept_lock, fl);
    return 0;
}

static struct fs_file *unix_acceptq_pop(ksock_net_t *listener) {
    if (!listener) return NULL;
    struct fs_file *out = NULL;
    unsigned long fl = 0;
    acquire_irqsave(&listener->unix_accept_lock, &fl);
    if (listener->unix_accept_count > 0) {
        out = listener->unix_accept_q[listener->unix_accept_head];
        listener->unix_accept_q[listener->unix_accept_head] = NULL;
        listener->unix_accept_head = (listener->unix_accept_head + 1) % (int)(sizeof(listener->unix_accept_q) / sizeof(listener->unix_accept_q[0]));
        listener->unix_accept_count--;
    }
    release_irqrestore(&listener->unix_accept_lock, fl);
    return out;
}

static inline int ip_is_loopback_be(uint32_t ip_be) {
    return (ip_be & 0xFF000000u) == 0x7F000000u;
}

static ksock_net_t *unix_find_listener_by_path(const char *path, int path_len, int is_abs) {
    if (!path || path_len <= 0) return NULL;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    for (int i = 0; i < KSOCK_REGISTRY_MAX; i++) {
        ksock_net_t *s = g_ksock_registry[i];
        if (!s || !s->unix_domain_stub || !s->unix_listening || !s->unix_bound)
            continue;
        if (unix_path_equal(s, path, path_len, is_abs)) {
            release_irqrestore(&g_ksock_registry_lock, flags);
            return s;
        }
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    /* Fallback: scan process/thread fds (pre-registry listeners / races). */
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *th = thread_get_by_index(ti);
        if (!th) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = th->process && th->process->fds[fd] ?
                th->process->fds[fd] : th->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (!s->unix_domain_stub || !s->unix_listening || !s->unix_bound) continue;
            if (unix_path_equal(s, path, path_len, is_abs)) return s;
        }
    }
    return NULL;
}

static size_t unix_stream_avail_to_read(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 0;
    const unix_stream_conn_t *c = s->unix_conn;
    return (s->unix_end == 0) ? c->q10_count : c->q01_count;
}

static size_t unix_stream_avail_to_write(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 0;
    const unix_stream_conn_t *c = s->unix_conn;
    size_t cap = (s->unix_end == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t used = (s->unix_end == 0) ? c->q01_count : c->q10_count;
    if (used >= cap) return 0;
    return cap - used;
}

static int unix_stream_peer_closed(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 1;
    const unix_stream_conn_t *c = s->unix_conn;
    int peer = (s->unix_end == 0) ? 1 : 0;
    return c->closed[peer] ? 1 : 0;
}

static ssize_t unix_stream_write_from_user(ksock_net_t *s, const void *buf_u, size_t len) {
    if (!s || !s->unix_conn) return -ENOTCONN;
    if (len == 0) return 0;
    if (!buf_u) return -EINVAL;
    if (!user_range_ok(buf_u, len)) return -EFAULT;
    unix_stream_conn_t *c = s->unix_conn;
    int from = s->unix_end;
    int to = (from == 0) ? 1 : 0;
    uint8_t *q = (from == 0) ? c->q01 : c->q10;
    size_t cap = (from == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t *head = (from == 0) ? &c->q01_head : &c->q10_head;
    size_t *tail = (from == 0) ? &c->q01_tail : &c->q10_tail;
    size_t *count = (from == 0) ? &c->q01_count : &c->q10_count;
    size_t written = 0;
    while (written < len) {
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        if (c->closed[to]) {
            release_irqrestore(&c->lock, fl);
            return written > 0 ? (ssize_t)written : -EPIPE;
        }
        size_t free = cap - *count;
        if (free == 0) {
            release_irqrestore(&c->lock, fl);
            if (s->nonblock) return written > 0 ? (ssize_t)written : -EAGAIN;
            thread_sleep(1);
            continue;
        }
        size_t n = len - written;
        if (n > free) n = free;
        size_t h = *head;
        size_t first = (h + n <= cap) ? n : (cap - h);
        uint8_t tmp[256];
        size_t off = 0;
        while (off < n) {
            size_t ch = n - off;
            if (ch > sizeof(tmp)) ch = sizeof(tmp);
            if (copy_from_user_raw(tmp, (const uint8_t *)buf_u + written + off, ch) != 0) {
                release_irqrestore(&c->lock, fl);
                return written > 0 ? (ssize_t)written : -EFAULT;
            }
            if (off < first) {
                size_t p = first - off;
                if (p > ch) p = ch;
                memcpy(q + h + off, tmp, p);
                if (p < ch) memcpy(q, tmp + p, ch - p);
            } else {
                memcpy(q + (off - first), tmp, ch);
            }
            off += ch;
        }
        *head = (h + n) % cap;
        *count += n;
        (void)tail;
        release_irqrestore(&c->lock, fl);
        written += n;
    }
    return (ssize_t)written;
}

static ssize_t unix_stream_read_to_user(ksock_net_t *s, void *buf_u, size_t len, int peek) {
    if (!s || !s->unix_conn) return -ENOTCONN;
    if (len == 0) return 0;
    if (!buf_u) return -EINVAL;
    if (!user_range_ok(buf_u, len)) return -EFAULT;
    unix_stream_conn_t *c = s->unix_conn;
    int from = (s->unix_end == 0) ? 1 : 0;
    uint8_t *q = (from == 0) ? c->q01 : c->q10;
    size_t cap = (from == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t *head = (from == 0) ? &c->q01_head : &c->q10_head;
    size_t *tail = (from == 0) ? &c->q01_tail : &c->q10_tail;
    size_t *count = (from == 0) ? &c->q01_count : &c->q10_count;
    (void)head;
    for (;;) {
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        if (*count > 0) {
            size_t n = len;
            if (n > *count) n = *count;
            size_t t = *tail;
            size_t first = (t + n <= cap) ? n : (cap - t);
            uint8_t tmp[256];
            size_t off = 0;
            while (off < n) {
                size_t ch = n - off;
                if (ch > sizeof(tmp)) ch = sizeof(tmp);
                if (off < first) {
                    size_t p = first - off;
                    if (p > ch) p = ch;
                    memcpy(tmp, q + t + off, p);
                    if (p < ch) memcpy(tmp + p, q, ch - p);
                } else {
                    memcpy(tmp, q + (off - first), ch);
                }
                if (copy_to_user_safe((uint8_t *)buf_u + off, tmp, ch) != 0) {
                    release_irqrestore(&c->lock, fl);
                    return -EFAULT;
                }
                off += ch;
            }
            if (!peek) {
                *tail = (t + n) % cap;
                *count -= n;
            }
            release_irqrestore(&c->lock, fl);
            return (ssize_t)n;
        }
        if (c->closed[from]) {
            release_irqrestore(&c->lock, fl);
            return 0;
        }
        release_irqrestore(&c->lock, fl);
        if (s->nonblock) return -EAGAIN;
        thread_sleep(1);
    }
}

static void unix_socket_cleanup(ksock_net_t *s) {
    if (!s) return;
    if (s->unix_listening) {
        struct fs_file *pf = NULL;
        while ((pf = unix_acceptq_pop(s)) != NULL) {
            /*
             * Queued accepts are ksock_register'd. Raw kfree left stale
             * registry slots → UAF on later lookup/teardown. Mirror TCP
             * accept rollback: net_fs_file_destroy → ksock_drop.
             */
            net_fs_file_destroy(pf);
        }
    }
    if (s->unix_conn) {
        unix_stream_conn_t *c = s->unix_conn;
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        c->closed[s->unix_end] = 1;
        c->refs--;
        int refs = c->refs;
        release_irqrestore(&c->lock, fl);
        if (refs <= 0) kfree(c);
        s->unix_conn = NULL;
    }
}

/* ---------- SysV SHM (minimal real implementation) ---------- */
#define SYSV_SHM_MAX_SEGMENTS 64
#define SYSV_SHM_MAX_ATTACH   256
#define SYSV_SHM_BASE         ((uintptr_t)0x0E000000ULL)

typedef struct {
    int used;
    int shmid;
    int key;
    size_t size;
    uintptr_t base;
    uint32_t mode;
    uid_t cuid;
    gid_t cgid;
    uid_t uid;
    gid_t gid;
    uint32_t cpid;
    uint32_t lpid;
    uint64_t atime;
    uint64_t dtime;
    uint64_t ctime;
    uint32_t nattch;
    int removed;
} sysv_shm_seg_t;

typedef struct {
    int used;
    int shmid;
    uint64_t tid;
    uintptr_t addr;
    int readonly;
} sysv_shm_attach_t;

static sysv_shm_seg_t g_sysv_shm[SYSV_SHM_MAX_SEGMENTS];
static sysv_shm_attach_t g_sysv_shm_attach[SYSV_SHM_MAX_ATTACH];
static int g_sysv_shm_next_id = 1;
static uintptr_t g_sysv_shm_next_addr = SYSV_SHM_BASE;
static spinlock_t g_sysv_shm_lock = { 0 };

static inline uint64_t sysv_shm_now_secs(void) {
    return pit_get_time_ms() / 1000ull;
}

static sysv_shm_seg_t *sysv_shm_find_by_id_nolock(int shmid) {
    for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
        if (g_sysv_shm[i].used && g_sysv_shm[i].shmid == shmid) return &g_sysv_shm[i];
    }
    return NULL;
}

static sysv_shm_seg_t *sysv_shm_find_by_key_nolock(int key) {
    for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
        if (g_sysv_shm[i].used && !g_sysv_shm[i].removed && g_sysv_shm[i].key == key) return &g_sysv_shm[i];
    }
    return NULL;
}

static uintptr_t sysv_shm_alloc_va_nolock(size_t size) {
    uintptr_t top = (uintptr_t)USER_TLS_BASE;
    uintptr_t addr = (g_sysv_shm_next_addr + 4095u) & ~(uintptr_t)4095u;
    if (addr < SYSV_SHM_BASE) addr = SYSV_SHM_BASE;
    if (addr + size < addr) return 0;
    if (addr + size >= top) return 0;
    g_sysv_shm_next_addr = addr + size;
    return addr;
}

static int sysv_shm_register_attach_nolock(int shmid, uint64_t tid, uintptr_t addr, int readonly) {
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used) {
            g_sysv_shm_attach[i].used = 1;
            g_sysv_shm_attach[i].shmid = shmid;
            g_sysv_shm_attach[i].tid = tid;
            g_sysv_shm_attach[i].addr = addr;
            g_sysv_shm_attach[i].readonly = readonly;
            return 0;
        }
    }
    return -1;
}

static int sysv_shm_detach_one_by_tid_addr_nolock(uint64_t tid, uintptr_t addr, int *out_shmid) {
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used) continue;
        if (g_sysv_shm_attach[i].tid != tid) continue;
        if (g_sysv_shm_attach[i].addr != addr) continue;
        int shmid = g_sysv_shm_attach[i].shmid;
        g_sysv_shm_attach[i].used = 0;
        if (out_shmid) *out_shmid = shmid;
        return 0;
    }
    return -1;
}

static void sysv_shm_cleanup_removed_nolock(sysv_shm_seg_t *seg) {
    if (!seg) return;
    if (seg->removed && seg->nattch == 0) {
        seg->used = 0;
    }
}

static void sysv_shm_detach_all_for_tid(uint64_t tid) {
    unsigned long fl = 0;
    acquire_irqsave(&g_sysv_shm_lock, &fl);
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used || g_sysv_shm_attach[i].tid != tid) continue;
        int shmid = g_sysv_shm_attach[i].shmid;
        g_sysv_shm_attach[i].used = 0;
        sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
        if (seg) {
            if (seg->nattch > 0) seg->nattch--;
            seg->dtime = sysv_shm_now_secs();
            seg->lpid = (uint32_t)tid;
            sysv_shm_cleanup_removed_nolock(seg);
        }
    }
    release_irqrestore(&g_sysv_shm_lock, fl);
}

struct sysv_ipc_perm_compat {
    uint32_t key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint16_t mode;
    uint16_t __pad1;
    uint16_t seq;
    uint16_t __pad2;
    uint64_t __unused1;
    uint64_t __unused2;
};

struct sysv_shmid_ds_compat {
    struct sysv_ipc_perm_compat shm_perm;
    uint64_t shm_segsz;
    int64_t shm_atime;
    int64_t shm_dtime;
    int64_t shm_ctime;
    int32_t shm_cpid;
    int32_t shm_lpid;
    uint64_t shm_nattch;
    uint64_t __unused4;
    uint64_t __unused5;
};

static inline size_t ksock_rx_pending_cap(void) {
    return (size_t)sizeof(((ksock_net_t *)0)->rx_pending);
}

/* Drop inconsistent pending state (e.g. off > len) before using rx_pending. */
static inline void ksock_rx_pending_normalize(ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return;
    size_t cap = ksock_rx_pending_cap();
    if (s->rx_pending_len > cap || s->rx_pending_off > s->rx_pending_len) {
        s->rx_has_pending = 0;
        s->rx_pending_len = 0;
        s->rx_pending_off = 0;
    }
}

static inline size_t ksock_rx_pending_avail(const ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return 0;
    if (s->rx_pending_off > s->rx_pending_len) return 0;
    return s->rx_pending_len - s->rx_pending_off;
}

static inline void ksock_rx_pending_install(ksock_net_t *s, int rn) {
    if (!s || rn <= 0) return;
    size_t n = (size_t)rn;
    size_t cap = ksock_rx_pending_cap();
    if (n > cap) n = cap;
    s->rx_has_pending = 1;
    s->rx_pending_len = n;
    s->rx_pending_off = 0;
}

typedef struct {
    int inited;
    int if_up;
    int ready;
    uint8_t mac[6];
    uint32_t ip_be;
    uint32_t mask_be;
    uint32_t gw_be;
    uint32_t dns_be;
    uint16_t ip_id;
    uint8_t gw_mac[6];
    int gw_mac_valid;
} net_state_t;

static net_state_t g_net;
static net_state_t g_net_shadow;
static int g_net_shadow_valid = 0;
static int g_net_from_dhcp = 0; /* lease came from userspace DHCP / ioctl path */
static volatile int g_net_dhcp_busy = 0; /* dhcp_acquire owns NIC RX; net_rx must not steal */
static int g_net_trace_budget;
static int g_net_l2_trace_budget;

static inline uint16_t be16(uint16_t v);
static inline uint32_t be32(uint32_t v);

/* Shared ARP table: RX pump and resolve must both update/consult it (Linux-like). */
#define ARP_CACHE_SLOTS 64
typedef struct {
    uint32_t ip_be;
    uint8_t mac[6];
    int valid;
} arp_cache_ent_t;
static arp_cache_ent_t g_arp_cache[ARP_CACHE_SLOTS];
static spinlock_t g_arp_cache_lock = { 0 };

static void net_arp_cache_learn(uint32_t ip_be, const uint8_t mac[6]) {
    if (!ip_be || !mac) return;
    if ((mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0) return;
    unsigned long irqf = 0;
    acquire_irqsave(&g_arp_cache_lock, &irqf);
    int free_slot = -1;
    for (int i = 0; i < ARP_CACHE_SLOTS; i++) {
        if (g_arp_cache[i].valid && g_arp_cache[i].ip_be == ip_be) {
            memcpy(g_arp_cache[i].mac, mac, 6);
            release_irqrestore(&g_arp_cache_lock, irqf);
            if (ip_be == g_net.gw_be) {
                memcpy(g_net.gw_mac, mac, 6);
                g_net.gw_mac_valid = 1;
            }
            return;
        }
        if (!g_arp_cache[i].valid && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        free_slot = (int)(pit_get_ticks() % (uint32_t)ARP_CACHE_SLOTS);
    g_arp_cache[free_slot].ip_be = ip_be;
    memcpy(g_arp_cache[free_slot].mac, mac, 6);
    g_arp_cache[free_slot].valid = 1;
    release_irqrestore(&g_arp_cache_lock, irqf);
    if (ip_be == g_net.gw_be) {
        memcpy(g_net.gw_mac, mac, 6);
        g_net.gw_mac_valid = 1;
    }
}

static int net_arp_cache_lookup(uint32_t ip_be, uint8_t out_mac[6]) {
    if (!out_mac || !ip_be) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_arp_cache_lock, &irqf);
    for (int i = 0; i < ARP_CACHE_SLOTS; i++) {
        if (g_arp_cache[i].valid && g_arp_cache[i].ip_be == ip_be) {
            memcpy(out_mac, g_arp_cache[i].mac, 6);
            release_irqrestore(&g_arp_cache_lock, irqf);
            return 0;
        }
    }
    release_irqrestore(&g_arp_cache_lock, irqf);
    return -1;
}

static void net_arp_observe_frame(const uint8_t *frame, size_t n) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->htype) != 1 || be16(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4)
        return;
    uint16_t oper = be16(arp->oper);
    if (oper != 1 && oper != 2) return;
    uint32_t spa = ((uint32_t)arp->spa[0] << 24) | ((uint32_t)arp->spa[1] << 16) |
                   ((uint32_t)arp->spa[2] << 8) | (uint32_t)arp->spa[3];
    net_arp_cache_learn(spa, arp->sha);
}

static int net_l3_send_errno(void) {
    if (!g_net.if_up || !e1000_is_ready()) return ENETDOWN;
    if (!g_net.ready || !g_net.ip_be) return ENETUNREACH;
    return EHOSTUNREACH;
}

static int net_stack_init(void);

/* AF_PACKET sockets (udhcpc raw DHCP before we have an IPv4 address). */
#define PACKET_SOCK_MAX 16
#define PACKET_RXQ_DEPTH 128
#define PACKET_RXQ_FRAME 2048
static ksock_net_t *g_packet_socks[PACKET_SOCK_MAX];
static spinlock_t g_packet_socks_lock = { 0 };

static void packet_sock_register(ksock_net_t *s) {
    if (!s) return;
    if (!s->packet_rxq) {
        s->packet_rxq = (uint8_t *)kmalloc((size_t)PACKET_RXQ_DEPTH * PACKET_RXQ_FRAME);
        s->packet_rxq_len = (size_t *)kmalloc((size_t)PACKET_RXQ_DEPTH * sizeof(size_t));
        if (!s->packet_rxq || !s->packet_rxq_len) {
            if (s->packet_rxq) { kfree(s->packet_rxq); s->packet_rxq = NULL; }
            if (s->packet_rxq_len) { kfree(s->packet_rxq_len); s->packet_rxq_len = NULL; }
        } else {
            memset(s->packet_rxq_len, 0, (size_t)PACKET_RXQ_DEPTH * sizeof(size_t));
            s->packet_rxq_r = s->packet_rxq_w = s->packet_rxq_n = 0;
        }
    }
    unsigned long irqf = 0;
    acquire_irqsave(&g_packet_socks_lock, &irqf);
    for (int i = 0; i < PACKET_SOCK_MAX; i++) {
        if (!g_packet_socks[i]) {
            g_packet_socks[i] = s;
            break;
        }
    }
    release_irqrestore(&g_packet_socks_lock, irqf);
}

static void packet_sock_unregister(ksock_net_t *s) {
    if (!s) return;
    unsigned long irqf = 0;
    acquire_irqsave(&g_packet_socks_lock, &irqf);
    for (int i = 0; i < PACKET_SOCK_MAX; i++) {
        if (g_packet_socks[i] == s)
            g_packet_socks[i] = NULL;
    }
    release_irqrestore(&g_packet_socks_lock, irqf);
    if (s->packet_rxq) { kfree(s->packet_rxq); s->packet_rxq = NULL; }
    if (s->packet_rxq_len) { kfree(s->packet_rxq_len); s->packet_rxq_len = NULL; }
    s->packet_rxq_r = s->packet_rxq_w = s->packet_rxq_n = 0;
    s->rx_has_pending = 0;
}

/* Enqueue one L3 (SOCK_DGRAM) or L2 (SOCK_RAW) frame. Drop oldest if full. */
static void packet_sock_enqueue(ksock_net_t *s, const uint8_t *data, size_t len) {
    if (!s || !data || len == 0 || !s->packet_rxq || !s->packet_rxq_len) return;
    if (len > PACKET_RXQ_FRAME) len = PACKET_RXQ_FRAME;
    if (s->packet_rxq_n >= PACKET_RXQ_DEPTH) {
        s->packet_rxq_r = (s->packet_rxq_r + 1) % PACKET_RXQ_DEPTH;
        s->packet_rxq_n--;
    }
    memcpy(s->packet_rxq + (size_t)s->packet_rxq_w * PACKET_RXQ_FRAME, data, len);
    s->packet_rxq_len[s->packet_rxq_w] = len;
    s->packet_rxq_w = (s->packet_rxq_w + 1) % PACKET_RXQ_DEPTH;
    s->packet_rxq_n++;
    s->rx_has_pending = 1;
}

static int packet_sock_dequeue(ksock_net_t *s, uint8_t *out, size_t cap, int peek) {
    if (!s || !out || cap == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_packet_socks_lock, &irqf);
    if (!s->packet_rxq || s->packet_rxq_n <= 0) {
        release_irqrestore(&g_packet_socks_lock, irqf);
        return 0;
    }
    size_t len = s->packet_rxq_len[s->packet_rxq_r];
    size_t ncopy = (len > cap) ? cap : len;
    memcpy(out, s->packet_rxq + (size_t)s->packet_rxq_r * PACKET_RXQ_FRAME, ncopy);
    if (!peek) {
        s->packet_rxq_r = (s->packet_rxq_r + 1) % PACKET_RXQ_DEPTH;
        s->packet_rxq_n--;
        if (s->packet_rxq_n <= 0) {
            s->packet_rxq_n = 0;
            s->rx_has_pending = 0;
        }
    }
    release_irqrestore(&g_packet_socks_lock, irqf);
    return (int)ncopy;
}

static int packet_sock_has_data(ksock_net_t *s) {
    int ready;
    unsigned long irqf = 0;

    if (!s) return 0;
    acquire_irqsave(&g_packet_socks_lock, &irqf);
    ready = s->packet_rxq && s->packet_rxq_n > 0;
    release_irqrestore(&g_packet_socks_lock, irqf);
    return ready;
}

static int net_l2_payload(const uint8_t *frame, size_t n, uint16_t *protocol,
                          const uint8_t **payload, size_t *payload_len)
{
    size_t off = sizeof(eth_hdr_t);
    uint16_t proto;

    if (!frame || n < off || !protocol || !payload || !payload_len)
        return -1;
    proto = ((uint16_t)frame[12] << 8) | frame[13];
    for (int tags = 0; tags < 2 &&
         (proto == 0x8100u || proto == 0x88a8u); tags++) {
        if (n < off + 4)
            return -1;
        proto = ((uint16_t)frame[off + 2] << 8) | frame[off + 3];
        off += 4;
    }
    *protocol = proto;
    *payload = frame + off;
    *payload_len = n - off;
    return 0;
}

static int net_packet_deliver(const uint8_t *frame, size_t n) {
    if (!frame || n < sizeof(eth_hdr_t)) return 0;
    uint16_t et_host;
    const uint8_t *payload;
    size_t plen;

    if (net_l2_payload(frame, n, &et_host, &payload, &plen) != 0)
        return 0;
    int delivered = 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_packet_socks_lock, &irqf);
    for (int i = 0; i < PACKET_SOCK_MAX; i++) {
        ksock_net_t *s = g_packet_socks[i];
        if (!s || s->sock_domain != AF_PACKET_LOCAL) continue;
        if (s->packet_proto_host && s->packet_proto_host != ETH_P_ALL_HOST &&
            s->packet_proto_host != et_host)
            continue;
        if (s->type_base == SOCK_RAW_LOCAL)
            packet_sock_enqueue(s, frame, n);
        else
            packet_sock_enqueue(s, payload, plen);
        delivered = 1;
    }
    release_irqrestore(&g_packet_socks_lock, irqf);
    return delivered;
}

static int net_packet_send_frame(ksock_net_t *s, const uint8_t dst_mac[6],
                                 const uint8_t *payload, size_t payload_len) {
    if (!s || !dst_mac || !payload || payload_len == 0) return -1;
    if (net_stack_init() != 0) return -1;
    if (!g_net.if_up) return -1;
    size_t frame_len;
    uint8_t *frame;
    if (s->type_base == SOCK_RAW_LOCAL) {
        /* Userspace provided a full ethernet frame. */
        frame_len = payload_len;
        frame = (uint8_t *)kmalloc(frame_len);
        if (!frame) return -1;
        memcpy(frame, payload, payload_len);
    } else {
        frame_len = sizeof(eth_hdr_t) + payload_len;
        frame = (uint8_t *)kmalloc(frame_len);
        if (!frame) return -1;
        eth_hdr_t *eth = (eth_hdr_t *)frame;
        memcpy(eth->dst, dst_mac, 6);
        memcpy(eth->src, g_net.mac, 6);
        eth->ethertype = be16(s->packet_proto_host ? s->packet_proto_host : ETH_TYPE_IPV4);
        memcpy(frame + sizeof(eth_hdr_t), payload, payload_len);
    }
    int r = e1000_send_frame(frame, frame_len);
    if (g_net_l2_trace_budget-- > 0) {
        klogprintf("net-l2: tx proto=0x%04x len=%u rc=%d\n",
                   (unsigned)s->packet_proto_host, (unsigned)frame_len, r);
    }
    kfree(frame);
    return (r < 0) ? -1 : 0;
}

typedef struct __attribute__((packed)) {
    uint16_t sll_family;
    uint16_t sll_protocol;
    int32_t sll_ifindex;
    uint16_t sll_hatype;
    uint8_t sll_pkttype;
    uint8_t sll_halen;
    uint8_t sll_addr[8];
} sockaddr_ll_k;

/* ---------- RX pump: answer ARP/ICMP and queue everything else ---------- */
static uint16_t ip_checksum16(const void *data, size_t len);
static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]);
static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len);

#define NET_RXQ_SLOTS  128
#define NET_RXQ_BUF    2048
static uint8_t g_net_rxq[NET_RXQ_SLOTS][NET_RXQ_BUF];
static uint16_t g_net_rxq_len[NET_RXQ_SLOTS];
static uint32_t g_net_rxq_head = 0, g_net_rxq_tail = 0, g_net_rxq_count = 0;
static spinlock_t g_net_rxq_lock = { 0 };
static spinlock_t g_net_nic_lock = { 0 };
static volatile int g_net_tcp_connect_active = 0;
static int g_net_tcp_sniff_left = 0;
static uint8_t g_tcp_xmit_mac[6];
static int g_tcp_xmit_mac_valid = 0;
static int g_net_rx_thread_started = 0;

static int net_rxq_push(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return -1;
    if (n > NET_RXQ_BUF) n = NET_RXQ_BUF;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count >= NET_RXQ_SLOTS) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return -2;
    }
    memcpy(g_net_rxq[g_net_rxq_tail], frame, n);
    g_net_rxq_len[g_net_rxq_tail] = (uint16_t)n;
    g_net_rxq_tail = (g_net_rxq_tail + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count++;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return 0;
}

static int net_rxq_pop(void *out, size_t cap) {
    if (!out || cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t idx = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[idx];
    g_net_rxq_len[idx] = 0;
    g_net_rxq_head = (idx + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    size_t copy_len = (n > cap) ? cap : (size_t)n;
    memcpy(out, g_net_rxq[idx], copy_len);
    return (int)copy_len;
}

static int net_reply_arp_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return 0;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->oper) != 1) return 0; /* request */
    if (be16(arp->htype) != 1 || be16(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4) return 0;
    uint32_t tpa = ((uint32_t)arp->tpa[0] << 24) | ((uint32_t)arp->tpa[1] << 16) | ((uint32_t)arp->tpa[2] << 8) | arp->tpa[3];
    if (tpa != g_net.ip_be) return 0;

    uint8_t reply[64];
    memset(reply, 0, sizeof(reply));
    eth_hdr_t *reth = (eth_hdr_t *)reply;
    memcpy(reth->dst, eth->src, 6);
    memcpy(reth->src, g_net.mac, 6);
    reth->ethertype = be16(ETH_TYPE_ARP);
    arp_hdr_t *rarp = (arp_hdr_t *)(reply + sizeof(eth_hdr_t));
    rarp->htype = be16(1);
    rarp->ptype = be16(ETH_TYPE_IPV4);
    rarp->hlen = 6;
    rarp->plen = 4;
    rarp->oper = be16(2); /* reply */
    memcpy(rarp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, rarp->spa);
    memcpy(rarp->tha, arp->sha, 6);
    memcpy(rarp->tpa, arp->spa, 4);
    (void)e1000_send_frame(reply, sizeof(reply));
    return 1;
}

static int net_reply_icmp_echo_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8) return 0;
    static int icmp_dbg_left = 3;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint32_t dst_ip_be = be32(ip->dst);
    if (dst_ip_be != g_net.ip_be) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + (size_t)tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 8 || icmp[1] != 0) return 0; /* echo request */
    size_t icmp_len = (size_t)tot - ihl;
    if (icmp_dbg_left-- > 0) {
        uint32_t src_ip_be = be32(ip->src);
        klogprintf("net: ICMP echo request from %u.%u.%u.%u len=%u\n",
                   (unsigned)((src_ip_be >> 24) & 0xFF), (unsigned)((src_ip_be >> 16) & 0xFF),
                   (unsigned)((src_ip_be >> 8) & 0xFF), (unsigned)(src_ip_be & 0xFF),
                   (unsigned)icmp_len);
    }

    uint8_t *reply = (uint8_t *)kmalloc(icmp_len);
    if (!reply) return 1; /* consume to avoid loops; out of memory */
    memcpy(reply, icmp, icmp_len);
    reply[0] = 0; /* echo reply */
    reply[2] = 0; reply[3] = 0;
    uint16_t csum = ip_checksum16(reply, icmp_len);
    reply[2] = (uint8_t)(csum >> 8);
    reply[3] = (uint8_t)(csum);
    uint32_t src_ip_be = be32(ip->src);
    (void)net_send_eth_ipv4(eth->src, src_ip_be, IPPROTO_ICMP_LOCAL, reply, icmp_len);
    kfree(reply);
    if (icmp_dbg_left >= 0) klogprintf("net: ICMP echo reply sent\n");
    return 1;
}

static int net_process_incoming_or_queue(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return 0;
    if (g_net_l2_trace_budget-- > 0 && n >= sizeof(eth_hdr_t)) {
        const eth_hdr_t *eth = (const eth_hdr_t *)frame;

        klogprintf("net-l2: rx proto=0x%04x len=%u\n",
                   (unsigned)be16(eth->ethertype), (unsigned)n);
    }
    /* Learn ARP before demux so resolve/send do not race the RX pump. */
    net_arp_observe_frame(frame, n);
    (void)net_packet_deliver(frame, n);
    if (!g_net.ready) return 1; /* L2 only: udhcpc AF_PACKET before address */
    if (net_reply_arp_if_needed(frame, n)) return 1;
    if (net_reply_icmp_echo_if_needed(frame, n)) return 1;
    if (net_tcp_dispatch_incoming(frame, n)) return 1;
    (void)net_rxq_push(frame, n);
    return 1;
}

static int net_nic_pull_frame(void *buf, size_t cap);

/* Pump NIC into packet socks / stack. Static buf — safe on deep syscall stacks. */
static void net_packet_pump_rx(int budget) {
    static uint8_t frame[NET_RXQ_BUF];
    if (budget < 1) budget = 1;
    if (budget > 32) budget = 32;
    for (int i = 0; i < budget; i++) {
        int rn = net_nic_pull_frame(frame, sizeof(frame));
        if (rn <= 0) break;
        (void)net_process_incoming_or_queue(frame, (size_t)rn);
    }
}

/* AF_PACKET read into kernel buffer. Returns bytes or -errno. */
static int net_packet_sock_recv(ksock_net_t *s, uint8_t *out, size_t cap, int peek, uint32_t wait_ms) {
    if (!s || !out || cap == 0) return -EINVAL;
    uint64_t start = pit_get_time_ms();
    for (;;) {
        thread_t *cur = thread_current();
        if (thread_has_interrupt_signal(cur))
            return -EINTR;
        if (packet_sock_has_data(s)) break;
        net_packet_pump_rx(16);
        if (packet_sock_has_data(s)) break;
        if (wait_ms == 0) return -EAGAIN;
        if ((pit_get_time_ms() - start) >= (uint64_t)wait_ms) return -EAGAIN;
        thread_sleep(1);
    }
    if (packet_sock_has_data(s))
        return packet_sock_dequeue(s, out, cap, peek);
    /* Legacy single-slot path (should not be used for AF_PACKET). */
    size_t avail = s->rx_pending_len;
    size_t ncopy = (avail > cap) ? cap : avail;
    if (ncopy > 0) memcpy(out, s->rx_pending, ncopy);
    if (!peek) {
        s->rx_has_pending = 0;
        s->rx_pending_len = 0;
        s->rx_pending_off = 0;
    }
    return (int)ncopy;
}

/* Single consumer for e1000 RX ring (net_rx thread + syscalls share this lock). */
static int net_nic_pull_frame(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_nic_lock, &irqf);
    int n = e1000_recv_frame(buf, cap);
    release_irqrestore(&g_net_nic_lock, irqf);
    return n;
}

static void net_nic_drain_to_rxq(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(frame, sizeof(frame));
        if (n <= 0) break;
        if (net_reply_arp_if_needed(frame, (size_t)n)) continue;
        if (net_reply_icmp_echo_if_needed(frame, (size_t)n)) continue;
        if (net_rxq_push(frame, (size_t)n) != 0) {
            uint8_t drop[NET_RXQ_BUF];
            (void)net_rxq_pop(drop, sizeof(drop));
            (void)net_rxq_push(frame, (size_t)n);
        }
    }
}

/* Pull NIC frames and run TCP listen/handshake immediately (accept must not only enqueue). */
static void net_nic_drain_process_incoming(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(frame, sizeof(frame));
        if (n <= 0) break;
        (void)net_process_incoming_or_queue(frame, (size_t)n);
    }
}

static void net_rxq_drain_process_incoming(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_rxq_pop(frame, sizeof(frame));
        if (n <= 0) break;
        (void)net_process_incoming_or_queue(frame, (size_t)n);
    }
}

static void net_pump_listen_handshake(void) {
    net_nic_drain_process_incoming(8);
    net_rxq_drain_process_incoming(4);
}

static void net_nic_discard_pending(int budget) {
    uint8_t junk[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(junk, sizeof(junk));
        if (n <= 0) break;
        (void)net_reply_arp_if_needed(junk, (size_t)n);
        (void)net_reply_icmp_echo_if_needed(junk, (size_t)n);
    }
}

static int net_recv_frame_any(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    int qn = net_rxq_pop(buf, cap);
    if (qn > 0) return qn;
    net_nic_drain_to_rxq(16);
    return net_rxq_pop(buf, cap);
}

/* Drop queued RX frames (stale TCP after failed HTTPS, etc.) before a new connect. */
static void net_rxq_flush(void) {
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    g_net_rxq_head = 0;
    g_net_rxq_tail = 0;
    g_net_rxq_count = 0;
    release_irqrestore(&g_net_rxq_lock, irqf);
    net_nic_discard_pending(64);
}

/* Match IPv4/TCP frame to an established connection (same filters as net/tcp.c). */
static int net_tcp_match_frame(const uint8_t *frame, size_t n, uint32_t local_ip_be,
    const net_tcp_conn_t *c) {
    if (!c || !c->used || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 20u)
        return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if ((be16(ip->frag_off) & 0x1FFFu) != 0) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) return 0;
    if (be32(ip->dst) != local_ip_be || be32(ip->src) != c->dst_ip_be) return 0;
    const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(th->src_port) != c->dst_port || be16(th->dst_port) != c->src_port) return 0;
    return 1;
}

/* Log any IPv4 RX during blocking connect (SYN-ACK, ICMP errors, etc.). */
static void net_tcp_sniff_frame(const uint8_t *frame, size_t n, const net_tcp_conn_t *c) {
    if (!g_net_tcp_connect_active || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t))
        return;
    /* Budgeted debug only — never re-arm forever (that painted VGA on every RX). */
    if (g_net_tcp_sniff_left <= 0)
        return;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return;
    uint32_t sip = be32(ip->src), dip = be32(ip->dst);
    if (ip->proto == IPPROTO_TCP_LOCAL && n >= sizeof(eth_hdr_t) + ihl + 20u && c) {
        const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
        klogprintf("tcp: sniff tcp %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u fl=0x%02x ack=%u match=%d\n",
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF), (unsigned)be16(th->src_port),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF), (unsigned)be16(th->dst_port),
            (unsigned)th->flags, (unsigned)be32(th->ack),
            net_tcp_match_frame(frame, n, g_net.ip_be, c));
    } else if (ip->proto == IPPROTO_ICMP_LOCAL) {
        klogprintf("tcp: sniff icmp %u.%u.%u.%u -> %u.%u.%u.%u type=%u\n",
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF),
            (unsigned)(frame[sizeof(eth_hdr_t) + ihl]));
    } else {
        klogprintf("tcp: sniff proto=%u %u.%u.%u.%u -> %u.%u.%u.%u\n",
            (unsigned)ip->proto,
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF));
    }
    g_net_tcp_sniff_left--;
}

/* Dequeue a TCP frame for this socket without head-of-line blocking (DNS-style scan). */
static int net_rxq_take_tcp_frame(const net_tcp_conn_t *c, uint32_t local_ip_be,
    void *buf, size_t cap) {
    if (!c || !buf || cap == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_tcp_match_frame(g_net_rxq[idx], fn, local_ip_be, c)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    size_t copy_len = (n > cap) ? cap : (size_t)n;
    memcpy(buf, g_net_rxq[hi2], copy_len);
    return (int)copy_len;
}

static int net_stack_init(void);
static int net_run_dhcp(void);
static int net_ensure_ipv4(void);
static int net_apply_ipv4(uint32_t ip_be, uint32_t mask_be, uint32_t gw_be, uint32_t dns_be, int from_dhcp);
static void net_announce_ipv4(const char *how);
static void net_write_resolv_from_dns(uint32_t dns_be);

static void net_rx_pump_thread(void) {
    uint8_t buf[NET_RXQ_BUF];
    for (;;) {
        if (g_net_dhcp_busy) {
            /* In-kernel dhcp_acquire (legacy) polls e1000 — do not steal frames. */
            thread_sleep(5);
            continue;
        }
        if (!g_net.if_up) {
            thread_sleep(50);
            continue;
        }
        /* Always drain L2 RX: ARP + AF_PACKET (udhcpc) before IPv4 is configured. */
        for (int i = 0; i < 32; i++) {
            int n = net_nic_pull_frame(buf, sizeof(buf));
            if (n <= 0) break;
            (void)net_process_incoming_or_queue(buf, (size_t)n);
        }
        thread_sleep(1);
    }
}

static inline uint16_t be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t be32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* Linux-style demux: scan the software RX ring for a matching UDP datagram; do not drop non-matches
 * that belong to TCP or another UDP port (head-of-line blocking was losing DNS replies). */
static int net_udp_match_sock_frame(const uint8_t *frame, size_t n, ksock_net_t *s) {
    if (!s || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != s->local_port) return 0;
    uint32_t src_ip = be32(ip->src);
    uint16_t sport = be16(uh->src_port);
    if (s->connected) {
        int ok = (src_ip == s->peer_ip_be && sport == s->peer_port);
        if (!ok && s->peer_port == 53u && sport == 53u &&
            ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
             (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)))
            ok = 1;
        if (!ok) return 0;
    }
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    return 1;
}

static int net_udp_match_raw_frame(const uint8_t *frame, size_t n, uint16_t local_port,
                                   uint32_t peer_ip_be, uint16_t peer_port) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != local_port) return 0;
    uint32_t sip = be32(ip->src);
    uint16_t sp = be16(uh->src_port);
    int ok = (sip == peer_ip_be && sp == peer_port);
    if (!ok && peer_port == 53u && sp == 53u) ok = 1;
    return ok ? 1 : 0;
}

static int net_udp_copy_payload_from_frame(const uint8_t *frame, size_t n, uint8_t *out, size_t out_cap,
                                          uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!frame || !out || out_cap == 0) return 0;
    if (n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t sport = be16(uh->src_port);
    uint32_t src_ip = be32(ip->src);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    size_t copy_len = (payload_len > out_cap) ? out_cap : payload_len;
    if (copy_len > 0) memcpy(out, (const uint8_t *)uh + sizeof(udp_hdr_t), copy_len);
    if (out_src_ip_be) *out_src_ip_be = src_ip;
    if (out_src_port) *out_src_port = sport;
    return (int)copy_len;
}

/* UDP payload length in frame (for FIONREAD); 0 if not a valid IPv4 UDP datagram. */
static int net_udp_payload_len_from_frame(const uint8_t *frame, size_t n) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    if (payload_len > 0x7fffffffu) return 0;
    return (int)payload_len;
}

/* Bytes available for recv without dequeuing (head-of-line: first matching UDP in RX queue). */
static int net_rxq_peek_udp_payload_for_sock(ksock_net_t *s) {
    if (!s || s->local_port == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    uint32_t head0 = g_net_rxq_head;
    int plen = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            plen = net_udp_payload_len_from_frame(g_net_rxq[idx], fn);
            break;
        }
    }
    release_irqrestore(&g_net_rxq_lock, irqf);
    return plen;
}

static int net_recv_post_arp_icmp_from_nic(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    for (int i = 0; i < 16; i++) {
        int nn = net_nic_pull_frame(buf, cap);
        if (nn <= 0) return nn;
        if (net_reply_arp_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        if (net_reply_icmp_echo_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        (void)net_rxq_push((const uint8_t *)buf, (size_t)nn);
    }
    return 0;
}

static int net_rxq_take_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap,
                                    uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, out_src_ip_be, out_src_port);
}

static int net_rxq_take_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                               uint8_t *out, size_t out_cap) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_raw_frame(g_net_rxq[idx], fn, local_port, peer_ip_be, peer_port)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, NULL, NULL);
}

static uint16_t ip_checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)((uint16_t)p[0] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]) {
    out[0] = (uint8_t)(ip_be >> 24);
    out[1] = (uint8_t)(ip_be >> 16);
    out[2] = (uint8_t)(ip_be >> 8);
    out[3] = (uint8_t)(ip_be);
}

static int ip_same_subnet(uint32_t a_be, uint32_t b_be, uint32_t mask_be) {
    return ((a_be & mask_be) == (b_be & mask_be));
}

static int net_stack_init(void);
static void net_ensure_resolv_conf(uint32_t dns_be);
static int ip_mask_prefix_len(uint32_t mask_be);
static int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms);

static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len) {
    if (!g_net.ready || !dst_mac || !l4 || l4_len > 1500) return -1;
    size_t frame_len = sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + l4_len;
    uint8_t *frame = (uint8_t *)kmalloc(frame_len);
    if (!frame) return -1;

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_IPV4);

    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = be16((uint16_t)(sizeof(ipv4_hdr_t) + l4_len));
    ip->id = be16(++g_net.ip_id);
    ip->frag_off = be16(0x0000);
    ip->ttl = 64;
    ip->proto = proto;
    ip->src = be32(g_net.ip_be);
    ip->dst = be32(dst_ip_be);
    {
        uint16_t c = ip_checksum16(ip, sizeof(*ip));
        uint8_t *cp = (uint8_t *)&ip->csum;
        cp[0] = (uint8_t)(c >> 8);
        cp[1] = (uint8_t)(c & 0xFF);
    }

    memcpy(frame + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t), l4, l4_len);
    int r = e1000_send_frame(frame, frame_len);
    e1000_poll();
    e1000_poll();
    kfree(frame);
    return (r < 0) ? -1 : 0;
}

static int net_resolve_next_hop_mac(uint32_t dst_ip_be, uint8_t out_mac[6]) {
    if (!out_mac) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    if (nh == g_net.gw_be && g_net.gw_mac_valid) {
        memcpy(out_mac, g_net.gw_mac, 6);
        return 0;
    }
    if (net_resolve_mac(nh, out_mac, 15000) != 0) return -1;
    if (nh == g_net.gw_be) {
        memcpy(g_net.gw_mac, out_mac, 6);
        g_net.gw_mac_valid = 1;
    }
    return 0;
}

static int net_send_udp_datagram(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len > 1472) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    uint8_t dst_mac[6];
    if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) return -1;
    size_t l4_len = sizeof(udp_hdr_t) + payload_len;
    uint8_t *pkt = (uint8_t *)kmalloc(l4_len);
    if (!pkt) return -1;
    udp_hdr_t *uh = (udp_hdr_t *)pkt;
    uh->src_port = be16(src_port);
    uh->dst_port = be16(dst_port);
    uh->len = be16((uint16_t)l4_len);
    uh->csum = 0; /* checksum optional for IPv4 */
    if (payload_len > 0) memcpy(pkt + sizeof(udp_hdr_t), payload, payload_len);
    int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_UDP_LOCAL, pkt, l4_len);
    kfree(pkt);
    return r;
}

static uint32_t g_net_ephemeral_port_seq;

/* Linux-style dynamic ports (32768–65535). Per-tid reuse broke resolver: parallel A/AAAA
 * UDP sockets on one thread shared the same local port and stole each other's replies. */
static uint16_t net_alloc_ephemeral_port(void) {
    uint32_t n = __atomic_add_fetch(&g_net_ephemeral_port_seq, 1u, __ATOMIC_RELAXED);
    return (uint16_t)(32768u + (n % 32768u));
}

static int net_recv_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0 || s->local_port == 0) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    /* timeout_ms==0: single attempt (poll / non-blocking). Old code used while(elapsed<0) and ran zero times. */
    do {
        int q = net_rxq_take_udp_datagram(s, out, out_cap, out_src_ip_be, out_src_port);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_sock_frame((const uint8_t *)frame, (size_t)n, s)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, out_src_ip_be, out_src_port);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

/* One-off UDP recv for DNS: filter by local_port and peer (peer_ip_be, peer_port). Returns bytes, 0=timeout, <0=error. */
static int net_recv_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                            uint8_t *out, size_t out_cap, uint32_t timeout_ms) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    do {
        int q = net_rxq_take_udp_raw(local_port, peer_ip_be, peer_port, out, out_cap);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_raw_frame((const uint8_t *)frame, (size_t)n, local_port, peer_ip_be, peer_port)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, NULL, NULL);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

#define NET_UDP_BLOCK_MAX_MS 120000u

/* One blocking recv: keep waiting (slice by slice) instead of returning EAGAIN after ~3s like a non-blocking socket. */
static int net_udp_recv_into_pending(ksock_net_t *s) {
    if (!s || s->rx_has_pending) return 1;
    if (s->local_port == 0) return -1;
    if (s->nonblock) {
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0u,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        return (rn < 0) ? -1 : 0;
    }
    uint64_t deadline = pit_get_time_ms() + (uint64_t)NET_UDP_BLOCK_MAX_MS;
    for (;;) {
        uint32_t slice = 10000u;
        uint64_t now = pit_get_time_ms();
        if (now >= deadline) return 0;
        if (now + slice > deadline) slice = (uint32_t)(deadline - now);
        if (slice < 1u) slice = 1u;
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), slice,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        if (rn < 0) return -1;
    }
}

static uint8_t s_net_pull_buf[NET_RXQ_BUF];

static int net_send_l4_ipv4_cb(void *context, uint32_t dst_ip_be, uint8_t proto,
                               const void *l4, size_t l4_len);

/* During connect: queue only matching TCP; process ARP/ICMP/listen; drop LAN noise.
 * Blind drain_to_rxq flooded RXQ with UDP broadcasts and displaced SYN-ACK. */
static void net_nic_drain_connect_priority(const net_tcp_conn_t *match, int budget) {
    if (!match || !g_net.ready) {
        net_nic_drain_to_rxq(budget);
        return;
    }
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(s_net_pull_buf, sizeof(s_net_pull_buf));
        if (n <= 0)
            break;
        if (net_tcp_match_frame(s_net_pull_buf, (size_t)n, g_net.ip_be, match)) {
            if (net_rxq_push(s_net_pull_buf, (size_t)n) != 0) {
                uint8_t drop[NET_RXQ_BUF];
                (void)net_rxq_pop(drop, sizeof(drop));
                (void)net_rxq_push(s_net_pull_buf, (size_t)n);
            }
            continue;
        }
        (void)net_process_incoming_or_queue(s_net_pull_buf, (size_t)n);
    }
}

static int net_recv_frame_cb(void *context, void *buf, size_t cap) {
    const net_tcp_conn_t *match = (const net_tcp_conn_t *)context;
    if (match && g_net.ready) {
        for (int pass = 0; pass < 2; pass++) {
            int n = net_rxq_take_tcp_frame(match, g_net.ip_be, buf, cap);
            if (n > 0) return n;
            if (g_net_tcp_connect_active)
                net_nic_drain_connect_priority(match, 16);
            else
                net_nic_drain_to_rxq(8);
        }
        for (int nic = 0; nic < 8; nic++) {
            int r = net_nic_pull_frame(s_net_pull_buf, sizeof(s_net_pull_buf));
            if (r <= 0)
                return 0;
            net_tcp_sniff_frame(s_net_pull_buf, (size_t)r, match);
            if (net_tcp_match_frame(s_net_pull_buf, (size_t)r, g_net.ip_be, match)) {
                if ((size_t)r > cap)
                    return -1;
                memcpy(buf, s_net_pull_buf, (size_t)r);
                return r;
            }
            (void)net_process_incoming_or_queue(s_net_pull_buf, (size_t)r);
        }
        return 0;
    }
    return net_recv_frame_any(buf, cap);
}

static uint64_t net_time_ms_cb(void) {
    return pit_get_time_ms();
}

static void net_yield_connect_cb(void *context) {
    /* Keep SYN-ACK path hot: priority drain + yield, no forced 1ms sleep. */
    net_nic_drain_connect_priority((const net_tcp_conn_t *)context, 16);
    thread_sleep(1);
}

static void net_yield_cb(void *context) {
    if (g_net_tcp_connect_active) {
        net_yield_connect_cb(context);
        return;
    }
    net_nic_drain_process_incoming(8);
    net_rxq_drain_process_incoming(8);
    /* A yield-only blocking socket remains RUNNING and creates a busy ring of
     * httpd children. Sleep makes the wait scheduler-visible and preemptible. */
    thread_sleep(1);
}

static void net_tcp_return_frame_cb(const void *frame, size_t n) {
    if (!frame || n == 0) return;
    if (net_rxq_push((const uint8_t *)frame, n) != 0) {
        uint8_t drop[NET_RXQ_BUF];
        (void)net_rxq_pop(drop, sizeof(drop));
        (void)net_rxq_push((const uint8_t *)frame, n);
    }
}

static void net_make_tcp_ops(net_tcp_ops_t *ops, net_tcp_conn_t *match) {
    if (!ops) return;
    memset(ops, 0, sizeof(*ops));
    ops->context = match;
    ops->local_ip_be = g_net.ip_be;
    ops->send_l4 = net_send_l4_ipv4_cb;
    ops->recv_frame = net_recv_frame_cb;
    ops->time_ms = net_time_ms_cb;
    ops->yield = net_yield_cb;
    ops->return_frame = net_tcp_return_frame_cb;
}

static void ksock_hold(ksock_net_t *s) {
    if (!s) return;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    if (s->kref > 0)
        s->kref++;
    release_irqrestore(&g_ksock_registry_lock, flags);
}

static void ksock_drop(ksock_net_t *s) {
    if (!s) return;
    int destroy = 0;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    if (s->kref > 0)
        s->kref--;
    if (s->kref == 0) {
        int slot = s->registry_slot - 1;
        if (slot >= 0 && slot < KSOCK_REGISTRY_MAX &&
            g_ksock_registry[slot] == s)
            g_ksock_registry[slot] = NULL;
        s->registry_slot = 0;
        destroy = 1;
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    if (!destroy)
        return;
    if (s->sock_domain == AF_PACKET_LOCAL)
        packet_sock_unregister(s);
    if (s->unix_domain_stub || s->unix_conn)
        unix_socket_cleanup(s);
    /* Drop listen flag before free so a dying nginx cannot block the next bind. */
    s->tcp_listening = 0;
    s->local_port = 0;
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge && !s->unix_conn) {
        if (s->tcp.used) {
            net_tcp_ops_t ops;
            net_make_tcp_ops(&ops, &s->tcp);
            (void)net_tcp_close(&s->tcp, &ops, 1000);
        }
        net_rxq_flush();
    }
    kfree(s);
}

static int fork_socket_is_connected_client(const ksock_net_t *s) {
    if (!s) return 0;
    if (s->unix_domain_stub)
        return s->connected && !s->unix_listening;
    if (s->unix_conn && s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL)
        return s->connected && !s->tcp_listening;
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge)
        return s->tcp.used && s->connected && !s->tcp_listening;
    return 0;
}

/* Child gets its own fs_file; both parent and child share one ksock (RX after fork).
 * Also used for listening sockets so accept queues stay on the shared ksock. */
static struct fs_file *fork_child_socket_file(struct fs_file *pf) {
    if (!pf || pf->type != SYSCALL_FTYPE_SOCKET || !pf->driver_private) return NULL;
    ksock_net_t *s = (ksock_net_t *)pf->driver_private;
    struct fs_file *cf = (struct fs_file *)kmalloc(sizeof(*cf));
    char *cp = (char *)kmalloc(24);
    if (!cf || !cp) {
        if (cf) kfree(cf);
        if (cp) kfree(cp);
        return NULL;
    }
    memset(cf, 0, sizeof(*cf));
    if (s->unix_domain_stub)
        snprintf(cp, 24, "socket:[unix]");
    else
        snprintf(cp, 24, "socket:[tcp]");
    cf->path = cp;
    cf->type = pf->type;
    cf->fs_private = pf->fs_private;
    cf->driver_private = s;
    cf->refcount = 1;
    ksock_hold(s);
    return cf;
}

static int fork_socket_should_share_ksock(const ksock_net_t *s) {
    if (!s) return 0;
    if (fork_socket_is_connected_client(s)) return 1;
    /* Listen sockets: share ksock (accept queue) across master/worker. */
    if (s->tcp_listening) return 1;
    if (s->unix_domain_stub && s->unix_listening) return 1;
    return 0;
}

static void fork_inherit_fd_table(thread_t *child, thread_t *parent) {
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        struct fs_file *pf = parent->fds[i];
        child->fds[i] = NULL;
        if (!pf) continue;
        if (pf->type == SYSCALL_FTYPE_SOCKET &&
            fork_socket_should_share_ksock((ksock_net_t *)pf->driver_private)) {
            struct fs_file *cf = fork_child_socket_file(pf);
            if (cf) {
                child->fds[i] = cf;
                continue;
            }
        }
        child->fds[i] = pf;
        if (pf->refcount <= 0) pf->refcount = 1;
        else pf->refcount++;
    }
}

/* Final unref: close TCP/unix and free driver_private (also used from SYS_exit via fs_file_free). */
void net_fs_file_destroy(struct fs_file *f) {
    if (!f) return;
    if (f->type != SYSCALL_FTYPE_SOCKET) return;
    ksock_net_t *s = (ksock_net_t *)f->driver_private;
    f->driver_private = NULL;
    ksock_drop(s);
    if (f->path) {
        kfree((void *)f->path);
        f->path = NULL;
    }
    kfree(f);
}

static ksock_net_t *net_tcp_find_listener(uint16_t port) {
    if (port == 0) return NULL;
    ksock_net_t *result = NULL;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    for (int i = 0; i < KSOCK_REGISTRY_MAX; ++i) {
        ksock_net_t *s = g_ksock_registry[i];
        if (!s || s->kref <= 0 || s->unix_domain_stub) continue;
        if (s->type_base != SOCK_STREAM_LOCAL ||
            s->protocol != IPPROTO_TCP_LOCAL) continue;
        if (!s->tcp_listening || s->local_port != port) continue;
        result = s;
        break;
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    return result;
}

/* Any TCP socket that already claimed this local port (bind, not yet listen). */
static ksock_net_t *net_tcp_find_bound_port(uint16_t port) {
    if (port == 0) return NULL;
    ksock_net_t *result = NULL;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    for (int i = 0; i < KSOCK_REGISTRY_MAX; ++i) {
        ksock_net_t *s = g_ksock_registry[i];
        if (!s || s->kref <= 0 || s->unix_domain_stub) continue;
        if (s->type_base != SOCK_STREAM_LOCAL ||
            s->protocol != IPPROTO_TCP_LOCAL) continue;
        if (s->local_port != port) continue;
        result = s;
        break;
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    return result;
}

/* TCP connect() to 127.0.0.0/8: software loopback via unix_stream_conn (no NIC). */
static int lo_tcp_stream_connect(ksock_net_t *client, uint32_t dst_ip_be, uint16_t dport, thread_t *t) {
    if (!client) return EINVAL;
    if (client->connected && client->unix_conn) return EISCONN;
    ksock_net_t *listener = net_tcp_find_listener(dport);
    if (!listener || !listener->tcp_listening) return ECONNREFUSED;

    unix_stream_conn_t *conn = (unix_stream_conn_t *)kmalloc(sizeof(*conn));
    ksock_net_t *srv = (ksock_net_t *)kmalloc(sizeof(*srv));
    struct fs_file *srv_f = (struct fs_file *)kmalloc(sizeof(*srv_f));
    char *srv_p = (char *)kmalloc(24);
    if (!conn || !srv || !srv_f || !srv_p) {
        if (conn) kfree(conn);
        if (srv) kfree(srv);
        if (srv_f) kfree(srv_f);
        if (srv_p) kfree(srv_p);
        return ENOMEM;
    }
    memset(conn, 0, sizeof(*conn));
    conn->refs = 2;
    memset(srv, 0, sizeof(*srv));
    memset(srv_f, 0, sizeof(*srv_f));
    snprintf(srv_p, 24, "socket:[lo]");
    srv->sock_domain = AF_INET_LOCAL;
    srv->type_base = SOCK_STREAM_LOCAL;
    srv->protocol = IPPROTO_TCP_LOCAL;
    srv->connected = 1;
    srv->unix_conn = conn;
    srv->unix_end = 1;
    srv->local_port = listener->local_port;
    srv->peer_ip_be = dst_ip_be;
    srv->nonblock = listener->nonblock;
    srv->kref = 1;
    srv_f->path = srv_p;
    srv_f->type = SYSCALL_FTYPE_SOCKET;
    srv_f->driver_private = srv;
    srv_f->refcount = 1;
    if (ksock_register(srv) != 0) {
        net_fs_file_destroy(srv_f);
        kfree(conn);
        return ENOMEM;
    }

    if (client->local_port == 0)
        client->local_port = net_alloc_ephemeral_port();
    srv->peer_port = client->local_port;

    if (unix_acceptq_push(listener, srv_f) != 0) {
        net_fs_file_destroy(srv_f);
        kfree(conn);
        return EAGAIN;
    }

    client->connected = 1;
    client->unix_conn = conn;
    client->unix_end = 0;
    client->peer_ip_be = dst_ip_be;
    client->peer_port = dport;
    (void)t;
    return 0;
}

static ksock_net_t *net_tcp_match_established_sock(uint16_t lport, uint32_t rip, uint16_t rport, ksock_net_t *s) {
    if (!s || s->unix_domain_stub || s->dns_tcp_udp_bridge) return NULL;
    if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) return NULL;
    if (!s->tcp.used || !s->tcp.established) return NULL;
    if (s->tcp.peer_fin || s->tcp.peer_rst) return NULL;
    if (s->local_port != lport || s->peer_ip_be != rip || s->peer_port != rport) return NULL;
    return s;
}

static ksock_net_t *net_tcp_find_established(uint16_t lport, uint32_t rip, uint16_t rport) {
    ksock_net_t *result = NULL;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    for (int i = 0; i < KSOCK_REGISTRY_MAX; ++i) {
        ksock_net_t *s = g_ksock_registry[i];
        if (!s || s->kref <= 0)
            continue;
        result = net_tcp_match_established_sock(lport, rip, rport, s);
        if (result)
            break;
    }
    release_irqrestore(&g_ksock_registry_lock, flags);
    return result;
}

static void net_tcp_frame_payload(const uint8_t *frame, size_t n, size_t ihl,
    const tcp_hdr_t *th, const uint8_t **payload_out, size_t *payload_len_out) {
    if (payload_out) *payload_out = NULL;
    if (payload_len_out) *payload_len_out = 0;
    if (!frame || !th || !payload_out || !payload_len_out) return;
    size_t doff = (size_t)((th->doff_res >> 4) * 4u);
    if (doff < sizeof(tcp_hdr_t) || (size_t)n < sizeof(eth_hdr_t) + ihl + doff) return;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ip_tot = (size_t)be16(ip->total_len);
    if (ip_tot < ihl + doff) return;
    size_t plen = ip_tot - ihl - doff;
    size_t frame_pay = (size_t)n - (sizeof(eth_hdr_t) + ihl + doff);
    if (plen > frame_pay) plen = frame_pay;
    *payload_out = frame + sizeof(eth_hdr_t) + ihl + doff;
    *payload_len_out = plen;
}

static void net_tcp_stage_peer_mac(net_tcp_conn_t *c, const uint8_t mac[6]) {
    if (!c || !mac) return;
    memcpy(c->peer_mac, mac, 6);
    c->peer_mac_valid = 1;
}

static void net_tcp_push_payload(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    if (!c || !payload || payload_len == 0) return;
    if (seq != c->rcv_nxt) return;
    size_t room = sizeof(c->rx_buf) - c->rx_len;
    size_t cp = payload_len > room ? room : payload_len;
    if (cp == 0) return;
    memcpy(c->rx_buf + c->rx_len, payload, cp);
    c->rx_len += cp;
    c->rcv_nxt += (uint32_t)cp;
}

static struct fs_file *net_tcp_make_accepted_file(ksock_net_t *listener, const net_tcp_conn_t *tcp,
                                                  uint32_t peer_ip_be, uint16_t peer_port,
                                                  const uint8_t peer_mac[6]) {
    ksock_net_t *srv = (ksock_net_t *)kmalloc(sizeof(*srv));
    struct fs_file *srv_f = (struct fs_file *)kmalloc(sizeof(*srv_f));
    char *srv_p = (char *)kmalloc(24);
    if (!srv || !srv_f || !srv_p) {
        if (srv) kfree(srv);
        if (srv_f) kfree(srv_f);
        if (srv_p) kfree(srv_p);
        return NULL;
    }
    memset(srv, 0, sizeof(*srv));
    memset(srv_f, 0, sizeof(*srv_f));
    snprintf(srv_p, 24, "socket:[tcp]");
    srv->sock_domain = AF_INET_LOCAL;
    srv->type_base = SOCK_STREAM_LOCAL;
    srv->protocol = IPPROTO_TCP_LOCAL;
    srv->connected = 1;
    srv->local_port = listener->local_port;
    srv->peer_ip_be = peer_ip_be;
    srv->peer_port = peer_port;
    srv->nonblock = listener->nonblock;
    memcpy(&srv->tcp, tcp, sizeof(*tcp));
    if (peer_mac)
        net_tcp_stage_peer_mac(&srv->tcp, peer_mac);
    srv->kref = 1;
    srv_f->path = srv_p;
    srv_f->type = SYSCALL_FTYPE_SOCKET;
    srv_f->driver_private = srv;
    srv_f->refcount = 1;
    if (ksock_register(srv) != 0) {
        net_fs_file_destroy(srv_f);
        return NULL;
    }
    return srv_f;
}

static int net_tcp_syn_wait_take_slot(tcp_syn_wait_t **out) {
    tcp_syn_wait_t *fresh = (tcp_syn_wait_t *)kmalloc(sizeof(*fresh));
    if (fresh)
        memset(fresh, 0, sizeof(*fresh));

    unsigned long fl = 0;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    for (int i = 0; i < TCP_SYN_WAIT_SLOTS; i++) {
        tcp_syn_wait_t *w = g_tcp_syn_wait[i];
        if (!w && fresh) {
            g_tcp_syn_wait[i] = fresh;
            w = fresh;
            fresh = NULL;
        }
        if (w && !w->active) {
            memset(w, 0, sizeof(*w));
            w->active = 1;
            *out = w;
            release_irqrestore(&g_tcp_syn_wait_lock, fl);
            if (fresh)
                kfree(fresh);
            return 0;
        }
    }
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
    if (fresh)
        kfree(fresh);
    return -1;
}

static tcp_syn_wait_t *net_tcp_syn_wait_find(uint16_t lport, uint32_t rip, uint16_t rport) {
    unsigned long fl = 0;
    tcp_syn_wait_t *found = NULL;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    for (int i = 0; i < TCP_SYN_WAIT_SLOTS; i++) {
        tcp_syn_wait_t *w = g_tcp_syn_wait[i];
        if (!w || !w->active || !w->listener) continue;
        if (w->listener->local_port == lport && w->peer_ip_be == rip && w->peer_port == rport) {
            found = w;
            break;
        }
    }
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
    return found;
}

static void net_tcp_syn_wait_release(tcp_syn_wait_t *w) {
    if (!w) return;
    unsigned long fl = 0;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    memset(w, 0, sizeof(*w));
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
}

static int net_tcp_dispatch_incoming(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 20u)
        return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (be32(ip->dst) != g_net.ip_be) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) return 0;
    const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t sport = be16(th->src_port);
    uint16_t dport = be16(th->dst_port);
    uint32_t seq = be32(th->seq);
    uint32_t ack = be32(th->ack);
    uint8_t flags = th->flags;
    uint32_t rip = be32(ip->src);
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    net_tcp_frame_payload(frame, n, ihl, th, &payload, &payload_len);

    if ((flags & 0x02u) && !(flags & 0x10u)) {
        if (heap_free_bytes() < (2u << 20))
            (void)thread_reap_unwaited_zombies();
        ksock_net_t *listener = net_tcp_find_listener(dport);
        if (!listener) return 0;
        tcp_syn_wait_t *wait = net_tcp_syn_wait_find(dport, rip, sport);
        net_tcp_conn_t *tc = wait ? &wait->tcp : NULL;
        if (!wait) {
            if (net_tcp_syn_wait_take_slot(&wait) != 0) return 0;
            wait->listener = listener;
            wait->peer_ip_be = rip;
            wait->peer_port = sport;
            memcpy(wait->peer_mac, eth->src, 6);
            tc = &wait->tcp;
            tc->dst_ip_be = rip;
            tc->dst_port = sport;
            tc->src_port = dport;
            net_tcp_stage_peer_mac(tc, eth->src);
        }
        {
            extern volatile uint64_t timer_ticks;
            uint32_t now = (uint32_t)timer_ticks;
            if (wait && tc->used && wait->last_synack_tick != 0 &&
                (uint32_t)(now - wait->last_synack_tick) < 8u) {
                return 1;
            }
            if (wait)
                wait->last_synack_tick = now;
        }
        int first_syn = !tc->used;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, tc);
        if (tc->used)
            (void)net_tcp_server_resend_synack(tc, &ops);
        else
            (void)net_tcp_server_reply_syn(tc, &ops, seq);
        if (first_syn) {
            klogprintf("tcp: server syn-ack port=%u from %u.%u.%u.%u:%u\n",
                (unsigned)dport,
                (unsigned)((rip >> 24) & 0xFF), (unsigned)((rip >> 16) & 0xFF),
                (unsigned)((rip >> 8) & 0xFF), (unsigned)(rip & 0xFF), (unsigned)sport);
        }
        {
            uint8_t drain[NET_RXQ_BUF];
            for (int di = 0; di < 4; di++) {
                int dn = net_nic_pull_frame(drain, sizeof(drain));
                if (dn <= 0) break;
                (void)net_process_incoming_or_queue(drain, (size_t)dn);
            }
        }
        return 1;
    }

    if ((flags & 0x10u) && !(flags & 0x02u)) {
        tcp_syn_wait_t *wait = net_tcp_syn_wait_find(dport, rip, sport);
        if (wait && wait->listener) {
            if (net_tcp_server_complete_ack(&wait->tcp, ack) == 0) {
                if (payload_len > 0)
                    net_tcp_push_payload(&wait->tcp, seq, payload, payload_len);
                struct fs_file *af = net_tcp_make_accepted_file(wait->listener, &wait->tcp, rip, sport, wait->peer_mac);
                if (!af) {
                    net_tcp_syn_wait_release(wait);
                    return 1;
                }
                if (unix_acceptq_push(wait->listener, af) != 0) {
                    net_fs_file_destroy(af);
                } else {
                    klogprintf("tcp: server accept port=%u from %u.%u.%u.%u:%u\n",
                        (unsigned)dport,
                        (unsigned)((rip >> 24) & 0xFF), (unsigned)((rip >> 16) & 0xFF),
                        (unsigned)((rip >> 8) & 0xFF), (unsigned)(rip & 0xFF), (unsigned)sport);
                }
                net_tcp_syn_wait_release(wait);
                return 1;
            }
            klogprintf("tcp: server ack mismatch port=%u ack=%u want=%u\n",
                (unsigned)dport, (unsigned)ack, (unsigned)(wait->tcp.syn_isn + 1u));
            return 1;
        }
    }

    ksock_net_t *est = net_tcp_find_established(dport, rip, sport);
    if (est) {
        if (net_rxq_push(frame, n) != 0) {
            uint8_t drop[NET_RXQ_BUF];
            (void)net_rxq_pop(drop, sizeof(drop));
            (void)net_rxq_push(frame, n);
        }
        /* Queue only. Calling service here re-entered recv_frame -> dispatch
         * recursively and multiplied work across every active connection. */
        return 1;
    }
    return 0;
}

static int net_send_l4_ipv4_cb(void *context, uint32_t dst_ip_be, uint8_t proto,
                               const void *l4, size_t l4_len) {
    const net_tcp_conn_t *match = (const net_tcp_conn_t *)context;
    uint8_t dst_mac[6];
    if (match && match->peer_mac_valid) {
        memcpy(dst_mac, match->peer_mac, 6);
    } else if (g_tcp_xmit_mac_valid) {
        memcpy(dst_mac, g_tcp_xmit_mac, 6);
    } else if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) {
        return -1;
    }
    return net_send_eth_ipv4(dst_mac, dst_ip_be, proto, l4, l4_len);
}

static void net_pump_tcp_sock(ksock_net_t *s, int rounds) {
    if (!s || !g_net.ready || !s->tcp.used) return;
    net_tcp_ops_t ops;
    net_make_tcp_ops(&ops, &s->tcp);
    for (int i = 0; i < rounds; i++)
        (void)net_tcp_service(&s->tcp, &ops, 64);
}

static void net_pump_all_tcp(thread_t *cur) {
    (void)cur;
    if (!g_net.ready) return;
    /*
     * This runs inside poll/select syscalls, where ring-3 timer preemption
     * cannot rescue a long pump. Keep one pass bounded and let the caller
     * block or yield before servicing more traffic.
     */
    net_nic_drain_to_rxq(8);
    /*
     * The old implementation scanned MAX_THREADS * THREAD_MAX_FD on every
     * poll() pass and could service the same inherited socket hundreds of
     * times. Snapshot a bounded, refcounted registry slice instead.
     */
    enum { PUMP_BUDGET = 32 };
    static unsigned cursor;
    ksock_net_t *batch[PUMP_BUDGET];
    int count = 0;
    unsigned next = cursor;
    unsigned long flags;
    acquire_irqsave(&g_ksock_registry_lock, &flags);
    for (unsigned seen = 0; seen < KSOCK_REGISTRY_MAX &&
                            count < PUMP_BUDGET; ++seen) {
        unsigned slot = (cursor + seen) % KSOCK_REGISTRY_MAX;
        ksock_net_t *sk = g_ksock_registry[slot];
        next = (slot + 1u) % KSOCK_REGISTRY_MAX;
        if (!sk || sk->kref <= 0)
            continue;
        if (sk->type_base != SOCK_STREAM_LOCAL ||
            sk->protocol != IPPROTO_TCP_LOCAL ||
            sk->dns_tcp_udp_bridge || sk->unix_conn)
            continue;
        sk->kref++;
        batch[count++] = sk;
    }
    cursor = next;
    release_irqrestore(&g_ksock_registry_lock, flags);
    for (int i = 0; i < count; ++i) {
        net_pump_tcp_sock(batch[i], 1);
        ksock_drop(batch[i]);
    }
}

static int net_send_arp_request(uint32_t target_ip_be) {
    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_ARP);

    arp_hdr_t *arp = (arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    arp->htype = be16(1);
    arp->ptype = be16(ETH_TYPE_IPV4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = be16(1);
    memcpy(arp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, arp->spa);
    memset(arp->tha, 0, 6);
    ip_be_to_bytes(target_ip_be, arp->tpa);

    return (e1000_send_frame(frame, sizeof(frame)) < 0) ? -1 : 0;
}

static int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms) {
    if (!out_mac || !ip_be) return -1;
    if (net_arp_cache_lookup(ip_be, out_mac) == 0) return 0;
    if (ip_be == g_net.gw_be && g_net.gw_mac_valid) {
        memcpy(out_mac, g_net.gw_mac, 6);
        return 0;
    }
    if (net_send_arp_request(ip_be) != 0) return -1;
    uint64_t start = pit_get_time_ms();
    uint64_t last_req = start;
    while ((pit_get_time_ms() - start) < (uint64_t)timeout_ms) {
        if (net_arp_cache_lookup(ip_be, out_mac) == 0) return 0;
        uint64_t now = pit_get_time_ms();
        if (now - last_req >= 1000ULL) {
            (void)net_send_arp_request(ip_be);
            last_req = now;
        }
        /* Yield so net_rx can learn the reply into the shared ARP cache. */
        thread_sleep(1);
    }
    return net_arp_cache_lookup(ip_be, out_mac);
}


static int net_stack_init(void) {
    if (g_net.inited) return 0;
    memset(&g_net, 0, sizeof(g_net));
    g_net.inited = 1;
    g_net.ip_id = 1;
    g_net.ready = 0;
    if (e1000_get_mac(g_net.mac) != 0) {
        g_net.inited = 0;
        return -1;
    }
    klogprintf("net: eth0 registered mac=%02x:%02x:%02x:%02x:%02x:%02x state=down\n",
               g_net.mac[0], g_net.mac[1], g_net.mac[2],
               g_net.mac[3], g_net.mac[4], g_net.mac[5]);
    return 0;
}

static int net_set_if_up(int up) {
    if (net_stack_init() != 0)
        return -1;
    if (!up) {
        g_net.if_up = 0;
        g_net.ready = 0;
        g_net.gw_mac_valid = 0;
        net_rxq_flush();
        return 0;
    }
    if (!g_net_rx_thread_started) {
        thread_t *t = thread_create(net_rx_pump_thread, "net_rx");
        if (!t)
            return -1;
        t->nice = 5;
        g_net_rx_thread_started = 1;
    }
    g_net.if_up = 1;
    g_net.ready = g_net.ip_be != 0;
    g_net_trace_budget = AXON_PRODUCTION ? 0 : 128;
    g_net_l2_trace_budget = AXON_PRODUCTION ? 0 : 16;
    klogprintf("net: eth0 state=up link=%s\n",
               e1000_link_is_up() ? "up" : "down");
    return 0;
}

static void net_announce_ipv4(const char *how) {
    klogprintf("net: eth0 %s ip=%u.%u.%u.%u mask=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
               how ? how : "configured",
               (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
               (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
               (unsigned)((g_net.mask_be >> 24) & 0xFF), (unsigned)((g_net.mask_be >> 16) & 0xFF),
               (unsigned)((g_net.mask_be >> 8) & 0xFF), (unsigned)(g_net.mask_be & 0xFF),
               (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
               (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF));
}

static void net_write_resolv_from_dns(uint32_t dns_be) {
#ifdef AUTO_CONFIGURE_DNS
    if (!dns_be) return;
    char line[96];
    int n = snprintf(line, sizeof(line), "nameserver %u.%u.%u.%u\n",
                     (unsigned)((dns_be >> 24) & 0xFFu), (unsigned)((dns_be >> 16) & 0xFFu),
                     (unsigned)((dns_be >> 8) & 0xFFu), (unsigned)(dns_be & 0xFFu));
    if (n <= 0 || (size_t)n >= sizeof(line)) return;
    (void)fs_unlink("/etc/resolv.conf");
    struct fs_file *f = fs_create_file("/etc/resolv.conf");
    if (!f) f = fs_open("/etc/resolv.conf");
    if (!f) return;
    fs_write(f, line, (size_t)n, 0);
    fs_file_free(f);
#endif
    return;
}

static int net_apply_ipv4(uint32_t ip_be, uint32_t mask_be, uint32_t gw_be, uint32_t dns_be, int from_dhcp) {
    if (net_stack_init() != 0) return -1;
    if (!ip_be) {
        g_net.ready = 0;
        g_net.ip_be = 0;
        g_net.gw_mac_valid = 0;
        g_net_from_dhcp = 0;
        return 0;
    }
    g_net.ip_be = ip_be;
    g_net.mask_be = mask_be ? mask_be : 0xFFFFFF00u;
    if (gw_be)
        g_net.gw_be = gw_be;
    if (dns_be)
        g_net.dns_be = dns_be;
    else if (!g_net.dns_be && g_net.gw_be)
        g_net.dns_be = g_net.gw_be;
    g_net.gw_mac_valid = 0;
    g_net.ready = g_net.if_up;
    g_net_from_dhcp = from_dhcp ? 1 : 0;
    if (from_dhcp) {
        g_net_shadow = g_net;
        g_net_shadow_valid = 1;
    } else {
        g_net_shadow_valid = 0;
    }
    net_announce_ipv4(from_dhcp ? "dhcp" : "static");
    net_write_resolv_from_dns(g_net.dns_be ? g_net.dns_be : g_net.gw_be);
    return 0;
}

static int net_run_dhcp(void) {
    if (net_stack_init() != 0) return -1;
    dhcp_lease_t lease;
    int dhcp_ok = 0;
    /* One retry only; never pit_sleep_ms — that busy-spins and freezes UP. */
    g_net_dhcp_busy = 1;
    for (int dhcp_round = 0; dhcp_round < 2 && !dhcp_ok; dhcp_round++) {
        if (dhcp_round > 0) {
            e1000_flush_rx();
            thread_sleep(500);
        }
        if (dhcp_acquire(g_net.mac, &lease) != 0)
            continue;
        dhcp_ok = 1;
    }
    g_net_dhcp_busy = 0;
    if (!dhcp_ok) {
        klogprintf("net: DHCP failed (no fallback; configure with ifconfig/route)\n");
        return -1;
    }
    return net_apply_ipv4(lease.ip_be, lease.mask_be, lease.gw_be,
                          lease.dns_be ? lease.dns_be : lease.gw_be, 1);
}

static int net_ensure_ipv4(void) {
    if (net_stack_init() != 0) return -1;
    return g_net.ready ? 0 : -1;
}

int syscall_net_preinit(void) {
    /* Register eth0 in DOWN state. Userspace controls IFF_UP and addressing. */
    return net_stack_init();
}

void syscall_net_ensure_resolv(void) {
    (void)net_stack_init();
    if (g_net.ready) {
        uint32_t dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
        net_write_resolv_from_dns(dns_be);
    }
}

/* DNS resolver callbacks (ctx unused) */
static int dns_send_udp_cb(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port,
                           const void *data, size_t len, void *ctx) {
    (void)ctx;
    return net_send_udp_datagram(dst_ip_be, src_port, dst_port, (const uint8_t *)data, len) == 0 ? 0 : -1;
}
static int dns_recv_udp_cb(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                           void *out, size_t cap, uint32_t timeout_ms, void *ctx) {
    (void)ctx;
    return net_recv_udp_raw(local_port, peer_ip_be, peer_port, (uint8_t *)out, cap, timeout_ms);
}

uint16_t axonos_dns_alloc_src_port(void) {
    return net_alloc_ephemeral_port();
}

uint64_t axonos_dns_time_ms(void) {
    return pit_get_time_ms();
}

static int kernel_dns_resolve(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!g_net.ready || !dns_ip_be) return -1;
    return net_dns_resolve(hostname, dns_ip_be, dns_send_udp_cb, dns_recv_udp_cb, NULL, out_ip_be);
}

/* Parse "a.b.c.d" to IPv4 network byte order. Returns 0 on success, -1 on invalid. */
static int parse_ipv4_dotted(const char *s, uint32_t *out_ip_be) {
    if (!s || !out_ip_be) return -1;
    uint32_t a = 0, b = 0, c = 0, d = 0;
    int na = 0, nb = 0, nc = 0, nd = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (uint32_t)(*p - '0'); na++; p++; }
    if (na == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { b = b * 10 + (uint32_t)(*p - '0'); nb++; p++; }
    if (nb == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { c = c * 10 + (uint32_t)(*p - '0'); nc++; p++; }
    if (nc == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { d = d * 10 + (uint32_t)(*p - '0'); nd++; p++; }
    if (nd == 0 || *p != '\0') return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *out_ip_be = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

/* Check if string looks like dotted-decimal IP (no hostname chars). */
static int is_dotted_ip(const char *s) {
    if (!s || !*s) return 0;
    size_t i = 0;
    int dots = 0;
    while (s[i]) {
        char c = s[i];
        if (c >= '0' && c <= '9') { i++; continue; }
        if (c == '.') { dots++; i++; continue; }
        return 0;
    }
    return (dots == 3);
}

/* Parse /etc/hosts and lookup hostname. Returns 0 if found, -1 if not. */
static int kernel_hosts_lookup(const char *hostname, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    struct fs_file *f = fs_open("/etc/hosts");
    if (!f) return -1;
    char buf[2048];
    ssize_t n = fs_read(f, buf, sizeof(buf) - 1, 0);
    fs_file_free(f);
    if (n <= 0) return -1;
    buf[(size_t)n] = '\0';
    const char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '#' || !*p) {
            while (*p && *p != '\n') p++;
            continue;
        }
        char ip_str[64];
        size_t ii = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && ii < sizeof(ip_str) - 1)
            ip_str[ii++] = *p++;
        ip_str[ii] = '\0';
        if (ii == 0) continue;
        uint32_t ip_be = 0;
        if (parse_ipv4_dotted(ip_str, &ip_be) != 0) continue;
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != '#' && *p != '\n') {
            size_t hn = 0;
            char hn_buf[256];
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && hn < sizeof(hn_buf) - 1)
                hn_buf[hn++] = *p++;
            hn_buf[hn] = '\0';
            if (hn > 0) {
                size_t hl = 0;
                while (hostname[hl] && hn_buf[hl] && hostname[hl] == hn_buf[hl]) hl++;
                if (hostname[hl] == '\0' && hn_buf[hl] == '\0') {
                    *out_ip_be = ip_be;
                    return 0;
                }
            }
            while (*p == ' ' || *p == '\t') p++;
        }
        while (*p && *p != '\n') p++;
    }
    return -1;
}

/*
 * Full resolver: 1) dotted-decimal IP, 2) /etc/hosts, 3) DNS.
 * Returns 0 on success, -1 on failure.
 */
static int kernel_resolve_full(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    if (is_dotted_ip(hostname) && parse_ipv4_dotted(hostname, out_ip_be) == 0)
        return 0;
    if (kernel_hosts_lookup(hostname, out_ip_be) == 0)
        return 0;
    if (net_ensure_ipv4() != 0) return -1;
    return kernel_dns_resolve(hostname, dns_ip_be, out_ip_be);
}

static void net_ensure_resolv_conf(uint32_t dns_be) {
    (void)dns_be;
    /* no-op: see syscall_net_ensure_resolv() */
}

static int ip_mask_prefix_len(uint32_t mask_be) {
    int n = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask_be & (1u << i)) n++;
        else break;
    }
    return n;
}

static int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq);

static int net_send_icmp_echo(ksock_net_t *s, uint32_t dst_ip_be, const uint8_t *icmp, size_t icmp_len) {
    if (!s || !icmp || icmp_len == 0) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    /* Drain RX before send (limit 64) so old echo replies don't block next recv (second ping timeout). */
    { uint8_t drain[256]; for (int d = 0; d < 64; d++) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; } }
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    uint8_t dst_mac[6];
    if (nh == g_net.gw_be && g_net.gw_mac_valid) memcpy(dst_mac, g_net.gw_mac, 6);
    else {
        uint32_t arp_ms = 3000;
        if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) {
            if (nh == g_net.gw_be) {
                if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) return -1;
            } else
                return -1;
        }
        if (nh == g_net.gw_be) {
            memcpy(g_net.gw_mac, dst_mac, 6);
            g_net.gw_mac_valid = 1;
        }
    }
    s->last_dst_ip_be = dst_ip_be;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* Linux ping commonly uses SOCK_DGRAM + IPPROTO_ICMP:
           userspace passes payload only, kernel builds ICMP header. */
        size_t pkt_len = 8 + icmp_len;
        uint8_t *pkt = (uint8_t *)kmalloc(pkt_len);
        if (!pkt) return -1;
        memset(pkt, 0, pkt_len);
        pkt[0] = 8; /* Echo Request */
        pkt[1] = 0; /* code */
        uint16_t id = (uint16_t)((thread_current() ? thread_current()->tid : 1) & 0xFFFFu);
        uint16_t seq = ++s->next_echo_seq;
        pkt[4] = (uint8_t)(id >> 8); pkt[5] = (uint8_t)id;
        pkt[6] = (uint8_t)(seq >> 8); pkt[7] = (uint8_t)seq;
        memcpy(pkt + 8, icmp, icmp_len);
        uint16_t csum = ip_checksum16(pkt, pkt_len);
        pkt[2] = (uint8_t)(csum >> 8); pkt[3] = (uint8_t)csum;
        s->last_echo_id = id;
        s->last_echo_seq = seq;
        int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, pkt, pkt_len);
        kfree(pkt);
        return r;
    }

    /* SOCK_RAW path: userspace provides full ICMP packet including header. */
    if (icmp_len < 8) return -1;
    s->last_echo_id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    s->last_echo_seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    return net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, icmp, icmp_len);
}

static int net_try_parse_icmp_reply(const uint8_t *frame, size_t n, ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t *out_src_ip_be) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8 || !s || !out) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 0 || icmp[1] != 0) return 0; /* echo reply */
    uint16_t id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    uint16_t seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    if (id != s->last_echo_id || seq != s->last_echo_seq) return 0;
    uint32_t src_ip_be = be32(ip->src);
    {
        uint64_t now_ms = pit_get_time_ms();
        /* Drop immediate duplicates of the same ICMP echo-reply tuple.
           Helps with NIC/drain races where the same frame is observed repeatedly. */
        if (s->last_rx_echo_ms != 0 &&
            s->last_rx_src_ip_be == src_ip_be &&
            s->last_rx_echo_id == id &&
            s->last_rx_echo_seq == seq &&
            (now_ms - s->last_rx_echo_ms) < 1500u) {
            return 0;
        }
        s->last_rx_src_ip_be = src_ip_be;
        s->last_rx_echo_id = id;
        s->last_rx_echo_seq = seq;
        s->last_rx_echo_ms = now_ms;
    }
    size_t copy_len = 0;
    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* For datagram ICMP sockets, return full ICMP message (header+payload).
           Busybox ping expects to parse id/seq from the received buffer. */
        size_t icmp_len = (size_t)tot - ihl;
        if (icmp_len < 8) return 0;
        copy_len = (icmp_len > out_cap) ? out_cap : icmp_len;
        memcpy(out, icmp, copy_len);
    } else {
        /* Raw ICMP sockets expect IPv4 header included. */
        copy_len = (tot > out_cap) ? out_cap : tot;
        memcpy(out, ip, copy_len);
    }
    if (out_src_ip_be) *out_src_ip_be = src_ip_be;
    return (int)copy_len;
}

static int net_recv_icmp_echo_reply(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be) {
    if (!s || !out || out_cap == 0) return -1;
    if (net_ensure_ipv4() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    while ((pit_get_time_ms() - start) < timeout_ms) {
        thread_t *tcur = thread_get_current_user();
        if (!tcur) tcur = thread_current();
        if (tcur && (tcur->pending_signals & (1ULL << (2 - 1)))) { ret = -4; break; } /* SIGINT */
        int n = net_recv_frame_any(frame, NET_FRAME_BUF);
        if (n > 0) {
            int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
            if (got > 0) { ret = got; break; }
        } else {
            int spun = 0;
            for (; spun < 200 && ret <= 0; spun++) {
                n = net_recv_frame_any(frame, NET_FRAME_BUF);
                if (n > 0) {
                    int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
                    if (got > 0) { ret = got; break; }
                    goto next_iter;
                }
            }
            if (spun >= 200) thread_sleep(1);
        }
next_iter:
        if (ret != 0) break;
    }
    kfree(frame);
    return ret;
}

enum {
    PING_TS_UNKNOWN = 0,
    PING_TS_NONE,
    PING_TS_U64_USEC,
    PING_TS_TIMEVAL64,
    PING_TS_TIMESPEC64,
    PING_TS_TIMEVAL32
};

static int net_detect_ping_ts_fmt(const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len < 8) return PING_TS_NONE;
    uint64_t w0 = 0, w1 = 0;
    memcpy(&w0, payload + 0, sizeof(w0));
    if (payload_len >= 16) memcpy(&w1, payload + 8, sizeof(w1));

    /* gettimeofday timeval64: sec near Unix epoch, usec sub-second */
    if (payload_len >= 16 &&
        w0 > 1000000000ULL && w0 < 5000000000ULL &&
        w1 < 1000000ULL) return PING_TS_TIMEVAL64;

    /* clock_gettime timespec64: sec since boot/epoch, nsec sub-second */
    if (payload_len >= 16 &&
        w0 < 0x7FFFFFFFULL &&
        w1 < 1000000000ULL) return PING_TS_TIMESPEC64;

    /* Common "u64 usec" ping payload style. */
    if (w0 > 1000000ULL) return PING_TS_U64_USEC;

    if (payload_len >= 8) {
        uint32_t s32 = 0, us32 = 0;
        memcpy(&s32, payload + 0, sizeof(s32));
        memcpy(&us32, payload + 4, sizeof(us32));
        if (s32 > 1000000000U && s32 < 5000000000U && us32 < 1000000U) return PING_TS_TIMEVAL32;
    }

    return PING_TS_UNKNOWN;
}

/* BusyBox ping stores *(uint32_t*)icmp_data = monotonic_us() (see networking/ping.c). */
static void net_update_ping_ts_payload(uint8_t *payload, size_t payload_len, int fmt) {
    (void)fmt;
    if (!payload || payload_len < 4) return;
    uint32_t us = (uint32_t)(pit_get_time_ms() * 1000ULL);
    memcpy(payload, &us, sizeof(us));
}

static int net_send_icmp_echo_timer_compat(ksock_net_t *s) {
    if (!s || s->last_dst_ip_be == 0 || s->last_req_len == 0) return -1;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        net_update_ping_ts_payload(s->last_req, s->last_req_len, s->last_req_ts_fmt);
        return net_send_icmp_echo(s, s->last_dst_ip_be, s->last_req, s->last_req_len);
    }

    if (s->last_req_len < 8) return -1;
    uint8_t *pkt = s->last_req;
    uint16_t seq = (uint16_t)((pkt[6] << 8) | pkt[7]);
    seq = (uint16_t)(seq + 1u);
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)seq;
    if (s->last_req_len > 8) {
        net_update_ping_ts_payload(pkt + 8, s->last_req_len - 8, s->last_req_ts_fmt);
    }
    pkt[2] = 0;
    pkt[3] = 0;
    {
        uint16_t csum = ip_checksum16(pkt, s->last_req_len);
        pkt[2] = (uint8_t)(csum >> 8);
        pkt[3] = (uint8_t)csum;
    }
    return net_send_icmp_echo(s, s->last_dst_ip_be, pkt, s->last_req_len);
}

/* Authoritative open-file lookup for the task issuing a syscall.
 * Prefer process->fds (shared table) but fall back to the thread slot so a
 * briefly desynced dup()/F_DUPFD path cannot spuriously POLLNVAL. */
static struct fs_file *syscall_fd_get(thread_t *t, int fd) {
    if (!t || fd < 0 || fd >= THREAD_MAX_FD)
        return NULL;
    if (t->process && t->process->fds[fd])
        return t->process->fds[fd];
    return t->fds[fd];
}

static struct fs_file *socket_file_get(thread_t *cur, int fd, ksock_net_t **out_sock) {
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return NULL;
    struct fs_file *f = syscall_fd_get(cur, fd);
    if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) return NULL;
    if (out_sock) *out_sock = (ksock_net_t *)f->driver_private;
    return f;
}

static void net_debug_log_tls443_tx(ksock_net_t *s, const uint8_t *buf, size_t len, const char *path) {
    if (!s || !buf || len == 0) return;
    if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL || s->dns_tcp_udp_bridge)
        return;
    if (s->peer_port != 443u)
        return;
    static int left = 16;
    if (left <= 0)
        return;
    left--;
    qemu_debug_printf("HTTPS-TX[%s]: len=%llu first=%02x %02x %02x %02x %02x %02x %02x %02x tls=%d\n",
        path ? path : "?",
        (unsigned long long)len,
        (unsigned)(len > 0 ? buf[0] : 0),
        (unsigned)(len > 1 ? buf[1] : 0),
        (unsigned)(len > 2 ? buf[2] : 0),
        (unsigned)(len > 3 ? buf[3] : 0),
        (unsigned)(len > 4 ? buf[4] : 0),
        (unsigned)(len > 5 ? buf[5] : 0),
        (unsigned)(len > 6 ? buf[6] : 0),
        (unsigned)(len > 7 ? buf[7] : 0),
        (len >= 3 && buf[0] == 0x16 && buf[1] == 0x03) ? 1 : 0);
}

/* Linux /proc/net/tcp IPv4 hex: byte-reverse of network-order IP (see /proc/net/tcp). */
static uint32_t ip_be_to_proc_net_hex(uint32_t ip_be) {
    return ((ip_be & 0xFFu) << 24) | ((ip_be & 0xFF00u) << 8)
         | ((ip_be >> 8) & 0xFF00u) | ((ip_be >> 24) & 0xFFu);
}

static unsigned procfs_tcp_port_hex(uint16_t port_host) {
    return (unsigned)(((port_host & 0xFFu) << 8) | ((port_host >> 8) & 0xFFu));
}

ssize_t procfs_net_snap_tcp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            unsigned lport_hex = procfs_tcp_port_hex(s->local_port);
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 1000u);
            if (s->tcp_listening && s->local_port != 0) {
                n = snprintf((char *)buf + w, w < size ? size - w : 0,
                    "%4d: %08X:%04X 00000000:0000 0A %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                    sl++, lhx, lport_hex, 0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
                if (n < 0) return (ssize_t)w;
                w += (size_t)n;
                if (w + 256 >= size) return (ssize_t)w;
                continue;
            }
            if (!s->tcp.used) continue;
            uint32_t rhx = ip_be_to_proc_net_hex(s->peer_ip_be);
            unsigned rport_hex = procfs_tcp_port_hex(s->peer_port);
            unsigned st = s->tcp.established ? 1u : 2u;
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, lport_hex, rhx, rport_hex, st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_udp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_DGRAM_LOCAL || s->protocol != IPPROTO_UDP_LOCAL) continue;
            if (s->local_port == 0 && !s->connected) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            uint32_t rhx = s->connected ? ip_be_to_proc_net_hex(s->peer_ip_be) : 0u;
            uint32_t rp = s->connected ? (uint32_t)(s->peer_port & 0xFFFFu) : 0u;
            unsigned st = 7u;
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 50000u);
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, (unsigned)(s->local_port & 0xFFFFu), rhx, rp, st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_tcp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n");
}

ssize_t procfs_net_snap_udp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n");
}

ssize_t procfs_net_snap_raw(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
}

ssize_t procfs_net_snap_raw6(char *buf, size_t size) {
    return procfs_net_snap_raw(buf, size);
}

ssize_t procfs_net_snap_unix(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "Num       RefCount Protocol Flags    Type St Inode Path\n");
}

ssize_t procfs_net_snap_arp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "IP address       HW type     Flags       HW address            Mask     Device\n");
    if (n < 0) return 0;
    w += (size_t)n;
    unsigned long irqf = 0;
    acquire_irqsave(&g_arp_cache_lock, &irqf);
    for (int i = 0; i < ARP_CACHE_SLOTS; i++) {
        if (!g_arp_cache[i].valid) continue;
        uint32_t ip = g_arp_cache[i].ip_be;
        const uint8_t *m = g_arp_cache[i].mac;
        n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                     "%u.%u.%u.%u   0x1         0x2         %02x:%02x:%02x:%02x:%02x:%02x     *        eth0\n",
                     (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
                     (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF),
                     m[0], m[1], m[2], m[3], m[4], m[5]);
        if (n > 0) w += (size_t)n;
        if (w >= size) break;
    }
    release_irqrestore(&g_arp_cache_lock, irqf);
    return (ssize_t)((w > size) ? size : w);
}

ssize_t procfs_net_snap_dev(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "Inter-|   Receive                                                |  Transmit\n"
                     " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
    if (n < 0) return 0;
    w += (size_t)n;
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "  lo: 0        0       0    0    0    0     0          0         0        0       0    0    0    0     0       0\n");
    if (n > 0) w += (size_t)n;
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "eth0: 0        0       0    0    0    0     0          0         0        0       0    0    0    0     0       0\n");
    if (n > 0) w += (size_t)n;
    return (ssize_t)w;
}

ssize_t procfs_net_snap_route(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
    if (n < 0) return 0;
    w += (size_t)n;
    if (!g_net.ready) return (ssize_t)w;
    /* default route via gateway */
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "eth0\t%08X\t%08X\t0003\t0\t0\t0\t%08X\t0\t0\t0\n",
                 0u, ip_be_to_proc_net_hex(g_net.gw_be), ip_be_to_proc_net_hex(g_net.mask_be));
    if (n > 0) w += (size_t)n;
    return (ssize_t)w;
}

ssize_t procfs_net_snap_dhcp(char *buf, size_t size) {
    const char *state;
    const char *source;

    if (!buf || size < 64) return 0;
    if (!g_net.if_up)
        state = "down";
    else if (!g_net.ready)
        state = "unconfigured";
    else
        state = "bound";
    source = !g_net.ready ? "none" : (g_net_from_dhcp ? "dhcp" : "static");

    return (ssize_t)snprintf(
        buf, size,
        "interface=eth0\n"
        "state=%s\n"
        "source=%s\n"
        "address=%u.%u.%u.%u\n"
        "netmask=%u.%u.%u.%u\n"
        "gateway=%u.%u.%u.%u\n"
        "dns=%u.%u.%u.%u\n"
        "control=write renew or release\n",
        state, source,
        (unsigned)((g_net.ip_be >> 24) & 0xff),
        (unsigned)((g_net.ip_be >> 16) & 0xff),
        (unsigned)((g_net.ip_be >> 8) & 0xff),
        (unsigned)(g_net.ip_be & 0xff),
        (unsigned)((g_net.mask_be >> 24) & 0xff),
        (unsigned)((g_net.mask_be >> 16) & 0xff),
        (unsigned)((g_net.mask_be >> 8) & 0xff),
        (unsigned)(g_net.mask_be & 0xff),
        (unsigned)((g_net.gw_be >> 24) & 0xff),
        (unsigned)((g_net.gw_be >> 16) & 0xff),
        (unsigned)((g_net.gw_be >> 8) & 0xff),
        (unsigned)(g_net.gw_be & 0xff),
        (unsigned)((g_net.dns_be >> 24) & 0xff),
        (unsigned)((g_net.dns_be >> 16) & 0xff),
        (unsigned)((g_net.dns_be >> 8) & 0xff),
        (unsigned)(g_net.dns_be & 0xff));
}

ssize_t procfs_net_store_dhcp(const char *buf, size_t size) {
    char command[16];
    size_t len;

    if (!buf || !size) return -1;
    len = size < sizeof(command) - 1 ? size : sizeof(command) - 1;
    memcpy(command, buf, len);
    command[len] = '\0';
    while (len && (command[len - 1] == '\n' ||
                   command[len - 1] == '\r' ||
                   command[len - 1] == ' '))
        command[--len] = '\0';

    if (!strcmp(command, "renew") || !strcmp(command, "start")) {
        if (net_set_if_up(1) != 0 || net_run_dhcp() != 0)
            return -1;
    } else if (!strcmp(command, "release") || !strcmp(command, "stop")) {
        if (net_apply_ipv4(0, 0, 0, 0, 0) != 0)
            return -1;
    } else {
        return -1;
    }
    return (ssize_t)size;
}

typedef struct __attribute__((packed)) {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
} sockaddr_in_k;

typedef struct __attribute__((packed)) {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
    uint32_t sin6_scope_id; /* Linux ABI: sizeof(sockaddr_in6) == 28 */
} sockaddr_in6_k;

static void sockaddr_in6_v4mapped_fill(sockaddr_in6_k *s6, uint32_t ip_be, uint16_t port_host)
{
    memset(s6, 0, sizeof(*s6));
    s6->sin6_family = AF_INET6;
    s6->sin6_port = be16(port_host);
    memset(s6->sin6_addr, 0, 10);
    s6->sin6_addr[10] = 0xff;
    s6->sin6_addr[11] = 0xff;
    {
        uint32_t s_addr = be32(ip_be);
        memcpy(s6->sin6_addr + 12, &s_addr, 4);
    }
}

/* connect/sendto: Linux glibc often passes AF_INET6 (v4-mapped or ::1). Returns 0 or errno. */
static int user_sockaddr_to_ipv4_peer(const void *addr_u, size_t addrlen, sockaddr_in_k *out) {
    if (!out) return EFAULT;
    if (!addr_u || addrlen < 2) return EFAULT;
    if (!user_range_ok(addr_u, addrlen)) return EFAULT;
    uint16_t fam = 0;
    if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return EFAULT;
    if (fam == 1) return ECONNREFUSED;
    if (fam == AF_INET_LOCAL) {
        if (addrlen < sizeof(sockaddr_in_k)) return EINVAL;
        if (copy_from_user_raw(out, addr_u, sizeof(*out)) != 0) return EFAULT;
        /* Trust sa_family at addr_u; glibc padding/quirks can leave sin_family != 2 in the copy. */
        out->sin_family = AF_INET_LOCAL;
        return 0;
    }
    if (fam == AF_INET6) {
        if (addrlen < sizeof(sockaddr_in6_k)) return EINVAL;
        sockaddr_in6_k s6;
        if (copy_from_user_raw(&s6, addr_u, sizeof(s6)) != 0) return EFAULT;
        int v4m = 1;
        for (int i = 0; i < 10; i++) {
            if (s6.sin6_addr[i]) v4m = 0;
        }
        if (s6.sin6_addr[10] != 0xff || s6.sin6_addr[11] != 0xff) v4m = 0;
        /* Some getaddrinfo paths pass IPv4 in the low 32 bits without ::ffff prefix. */
        int v4lo = 1;
        for (int i = 0; i < 12; i++) {
            if (s6.sin6_addr[i]) v4lo = 0;
        }
        memset(out, 0, sizeof(*out));
        out->sin_family = AF_INET_LOCAL;
        out->sin_port = s6.sin6_port;
        if (v4m || v4lo) {
            memcpy(&out->sin_addr, s6.sin6_addr + 12, 4);
            return 0;
        }
        /*
         * No real IPv6 stack. Do not map ::1 → 127.0.0.1: musl AI_ADDRCONFIG
         * probes connect(::1) and treats success as "IPv6 is configured". On
         * kernels without IPv6 that probe must fail with an allowlisted errno
         * (EADDRNOTAVAIL/ENETUNREACH/…) or getaddrinfo returns EAI_SYSTEM and
         * curl fails immediately with "Could not resolve host".
         */
        return EADDRNOTAVAIL;
    }
    /* Same as IPv6: avoid EAFNOSUPPORT so glibc can try other addresses / paths. */
    return ENETUNREACH;
}

/* Normalize fs_mkdir internal negative codes to Linux errno. */
static int fs_mkdir_errno(int r) {
    if (r == -4 || r == -17) return EEXIST;
    if (r == -2) return ENOENT;
    if (r == -3) return ENOTDIR;
    if (r == -5) return ENOMEM;
    return EIO;
}

typedef struct __attribute__((packed)) {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
} sockaddr_nl_k;

typedef struct __attribute__((packed)) {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
} nlmsghdr_k;

typedef struct __attribute__((packed)) {
    uint8_t rtgen_family;
} rtgenmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifi_family;
    uint8_t  __ifi_pad;
    uint16_t ifi_type;
    int32_t  ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
} ifinfomsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifa_family;
    uint8_t  ifa_prefixlen;
    uint8_t  ifa_flags;
    uint8_t  ifa_scope;
    uint32_t ifa_index;
} ifaddrmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
} rtmsg_k;

typedef struct __attribute__((packed)) {
    uint16_t rta_len;
    uint16_t rta_type;
} rtattr_k;

static inline size_t nl_align4(size_t n) { return (n + 3u) & ~3u; }

static int nl_append_blob(uint8_t *buf, size_t cap, size_t *off, const void *data, size_t len) {
    if (!buf || !off || !data) return -1;
    if (*off + len > cap) return -1;
    memcpy(buf + *off, data, len);
    *off += len;
    return 0;
}

static int nl_append_attr_u32(uint8_t *buf, size_t cap, size_t *off, uint16_t type, uint32_t v) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + sizeof(uint32_t));
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (nl_append_blob(buf, cap, off, &v, sizeof(v)) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_append_attr_blob(uint8_t *buf, size_t cap, size_t *off, uint16_t type, const void *data, size_t data_len) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + data_len);
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (data_len && nl_append_blob(buf, cap, off, data, data_len) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_msg_begin(uint8_t *buf, size_t cap, size_t *off, size_t *msg_start, uint16_t type, uint16_t flags, uint32_t seq, uint32_t pid) {
    if (!buf || !off || !msg_start) return -1;
    *msg_start = *off;
    nlmsghdr_k h;
    memset(&h, 0, sizeof(h));
    h.nlmsg_type = type;
    h.nlmsg_flags = flags;
    h.nlmsg_seq = seq;
    h.nlmsg_pid = pid;
    return nl_append_blob(buf, cap, off, &h, sizeof(h));
}

static int nl_msg_end(uint8_t *buf, size_t cap, size_t *off, size_t msg_start) {
    if (!buf || !off || msg_start > *off || msg_start + sizeof(nlmsghdr_k) > cap) return -1;
    size_t mlen = *off - msg_start;
    ((nlmsghdr_k *)(buf + msg_start))->nlmsg_len = (uint32_t)mlen;
    size_t need = nl_align4(mlen);
    while ((*off - msg_start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq) {
    if (!s) return -1;
    if (net_stack_init() != 0) return -1;
    enum {
        NLMSG_DONE_LOCAL = 3,
        NLM_F_MULTI_LOCAL = 0x2,
        RTM_NEWLINK_LOCAL = 16, RTM_GETLINK_LOCAL = 18,
        RTM_NEWADDR_LOCAL = 20, RTM_GETADDR_LOCAL = 22,
        RTM_NEWROUTE_LOCAL = 24, RTM_GETROUTE_LOCAL = 26,
        IFLA_ADDRESS_LOCAL = 1, IFLA_BROADCAST_LOCAL = 2, IFLA_IFNAME_LOCAL = 3, IFLA_MTU_LOCAL = 4,
        IFLA_LINK_LOCAL = 5, IFLA_QDISC_LOCAL = 6, IFLA_STATS_LOCAL = 7, IFLA_TXQLEN_LOCAL = 13,
        IFLA_OPERSTATE_LOCAL = 16, IFLA_LINKMODE_LOCAL = 17, IFLA_GROUP_LOCAL = 27,
        IFA_ADDRESS_LOCAL = 1, IFA_LOCAL_LOCAL = 2, IFA_LABEL_LOCAL = 3, IFA_FLAGS_LOCAL = 8,
        RTA_DST_LOCAL = 1, RTA_OIF_LOCAL = 4, RTA_GATEWAY_LOCAL = 5, RTA_PREFSRC_LOCAL = 7,
        /* Interface flags */
        IFF_UP_LOCAL = 0x1, IFF_BROADCAST_LOCAL = 0x2, IFF_LOOPBACK_LOCAL = 0x8,
        IFF_RUNNING_LOCAL = 0x40, IFF_NOARP_LOCAL = 0x80, IFF_LOWER_UP_LOCAL = 0x10000,
        IFF_MULTICAST_LOCAL = 0x1000
    };
    size_t off = 0;
    uint16_t msg_type = 0;
    if (req_type == RTM_GETLINK_LOCAL) msg_type = RTM_NEWLINK_LOCAL;
    else if (req_type == RTM_GETADDR_LOCAL) msg_type = RTM_NEWADDR_LOCAL;
    else if (req_type == RTM_GETROUTE_LOCAL) msg_type = RTM_NEWROUTE_LOCAL;
    else return -1;

    if (req_type == RTM_GETLINK_LOCAL) {
        /* Interface 1: lo (loopback) */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifinfomsg_k ifi;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 772; /* ARPHRD_LOOPBACK */
        ifi.ifi_index = 1;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_LOOPBACK_LOCAL | IFF_RUNNING_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "lo", 3) != 0) return -1;
        { uint32_t mtu = 65536; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 0; /* IF_OPER_UNKNOWN */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "noqueue", 8) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Interface 2: eth0 */
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 1; /* ARPHRD_ETHER */
        ifi.ifi_index = 2;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_BROADCAST_LOCAL | IFF_RUNNING_LOCAL | IFF_MULTICAST_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "eth0", 5) != 0) return -1;
        { uint32_t mtu = 1500; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 6; /* IF_OPER_UP */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_ADDRESS_LOCAL, g_net.mac, 6) != 0) return -1;
        { uint8_t brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_BROADCAST_LOCAL, brd, 6) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "fq_codel", 9) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    } else if (req_type == RTM_GETADDR_LOCAL) {
        /* Address for lo: 127.0.0.1/8 */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifaddrmsg_k ifa;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = 8;
        ifa.ifa_scope = 254; /* RT_SCOPE_HOST */
        ifa.ifa_index = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = 0x0100007Fu; /* 127.0.0.1 in little-endian for network order */
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "lo", 3) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Address for eth0 — only if configured (Linux: no addr until set). */
        if (g_net.ready && g_net.ip_be) {
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        ifa.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */
        ifa.ifa_index = 2;
        ifa.ifa_flags = 0x80; /* IFA_F_PERMANENT */
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = be32(g_net.ip_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        { uint32_t brd = be32((g_net.ip_be & g_net.mask_be) | ~g_net.mask_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, 4 /* IFA_BROADCAST */, &brd, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "eth0", 5) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
        }
    } else if (!g_net.ready || !g_net.ip_be) {
        /* No routes until IPv4 is configured. */
    } else {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        rtmsg_k rm;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_table = 254;
        rm.rtm_protocol = 3;
        rm.rtm_scope = 0;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t gw = be32(g_net.gw_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_GATEWAY_LOCAL, &gw, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_dst_len = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        rm.rtm_table = 254;
        rm.rtm_protocol = 2;
        rm.rtm_scope = 253;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t dst = be32(g_net.ip_be & (g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u));
          uint32_t src = be32(g_net.ip_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_DST_LOCAL, &dst, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_PREFSRC_LOCAL, &src, 4) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }

    {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, NLMSG_DONE_LOCAL, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }
    s->nl_rx_len = off;
    s->nl_rx_off = 0;
    return 0;
}

static int netlink_build_ack(ksock_net_t *s, const nlmsghdr_k *request,
                             int error) {
    struct {
        nlmsghdr_k header;
        int32_t error;
        nlmsghdr_k request;
    } reply;

    if (!s || !request) return -1;
    memset(&reply, 0, sizeof(reply));
    reply.header.nlmsg_len = sizeof(reply);
    reply.header.nlmsg_type = 2;
    reply.header.nlmsg_seq = request->nlmsg_seq;
    reply.header.nlmsg_pid = s->nl_pid;
    reply.error = error > 0 ? -error : error;
    reply.request = *request;
    memcpy(s->nl_rx, &reply, sizeof(reply));
    s->nl_rx_len = sizeof(reply);
    s->nl_rx_off = 0;
    return 0;
}

static int netlink_get_attr_u32(const uint8_t *data, size_t len,
                                uint16_t wanted, uint32_t *value) {
    size_t off = 0;

    while (off + sizeof(rtattr_k) <= len) {
        const rtattr_k *attr = (const rtattr_k *)(data + off);
        if (attr->rta_len < sizeof(*attr) || attr->rta_len > len - off)
            return -1;
        if (attr->rta_type == wanted &&
            attr->rta_len >= sizeof(*attr) + sizeof(uint32_t)) {
            memcpy(value, data + off + sizeof(*attr), sizeof(*value));
            return 0;
        }
        off += nl_align4(attr->rta_len);
    }
    return -1;
}

static int netlink_apply_request(ksock_net_t *s, const uint8_t *packet,
                                 size_t len) {
    enum {
        RTM_NEWLINK_LOCAL = 16,
        RTM_NEWADDR_LOCAL = 20,
        RTM_DELADDR_LOCAL = 21,
        RTM_NEWROUTE_LOCAL = 24,
        RTM_DELROUTE_LOCAL = 25,
        RTM_GETLINK_LOCAL = 18,
        RTM_GETADDR_LOCAL = 22,
        RTM_GETROUTE_LOCAL = 26,
        IFA_ADDRESS_LOCAL = 1,
        IFA_LOCAL_LOCAL = 2,
        RTA_OIF_LOCAL = 4,
        RTA_GATEWAY_LOCAL = 5,
    };
    const nlmsghdr_k *h;
    int error = 0;

    if (!s || !packet || len < sizeof(*h)) return -EINVAL;
    h = (const nlmsghdr_k *)packet;
    if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > len) return -EINVAL;

    if (h->nlmsg_type == RTM_GETLINK_LOCAL ||
        h->nlmsg_type == RTM_GETADDR_LOCAL ||
        h->nlmsg_type == RTM_GETROUTE_LOCAL)
        return netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);

    if (h->nlmsg_type == RTM_NEWLINK_LOCAL) {
        if (h->nlmsg_len < sizeof(*h) + sizeof(ifinfomsg_k)) {
            error = EINVAL;
        } else {
            const ifinfomsg_k *ifi =
                (const ifinfomsg_k *)(packet + sizeof(*h));
            if (ifi->ifi_index != 2)
                error = ENODEV;
            else if (net_set_if_up(!!(ifi->ifi_flags & 1u)) != 0)
                error = EIO;
        }
    } else if (h->nlmsg_type == RTM_NEWADDR_LOCAL ||
               h->nlmsg_type == RTM_DELADDR_LOCAL) {
        if (h->nlmsg_len < sizeof(*h) + sizeof(ifaddrmsg_k)) {
            error = EINVAL;
        } else {
            const ifaddrmsg_k *ifa =
                (const ifaddrmsg_k *)(packet + sizeof(*h));
            const uint8_t *attrs = packet + sizeof(*h) + sizeof(*ifa);
            size_t attrs_len = h->nlmsg_len - sizeof(*h) - sizeof(*ifa);
            uint32_t wire_ip = 0;

            if (ifa->ifa_family != AF_INET_LOCAL || ifa->ifa_index != 2) {
                error = EINVAL;
            } else if (h->nlmsg_type == RTM_DELADDR_LOCAL) {
                error = net_apply_ipv4(0, 0, 0, 0, 0) == 0 ? 0 : EIO;
            } else if (ifa->ifa_prefixlen > 32 ||
                       (netlink_get_attr_u32(attrs, attrs_len,
                                             IFA_LOCAL_LOCAL, &wire_ip) != 0 &&
                        netlink_get_attr_u32(attrs, attrs_len,
                                             IFA_ADDRESS_LOCAL, &wire_ip) != 0)) {
                error = EINVAL;
            } else {
                uint32_t mask = ifa->ifa_prefixlen ?
                    (0xffffffffu << (32u - ifa->ifa_prefixlen)) : 0;
                error = net_apply_ipv4(be32(wire_ip), mask, g_net.gw_be,
                                       g_net.dns_be, 0) == 0 ? 0 : EIO;
            }
        }
    } else if (h->nlmsg_type == RTM_NEWROUTE_LOCAL ||
               h->nlmsg_type == RTM_DELROUTE_LOCAL) {
        if (h->nlmsg_len < sizeof(*h) + sizeof(rtmsg_k)) {
            error = EINVAL;
        } else {
            const rtmsg_k *route =
                (const rtmsg_k *)(packet + sizeof(*h));
            const uint8_t *attrs = packet + sizeof(*h) + sizeof(*route);
            size_t attrs_len = h->nlmsg_len - sizeof(*h) - sizeof(*route);
            uint32_t oif = 2;
            uint32_t wire_gw = 0;

            (void)netlink_get_attr_u32(attrs, attrs_len,
                                       RTA_OIF_LOCAL, &oif);
            if (route->rtm_family != AF_INET_LOCAL || oif != 2) {
                error = EINVAL;
            } else if (h->nlmsg_type == RTM_DELROUTE_LOCAL) {
                g_net.gw_be = 0;
                g_net.gw_mac_valid = 0;
            } else if (netlink_get_attr_u32(attrs, attrs_len,
                                            RTA_GATEWAY_LOCAL,
                                            &wire_gw) != 0) {
                error = EINVAL;
            } else {
                g_net.gw_be = be32(wire_gw);
                g_net.gw_mac_valid = 0;
                if (!g_net.dns_be)
                    g_net.dns_be = g_net.gw_be;
            }
        }
    } else {
        error = EINVAL;
    }

    return netlink_build_ack(s, h, error);
}

static uint64_t last_syscall_debug = 0;
static int is_init_user(thread_t *t);
static int pid1_dl_trace_thread(thread_t *t);
static uint64_t g_dl_first_eperm_sc;
static int g_dl_eperm_count;
static thread_t *syscall_resolve_thread(void);

/* glibc ld.so private errno (RTLD_PRIVATE_ERRNO): int rtld_errno in ld-linux .bss.
   open_path() aborts with "Operation not permitted" when here_any && errno==EPERM
   even though openat succeeded and open_verify never runs (read_syscalls=0). */
#define RTLD_ERRNO_OFFSET 0x342a0u

static void init_clear_rtld_errno(thread_t *t) {
    if (!t)
        return;
    uintptr_t base = (uintptr_t)t->user_interp_base;
    if (base < 0x200000ULL)
        return;
    uintptr_t addr = base + RTLD_ERRNO_OFFSET;
    if (addr + 4 > (uintptr_t)MMIO_IDENTITY_LIMIT)
        return;
    int zero = 0;
    int old = 0;
    (void)copy_from_user_raw(&old, (const void *)(uintptr_t)addr, sizeof(old));
    if (copy_to_user_safe((void *)(uintptr_t)addr, &zero, sizeof(zero)) != 0)
        return;
    if (old != 0 && is_init_user(t)) {
        static int rtld_errno_log_left = 12;
        if (rtld_errno_log_left-- > 0)
            kprintf("rtld-errno: cleared stale=%d at 0x%llx (base=0x%llx)\n",
                old, (unsigned long long)addr, (unsigned long long)base);
    }
}

/* Last-line defense: some paths bypass ret_err() but must never return -EPERM
   (Linux errno 1) to ring-3 — glibc ld.so open_path() treats it as fatal. */
static uint64_t syscall_sanitize_user_ret(uint64_t ret) {
    thread_t *t = syscall_resolve_thread();
    if (!t || (t->ring != 3 && !is_init_user(t))) return ret;
    int64_t sr = (int64_t)ret;
    if (sr >= 0) {
        if (is_init_user(t) || pid1_dl_trace_thread(t))
            init_clear_rtld_errno(t);
        /* Zero-extend small positive returns so glibc INTERNAL_SYSCALL_ERROR_P
           does not treat fd=3 with garbage high bits as a syscall error. */
        if (sr <= 0x7FFFFFFFLL && (ret >> 32) != 0)
            ret = (uint64_t)(uint32_t)sr;
        return ret;
    }
    int e = (int)(-sr);
    /* Linux x86_64: syscall error -1 is EPERM (errno 1). glibc ld.so open_path()
       treats errno=EPERM as fatal for the whole library search.
       Keep real EPERM for setsid/setpgid — getty dies if these are forged. */
    int sc = (int)last_syscall_debug;
    int keep_eperm = (sc == SYS_setsid || sc == SYS_setpgid);
    if ((e == EPERM || sr == -1) && !keep_eperm) {
        g_dl_eperm_count++;
        if (!g_dl_first_eperm_sc) g_dl_first_eperm_sc = last_syscall_debug;
        kprintf("user-sanitize EPERM syscall=%llu tid=%llu name=%s ret=0x%llx -> ENOENT\n",
            (unsigned long long)last_syscall_debug,
            (unsigned long long)(t->tid ? t->tid : 1),
            t->name[0] ? t->name : "?",
            (unsigned long long)ret);
        return (uint64_t)(-(int64_t)ENOENT);
    }
    return ret;
}
/* P0 execve reliability counters: transient layout race recovery. */
static uint64_t g_execve_retry_eagain = 0;
static uint64_t g_execve_retry_ok = 0;
static uint64_t g_execve_retry_fail = 0;
static uint64_t g_execve_retry_last_log_ms = 0;
static inline int is_watch_proc(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    const char *nm = t->name;
    /* BusyBox is a multicall binary: applets often run with name "busybox". */
    return (strstr(nm, "busybox") || strstr(nm, "openrc") || strstr(nm, "/sbin/openrc") ||
            strstr(nm, "sh") || strstr(nm, "wget") || strstr(nm, "uget") ||
            strstr(nm, "adduser") || strstr(nm, "addgroup")) ? 1 : 0;
}

static inline int path_is_passwdish(const char *p) {
    if (!p) return 0;
    /* BusyBox update_passwd uses suffixes: /etc/passwd+, /etc/passwd- */
    return (strncmp(p, "/etc/passwd", 11) == 0) ||
           (strncmp(p, "/etc/group", 10) == 0) ||
           (strncmp(p, "/etc/shadow", 11) == 0) ||
           (strncmp(p, "/etc/gshadow", 12) == 0);
}

/* Syscall trace for debugging multicall userland (BusyBox). */
static int g_syscall_trace_on = AXON_PRODUCTION ? 0 : 1;
static int g_syscall_trace_budget = AXON_PRODUCTION ? 0 : 4000;
static inline int syscall_trace_pick(uint64_t num) {
    /* Keep this tight: only the syscalls that explain "hang" or "can't create user". */
    switch ((int)num) {
        case 0:  /* read */
        case 1:  /* write */
        case 3:  /* close */
        case 9:  /* mmap */
        case 10: /* mprotect */
        case 11: /* munmap */
        case 12: /* brk */
        case 16: /* ioctl */
        case 23: /* select */
        case 35: /* nanosleep */
        case 42: /* connect */
        case 57: /* fork */
        case 59: /* execve */
        case 60: /* exit */
        case 61: /* wait4 */
        case 72: /* fcntl */
        case 78: /* getdents */
        case 79: /* getcwd */
        case 87: /* unlink */
        case 89: /* readlink */
        case 97: /* getrlimit */
        case 158:/* arch_prctl */
        case 202:/* futex */
        case 231:/* exit_group */
        case 217:/* getdents64 */
        case 257:/* openat */
        case 258:/* mkdirat */
        case 259:/* mknodat */
        case 260:/* fchownat */
        case 262:/* newfstatat */
        case 263:/* unlinkat */
        case 264:/* renameat */
        case 265:/* linkat */
        case 268:/* fchmodat */
        case 271:/* ppoll */
        case 7:  /* poll */
            return 1;
        default:
            return 0;
    }
}
static const char *thread_fd_path(thread_t *cur, int fd);

static inline uint64_t ret_err(int e) {
    /* glibc open_path() aborts library search when errno is EPERM (not ENOENT/
       EACCES), reporting "cannot open shared object file: Operation not permitted"
       even after a successful openat. Never surface EPERM to ring-3 tasks —
       except for session/job-control syscalls where EPERM is meaningful (getty
       setsid / setpgid). */
    thread_t *t = syscall_resolve_thread();
    int sc = (int)last_syscall_debug;
    int keep_eperm = (sc == SYS_setsid || sc == SYS_setpgid || sc == SYS_kill);
    if (e == EPERM && !keep_eperm && t && (t->ring == 3 || is_init_user(t))) {
        g_dl_eperm_count++;
        if (!g_dl_first_eperm_sc) g_dl_first_eperm_sc = last_syscall_debug;
        kprintf("user-remap EPERM syscall=%llu tid=%llu name=%s -> ENOENT\n",
            (unsigned long long)last_syscall_debug,
            (unsigned long long)(t->tid ? t->tid : 1),
            t->name[0] ? t->name : "?");
        e = ENOENT;
    }
    if (t && t->name[0]) {
        const char *nm = t->name;
        int watch = 0;
        if (strstr(nm, "wget")) watch = 1;
        else if (strstr(nm, "uget")) watch = 1;
        else if (strstr(nm, "addgroup")) watch = 1;
        else if (strstr(nm, "adduser")) watch = 1;
        else if (strstr(nm, "openrc")) watch = 1;
        else if (strstr(nm, "ld-linux") || strstr(nm, "ld.so")) watch = 1;
        else if (t->tid <= 1) watch = 1;
        if (watch) {
            /* Rate-limit repetitive error logs (e.g. connect/read retries in wget).
               Excessive kprintf in hot paths can itself destabilize networking timings. */
            static uint64_t err_last_ms = 0;
            static uint64_t err_last_sys = ~0ULL;
            static int err_last_no = 0;
            static int err_repeat = 0;
            uint64_t now_ms = pit_get_time_ms();
            int suppress = 0;
            if (last_syscall_debug == err_last_sys && e == err_last_no && (now_ms - err_last_ms) < 2500ULL) {
                err_repeat++;
                if (err_repeat > 8) suppress = 1;
            } else {
                if (err_repeat > 8) {
                    qemu_debug_printf("SYSCALL-ERR: syscall=%llu errno=%d pid=%s (suppressed %d repeats)\n",
                        (unsigned long long)err_last_sys, err_last_no, nm, err_repeat - 8);
                }
                err_last_sys = last_syscall_debug;
                err_last_no = e;
                err_repeat = 0;
                err_last_ms = now_ms;
            }
            /* close(3)+EBADF is often harmless in libc fallback paths. */
            if (last_syscall_debug == 3u && e == EBADF)
                return (uint64_t)(-(int64_t)e);
            /* read(2)+EAGAIN on wget sockets is expected during polling; don't spam logs. */
            if (last_syscall_debug == SYS_read && e == EAGAIN)
                return (uint64_t)(-(int64_t)e);
            if (!suppress) {
                qemu_debug_printf("SYSCALL-ERR: syscall=%llu errno=%d pid=%s\n",
                    (unsigned long long)last_syscall_debug, e, nm);
                qemu_debug_printf("SYSCALL-ERR: syscall=%llu err=%d tid=%llu name=%s brk=0x%llx mmap_next=0x%llx\n",
                    (unsigned long long)last_syscall_debug,
                    e,
                    (unsigned long long)(t->tid ? t->tid : 1),
                    nm,
                    (unsigned long long)(uint64_t)t->user_brk_cur,
                    (unsigned long long)(uint64_t)t->user_mmap_next);
                if (e == EPERM) {
                    kprintf("dl-trace EPERM syscall=%llu tid=%llu name=%s\n",
                        (unsigned long long)last_syscall_debug,
                        (unsigned long long)(t->tid ? t->tid : 1), nm);
                }
            } else if (e == EPERM && (is_init_user(t) || strstr(nm, "openrc") ||
                       strstr(nm, "ld-linux") || strstr(nm, "ld.so"))) {
                kprintf("dl-trace EPERM syscall=%llu tid=%llu name=%s (suppressed=%d)\n",
                    (unsigned long long)last_syscall_debug,
                    (unsigned long long)(t->tid ? t->tid : 1), nm, err_repeat);
            }
        }
    }
    if (e == ENOMEM) {
        oom_serial_notify(last_syscall_debug, (t && t->name[0]) ? t->name : 0);
        qemu_debug_printf("ENOMEM: syscall=%llu name=%s heap_used=%llu heap_total=%llu\n",
            (unsigned long long)last_syscall_debug,
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes());
        qemu_debug_printf("ENOMEM: syscall=%llu tid=%llu name=%s brk=0x%llx mmap_next=0x%llx heap_used=%llu heap_total=%llu heap_peak=%llu\n",
            (unsigned long long)last_syscall_debug,
            (unsigned long long)(t ? (t->tid ? t->tid : 1) : 0),
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)(t ? (uint64_t)t->user_brk_cur : 0),
            (unsigned long long)(t ? (uint64_t)t->user_mmap_next : 0),
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes(),
            (unsigned long long)heap_peak_bytes());
    }
    return (uint64_t)(-(int64_t)e);
}

/* fs_read historically returned -1 for generic VFS failures; map to EIO, not EPERM. */
static inline uint64_t ret_read_err(ssize_t rr) {
    if (rr >= 0) return (uint64_t)rr;
    if (rr == -1) return ret_err(EIO);
    return ret_err((int)-rr);
}

/* minimal signal numbers used */
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef ESPIPE
#define ESPIPE 29
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef SIGABRT
#define SIGABRT 6
#endif
#ifndef SIGSEGV
#define SIGSEGV 11
#endif
#ifndef SIGILL
#define SIGILL 4
#endif
#ifndef SIGBUS
#define SIGBUS 7
#endif
#ifndef SIGFPE
#define SIGFPE 8
#endif

static void thread_set_pending_signal(thread_t *t, int signum) {
    if (!t || signum <= 0 || signum > 63) return;
    t->pending_signals |= (1ULL << (signum - 1));
    /* Wake waiters in rt_sigtimedwait / rt_sigsuspend / wait4. thread_unblock
     * already accepts THREAD_SLEEPING, but we must call it for both states:
     * sleeping poll loops otherwise wait out their full quantum. */
    if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING)
        thread_unblock((int)(t->tid ? t->tid : 1));
}

static int thread_fetch_pending_signal(thread_t *t, uint64_t mask) {
    if (!t) return 0;
    if (mask == 0) mask = ~0ULL;
    /* Always allow SIGCHLD to wake waits to avoid init deadlocks. */
    mask |= (1ULL << (SIGCHLD - 1));
    for (int sig = 1; sig <= 63; sig++) {
        uint64_t bit = 1ULL << (sig - 1);
        if ((mask & bit) && (t->pending_signals & bit)) {
            t->pending_signals &= ~bit;
            return sig;
        }
    }
    return 0;
}

static int is_init_user(thread_t *t) {
    int init_tid = thread_get_init_user_tid();
    return t && init_tid >= 0 && (int)t->tid == init_tid;
}

static int pid1_dl_trace_thread(thread_t *t) {
    if (AXON_PRODUCTION)
        return 0;
    if (is_init_user(t))
        return 1;
    if (!t || !t->name[0])
        return 0;
    return (strstr(t->name, "openrc") != NULL ||
            strstr(t->name, "ld-linux") != NULL ||
            strstr(t->name, "ld.so") != NULL);
}

static int pid1_dl_trace_path(const char *path) {
    if (!path)
        return 0;
    return (strstr(path, "libeinfo") != NULL ||
            strstr(path, "ld-linux") != NULL ||
            strstr(path, "ld.so") != NULL ||
            strstr(path, "libc.so") != NULL ||
            strstr(path, "librc") != NULL ||
            strstr(path, "libopenrc") != NULL ||
            strstr(path, "libtinfo") != NULL ||
            strstr(path, "openrc-init") != NULL);
}

typedef struct {
    uint64_t num;
    uint64_t a1;
    uint64_t a2;
    int64_t ret;
} dl_tail_ent_t;

static const char *dl_tail_scname(uint64_t n);

/* Full boot syscall log for PID1/ld.so (survives long ENOENT search loops). */
#define DL_BOOT_CAP 512
static dl_tail_ent_t g_dl_boot[DL_BOOT_CAP];
static int g_dl_boot_pos;
static int g_dl_post_open_left;
static char g_dl_fd_path[64][128];
static int g_dl_read_seen;

static void dl_boot_push(uint64_t num, uint64_t a1, uint64_t a2, int64_t ret) {
    dl_tail_ent_t *e = &g_dl_boot[g_dl_boot_pos % DL_BOOT_CAP];
    e->num = num;
    e->a1 = a1;
    e->a2 = a2;
    e->ret = ret;
    g_dl_boot_pos++;
}

static void dl_fd_note(int fd, const char *path) {
    if (fd < 0 || fd >= 64 || !path) return;
    strncpy(g_dl_fd_path[fd], path, sizeof(g_dl_fd_path[fd]) - 1);
    g_dl_fd_path[fd][sizeof(g_dl_fd_path[fd]) - 1] = '\0';
}

static void dl_fd_clear(int fd) {
    if (fd < 0 || fd >= 64) return;
    g_dl_fd_path[fd][0] = '\0';
}

static void boot_io_log(thread_t *cur, const char *tag, int fd, uint64_t extra) {
    if (AXON_PRODUCTION)
        return;
    if (!is_init_user(cur)) return;
    const char *p = thread_fd_path(cur, fd);
    kprintf("boot-io: %s fd=%d path=%s x=0x%llx\n", tag, fd, p ? p : "?", (unsigned long long)extra);
}

static void dl_fd_paths_dump(void) {
    if (AXON_PRODUCTION)
        return;
    kprintf("dl-fd-paths ===\n");
    for (int i = 0; i < 64; i++) {
        if (g_dl_fd_path[i][0])
            kprintf("dl-fd %2d path=%s\n", i, g_dl_fd_path[i]);
    }
    kprintf("dl-fd-paths === end ===\n");
}

/* Ring buffer of recent PID1/ld.so syscalls; dumped on exit_group so a short
   boot log tail still shows what failed after a successful libeinfo openat. */
#define DL_TAIL_CAP 80
static dl_tail_ent_t g_dl_tail[DL_TAIL_CAP];
static int g_dl_tail_pos;
static int g_dl_compact_left;
static int g_dl_libeinfo_fd = -1;

static const char *dl_tail_scname(uint64_t n) {
    switch ((int)n) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "open";
    case 3: return "close";
    case 5: return "fstat";
    case 9: return "mmap";
    case 10: return "mprotect";
    case 16: return "ioctl";
    case 17: return "pread64";
    case 19: return "readv";
    case 20: return "writev";
    case 21: return "access";
    case 109: return "setpgid";
    case 158: return "arch_prctl";
    case 202: return "futex";
    case 231: return "exit_group";
    case 257: return "openat";
    case 262: return "newfstatat";
    case 269: return "faccessat";
    default: return "?";
    }
}

static void dl_tail_push(uint64_t num, uint64_t a1, uint64_t a2, int64_t ret) {
    dl_tail_ent_t *e = &g_dl_tail[g_dl_tail_pos % DL_TAIL_CAP];
    e->num = num;
    e->a1 = a1;
    e->a2 = a2;
    e->ret = ret;
    g_dl_tail_pos++;
}

static void dl_watch_start(void) {
    g_dl_compact_left = 64;
}

static const char *thread_fd_path(thread_t *cur, int fd) {
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD)
        return NULL;
    struct fs_file *f = cur->fds[fd];
    return (f && f->path) ? f->path : NULL;
}

static int pid1_dl_trace_fd(thread_t *cur, int fd) {
    const char *p = thread_fd_path(cur, fd);
    return p && pid1_dl_trace_path(p);
}

static void pid1_dl_log_stat(const char *tag, const char *path) {
    struct stat st;
    char link[256];
    link[0] = '\0';
    if (!path) {
        kprintf("dl-trace %s path=(null)\n", tag ? tag : "?");
        return;
    }
    if (vfs_stat(path, &st) != 0) {
        kprintf("dl-trace %s path=%s stat=ENOENT\n", tag ? tag : "?", path);
        return;
    }
    ssize_t lr = vfs_readlink(path, link, sizeof(link) - 1);
    if (lr >= 0)
        link[lr] = '\0';
    kprintf("dl-trace %s path=%s dev=%llu ino=%llu mode=0%o uid=%u gid=%u size=%lld nlink=%llu link=%s\n",
        tag ? tag : "?", path,
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        (unsigned)(st.st_mode & 0777777), (unsigned)st.st_uid, (unsigned)st.st_gid,
        (long long)st.st_size, (unsigned long long)st.st_nlink,
        link[0] ? link : "(none)");
}

static void pid1_dl_log_fd(thread_t *cur, const char *tag, int fd) {
    const char *path = thread_fd_path(cur, fd);
    if (!path) {
        kprintf("dl-trace %s fd=%d path=(none)\n", tag ? tag : "?", fd);
        return;
    }
    struct fs_file *f = (cur && fd >= 0 && fd < THREAD_MAX_FD) ? cur->fds[fd] : NULL;
    struct stat st;
    if (f && vfs_fstat(f, &st) == 0) {
        kprintf("dl-trace %s fd=%d path=%s dev=%llu ino=%llu mode=0%o size=%lld pos=%lld type=%d\n",
            tag ? tag : "?", fd, path,
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
            (unsigned)(st.st_mode & 0777777), (long long)st.st_size,
            (long long)(int64_t)f->pos, f->type);
    } else {
        kprintf("dl-trace %s fd=%d path=%s fstat_fail\n", tag ? tag : "?", fd, path);
    }
}

/* glibc _dl_get_file_id compares fstat(fd) vs stat(readlink path) dev/ino. */
static void pid1_dl_verify_file_id(thread_t *cur, int fd) {
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD)
        return;
    struct fs_file *f = cur->fds[fd];
    const char *path = (f && f->path) ? f->path : NULL;
    if (!path)
        return;
    struct stat st_fd, st_path, st_lpath;
    if (vfs_fstat(f, &st_fd) != 0) {
        kprintf("dl-trace file_id fd=%d path=%s fstat_fail\n", fd, path);
        return;
    }
    if (vfs_stat(path, &st_path) != 0) {
        kprintf("dl-trace file_id fd=%d path=%s stat_fail dev=%llu ino=%llu\n",
            fd, path, (unsigned long long)st_fd.st_dev, (unsigned long long)st_fd.st_ino);
        return;
    }
    int lstat_ok = (vfs_lstat(path, &st_lpath) == 0);
    if (st_fd.st_dev != st_path.st_dev || st_fd.st_ino != st_path.st_ino) {
        if (lstat_ok) {
            kprintf("dl-trace file_id MISMATCH fd=%d path=%s "
                "fstat dev=%llu ino=%llu stat dev=%llu ino=%llu "
                "lstat dev=%llu ino=%llu\n",
                fd, path,
                (unsigned long long)st_fd.st_dev, (unsigned long long)st_fd.st_ino,
                (unsigned long long)st_path.st_dev, (unsigned long long)st_path.st_ino,
                (unsigned long long)st_lpath.st_dev, (unsigned long long)st_lpath.st_ino);
        } else {
            kprintf("dl-trace file_id MISMATCH fd=%d path=%s "
                "fstat dev=%llu ino=%llu stat dev=%llu ino=%llu lstat_fail\n",
                fd, path,
                (unsigned long long)st_fd.st_dev, (unsigned long long)st_fd.st_ino,
                (unsigned long long)st_path.st_dev, (unsigned long long)st_path.st_ino);
        }
    } else {
        kprintf("dl-trace file_id ok fd=%d path=%s dev=%llu ino=%llu mode=0%o size=%lld\n",
            fd, path,
            (unsigned long long)st_fd.st_dev, (unsigned long long)st_fd.st_ino,
            (unsigned)(st_fd.st_mode & 0777777), (long long)st_fd.st_size);
    }
}
static int has_terminated_child(thread_t *t) {
    if (!t) return 0;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return 1;
        }
    }
    return 0;
}

static thread_t *find_terminated_child(thread_t *t) {
    if (!t) return NULL;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return c;
        }
    }
    return NULL;
}

/* Returns 1 if path contains . or .. components that need normalization. */
static int path_needs_normalize(const char *p) {
    if (!p) return 0;
    if (p[0] == '.' && (p[1] == '\0' || p[1] == '/')) return 1;
    if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
    for (; *p; p++) {
        if (*p == '/' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
        if (*p == '/' && p[1] == '.' && p[2] == '.' && (p[3] == '\0' || p[3] == '/')) return 1;
    }
    return 0;
}

/* Normalize path by resolving . and .. components. Modifies buf in place. */
static void normalize_path(char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    char tmp[512];
    const char *comps[64];
    size_t comp_len[64];
    int n = 0;
    const char *p = buf;
    while (*p && n < (int)(sizeof(comps) / sizeof(comps[0]))) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 0) continue;
        if (len == 1 && start[0] == '.') continue;  /* skip . */
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (n > 0) n--;  /* pop .. */
            continue;
        }
        comps[n] = start;
        comp_len[n] = len;
        n++;
    }
    size_t pos = 0;
    tmp[pos++] = '/';
    for (int i = 0; i < n && pos < sizeof(tmp) - 1; i++) {
        if (i > 0) tmp[pos++] = '/';
        for (size_t j = 0; j < comp_len[i] && pos < sizeof(tmp) - 1; j++)
            tmp[pos++] = comps[i][j];
    }
    tmp[pos] = '\0';
    strncpy(buf, tmp, cap - 1);
    buf[cap - 1] = '\0';
}

static void map_tty_alias_path(char *buf, size_t cap) {
    if (!buf || cap < 10) return;
    if (strncmp(buf, "/tty", 4) == 0 &&
        buf[4] >= '1' && buf[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
        buf[5] == '\0') {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "/dev/tty%c", buf[4]);
        strncpy(buf, tmp, cap - 1);
        buf[cap - 1] = '\0';
    }
}

static void resolve_kernel_path(thread_t *cur, const char *path,
                                char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!path || !path[0]) {
        return;
    }
    const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
    if (path[0] == '/') {
        strncpy(out, path, out_cap);
        out[out_cap - 1] = '\0';
        if (path_needs_normalize(out)) normalize_path(out, out_cap);
        map_tty_alias_path(out, out_cap);
        return;
    }
    /* "." means current directory. */
    if (strcmp(path, ".") == 0) {
        strncpy(out, cwd, out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    /* ".." means parent directory. */
    if (strcmp(path, "..") == 0) {
        if (strcmp(cwd, "/") == 0) {
            strncpy(out, "/", out_cap);
            out[out_cap - 1] = '\0';
        } else {
            const char *slash = strrchr(cwd, '/');
            if (slash && slash > cwd) {
                size_t len = (size_t)(slash - cwd);
                if (len >= out_cap) len = out_cap - 1;
                memcpy(out, cwd, len);
                out[len] = '\0';
            } else {
                strncpy(out, "/", out_cap);
                out[out_cap - 1] = '\0';
            }
        }
        return;
    }
    /* Build full path and normalize (handles ./run, a/./b, a/../b, etc.) */
    if (strcmp(cwd, "/") == 0) {
        snprintf(out, out_cap, "/%s", path);
    } else {
        snprintf(out, out_cap, "%s/%s", cwd, path);
    }
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    map_tty_alias_path(out, out_cap);
}

static void resolve_user_path(thread_t *cur, const char *path_u,
                              char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!path_u || !user_range_ok(path_u, 1))
        return;
    char path_local[4096];
    size_t len = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
    if (len >= sizeof(path_local) - 1 ||
        !user_range_ok(path_u, len + 1) ||
        copy_from_user_raw(path_local, path_u, len + 1) != 0)
        return;
    path_local[len] = '\0';
    resolve_kernel_path(cur, path_local, out, out_cap);
}

/* Resolve path for openat: dirfd base or cwd. Returns 0 on success, negative errno on error. */
static int resolve_user_path_at(thread_t *cur, int dirfd, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return -EFAULT;
    out[0] = '\0';
    const char *path = path_u;
    /* The syscall stack is 64 KiB, so PATH_MAX-sized scratch storage is safe. */
    char path_local[4096];
    if (path_u && user_range_ok(path_u, 1)) {
        size_t L = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
        if (L >= sizeof(path_local) - 1) return -ENAMETOOLONG;
        if (!user_range_ok(path_u, L + 1) || copy_from_user_raw(path_local, path_u, L + 1) != 0) return -EFAULT;
        path_local[L] = '\0';
        path = path_local;
    }
    if (!path || !path[0]) return -ENOENT;
    /* Absolute path: dirfd ignored, use standard resolve */
    if (path[0] == '/') {
        resolve_kernel_path(cur, path, out, out_cap);
        return 0;
    }
    /* AT_FDCWD = -100: use current working directory */
    enum { AT_FDCWD = -100 };
    if (dirfd == AT_FDCWD) {
        resolve_kernel_path(cur, path, out, out_cap);
        return 0;
    }
    /* dirfd: resolve relative to that directory */
    if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return -EBADF;
    struct fs_file *f = cur->fds[dirfd];
    if (!f) return -EBADF;
    if (f->type != FS_TYPE_DIR) return -ENOTDIR;
    const char *base = f->path ? f->path : "/";
    size_t bl = strlen(base);
    int has_trailing = (bl > 1 && base[bl - 1] == '/');
    size_t pl = strlen(path);
    if (has_trailing) {
        snprintf(out, out_cap, "%s%s", base, path);
    } else {
        snprintf(out, out_cap, "%s/%s", base, path);
    }
    out[out_cap - 1] = '\0';
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    return 0;
}

static int copy_to_user_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr) return -1;
    if (n == 0) return 0;
    if (!user_range_ok(uptr, n)) return -1;
    thread_t *t = uaccess_thread();
    /* Break fork-COW on destination pages before the store. Kernel writes do
     * not take the user #PF COW path; without this, rt_sigaction(oldact) on a
     * still-shared stack page faults into uaccess-abort / hang. */
    if (t && t->mm && t->mm != mm_kernel()) {
        mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : mm_kernel();
        return mm_copy_to_user(t->mm, share,
                               (uint64_t)(uintptr_t)uptr, kptr, n);
    }
    if (uaccess_arm(t, uptr, n, &&fault, 0) != 0) return -1;
    {
        volatile uint8_t *dst = (volatile uint8_t *)uptr;
        const uint8_t *src = (const uint8_t *)kptr;
        for (size_t i = 0; i < n; i++) dst[i] = src[i];
    }
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

static int copy_from_user_raw(void *kdst, const void *usrc, size_t n) {
    if (!kdst || !usrc) return -1;
    if (n == 0) return 0;
    if (!user_range_ok(usrc, n)) return -1;
    thread_t *t = uaccess_thread();
    /*
     * Always read the task leaf PFN (including identity leaves). VA reads
     * under kernel CR3 after vfork detach saw sa_mask as sa_handler.
     */
    if (t && t->mm && t->mm != mm_kernel() && t->mm->pml4) {
        return mm_copy_from_user(t->mm, kdst,
                                 (uint64_t)(uintptr_t)usrc, n);
    }
    if (uaccess_arm(t, usrc, n, &&fault, 0) != 0) return -1;
    {
        uint8_t *dst = (uint8_t *)kdst;
        const volatile uint8_t *src = (const volatile uint8_t *)usrc;
        for (size_t i = 0; i < n; i++) dst[i] = src[i];
    }
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

static inline int user_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    /* Linux user addresses: low identity through stack + AVX guard.
       Cap was USER_STACK_TOP and rejected valid pointers in the +2MiB
       overrun window — execve then returned EFAULT ("Bad address"). */
    const uintptr_t user_min = 0x00010000u;
    const uintptr_t user_max = (uintptr_t)USER_STACK_TOP + (64u * (uintptr_t)PAGE_SIZE_2M);
    if (start < user_min) return 0;
    if (end > user_max) return 0;
    if (end > (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

static inline int user_recv_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    if (start < 0x00010000u) return 0;
    if (end > (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

static int copy_to_user_recv_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, uptr, n, &&fault, 1) != 0) return -1;
    volatile uint8_t *dst = (volatile uint8_t *)uptr;
    const uint8_t *src = (const uint8_t *)kptr;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

static int user_read_u64(const void *uaddr, uint64_t *out) {
    if (!out) return -1;
    if (!user_range_ok(uaddr, sizeof(uint64_t))) return -1;
    /* copy to avoid alignment surprises */
    if (copy_from_user_raw(out, uaddr, sizeof(uint64_t)) != 0) return -1;
    return 0;
}

static int user_read_u8(const void *uaddr, uint8_t *out) {
    if (!out) return -1;
    if (!user_range_ok(uaddr, 1)) return -1;
    if (copy_from_user_raw(out, uaddr, 1) != 0) return -1;
    return 0;
}

static int user_write_u64(void *uaddr, uint64_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

static int user_write_u8(void *uaddr, uint8_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

static size_t user_strnlen_bounded(const char *s, size_t max) {
    if (!s) return 0;
    if (max == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, s, max, &&fault, 0) != 0) return 0;
    const volatile char *p = (const volatile char *)s;
    for (size_t i = 0; i < max; i++) {
        if (p[i] == '\0') {
            uaccess_clear(t);
            return i;
        }
    }
    uaccess_clear(t);
    return max;
fault:
    /* Must not return `max` — callers treat that as a full string and
       user_range_ok(s, max+1) then fails with EFAULT (BusyBox: Bad address). */
    uaccess_clear(t);
    return 0;
}

static char *copy_user_cstr(const char *u, size_t maxlen) {
    if (!u) return NULL;
    size_t L = user_strnlen_bounded(u, maxlen - 1);
    if (L >= maxlen) L = maxlen - 1;
    if (!user_range_ok(u, L + 1)) return NULL;
    char *k = (char*)kmalloc(L + 1);
    if (!k) return NULL;
    if (copy_from_user_raw(k, u, L + 1) != 0) { kfree(k); return NULL; }
    k[L] = '\0';
    return k;
}

/* Minimal tty state for job control-ish ioctls (single session). */
static uint64_t user_pgrp = 1;

/* Signal delivery: handlers, restorers, and per-thread mask. */
typedef void (*user_sighandler_t)(int);
#define SA_SIGINFO 0x4
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000u
#endif
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0x01000000u
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0x40000000u
#endif
#ifndef SS_ONSTACK
#define SS_ONSTACK 1
#endif
#ifndef SS_DISABLE
#define SS_DISABLE 2
#endif
#define MINSIGSTKSZ_AXON 2048u
#define SIG_DFL ((user_sighandler_t)0)
#define SIG_IGN ((user_sighandler_t)1)

/* Linux stores the userspace address; executable/NX validity is checked on use. */
static int sighandler_user_plausible(uint64_t h) {
    if (h == 0 || h == 1)
        return 1; /* SIG_DFL / SIG_IGN */
    return h >= 0x10000ULL && h < (uint64_t)MMIO_IDENTITY_LIMIT;
}
typedef struct {
    user_sighandler_t handler;
    uint64_t restorer;   /* glibc passes __restore_rt; we need it for sigreturn */
    uint64_t flags;      /* SA_SIGINFO etc. */
    uint64_t mask;       /* low 64 bits of sa_mask */
} user_sigaction_t;
static user_sigaction_t user_sig_actions[65]; /* 1..64 */
/* Legacy global mask; rt_sigprocmask uses per-thread saved_sig_mask when available */
static uint64_t user_sig_mask = 0;
/* Compatibility shim for tools (e.g. ping) that expect periodic SIGALRM. */
static uint32_t user_itimer_interval_ms = 0;

/* write()/writev() on sockets: glibc DNS may use writev; fs_write() does not handle SYSCALL_FTYPE_SOCKET. */
static ssize_t net_sock_write_userspace(thread_t *cur, int fd, ksock_net_t *s, const void *bufp, size_t cnt) {
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        (void)cur;
        (void)fd;
        if (!s->connected) return -ENOTCONN;
        if (cnt == 0) return 0;
        return unix_stream_write_from_user(s, bufp, cnt);
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (!bufp || cnt == 0) return -EINVAL;
        if (cnt < sizeof(nlmsghdr_k) || !user_range_ok(bufp, cnt)) return -EFAULT;
        uint8_t pkt[256];
        size_t cp = (cnt > sizeof(pkt)) ? sizeof(pkt) : cnt;
        if (copy_from_user_raw(pkt, bufp, cp) != 0) return -EFAULT;
        nlmsghdr_k *h = (nlmsghdr_k *)pkt;
        if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > cnt) return -EINVAL;
        if (s->nl_pid == 0) s->nl_pid = (uint32_t)((cur && cur->tid) ? cur->tid : 1);
        if (netlink_apply_request(s, pkt, cp) != 0) return -EINVAL;
        return (ssize_t)cnt;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->unix_conn) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            if (!s->connected) return -ENOTCONN;
            return unix_stream_write_from_user(s, bufp, cnt);
        }
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            if (!s->connected) return -EDESTADDRREQ;
            if (cnt > 2048) return -EINVAL;
            if (s->local_port == 0)
                s->local_port = net_alloc_ephemeral_port();
            uint8_t *payload = (uint8_t *)kmalloc(cnt);
            if (!payload) return -ENOMEM;
            if (copy_from_user_raw(payload, bufp, cnt) != 0) {
                kfree(payload);
                return -EFAULT;
            }
            int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
            kfree(payload);
            if (r != 0) return (ssize_t)(-net_l3_send_errno());
            return (ssize_t)cnt;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->tcp.peer_rst) return -ECONNRESET;
        if (s->tcp.peer_fin) return -EPIPE;
        if (!s->connected || !s->tcp.established) return -ENOTCONN;
        size_t total = 0;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, &s->tcp);
        while (total < cnt) {
            size_t chunk = cnt - total;
            if (chunk > 4096) chunk = 4096;
            uint8_t *tmp = (uint8_t *)kmalloc(chunk);
            if (!tmp) return (ssize_t)((total > 0) ? (ssize_t)total : -ENOMEM);
            if (copy_from_user_raw(tmp, (const uint8_t *)bufp + total, chunk) != 0) {
                kfree(tmp);
                return (ssize_t)((total > 0) ? (ssize_t)total : -EFAULT);
            }
            if (total == 0)
                net_debug_log_tls443_tx(s, tmp, chunk, "write");
            int wr = net_tcp_send(&s->tcp, &ops, tmp, chunk, 30000);
            kfree(tmp);
            if (wr < 0) {
                return (ssize_t)((total > 0) ? (ssize_t)total : -EIO);
            }
            total += (size_t)wr;
            if ((size_t)wr < chunk) break;
        }
        (void)net_tcp_flush_tx(&s->tcp, &ops, 250);
        for (int p = 0; p < 2; p++) {
            e1000_poll();
            (void)net_tcp_service(&s->tcp, &ops, 8);
            if (s->tcp.rx_len > 0)
                break;
        }
        (void)net_tcp_window_update(&s->tcp, &ops);
        return (ssize_t)total;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (!s->connected) return -EDESTADDRREQ;
        if (cnt > 2048) return -EINVAL;
        if (s->local_port == 0)
            s->local_port = net_alloc_ephemeral_port();
        uint8_t *payload = (uint8_t *)kmalloc(cnt);
        if (!payload) return -ENOMEM;
        if (copy_from_user_raw(payload, bufp, cnt) != 0) {
            kfree(payload);
            return -EFAULT;
        }
        int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
        kfree(payload);
        if (r != 0) return (ssize_t)(-net_l3_send_errno());
        return (ssize_t)cnt;
    }
    return -EINVAL;
}

/* Kernel-buffer TCP write for sendfile(2) (fs_write does not handle sockets). */
static ssize_t net_sock_write_kbuf(ksock_net_t *s, const void *buf, size_t cnt) {
    if (!s || !buf) return -EINVAL;
    if (cnt == 0) return 0;
    if (s->unix_domain_stub || s->unix_conn)
        return -EINVAL;
    if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL)
        return -EINVAL;
    if (s->dns_tcp_udp_bridge) return -EINVAL;
    if (s->tcp.peer_rst) return -ECONNRESET;
    if (s->tcp.peer_fin) return -EPIPE;
    if (!s->connected || !s->tcp.established) return -ENOTCONN;
    net_tcp_ops_t ops;
    net_make_tcp_ops(&ops, &s->tcp);
    size_t total = 0;
    while (total < cnt) {
        size_t chunk = cnt - total;
        if (chunk > 4096) chunk = 4096;
        int wr = net_tcp_send(&s->tcp, &ops, (const uint8_t *)buf + total, chunk, 30000);
        if (wr < 0)
            return (ssize_t)((total > 0) ? (ssize_t)total : -EIO);
        total += (size_t)wr;
        if ((size_t)wr < chunk) break;
    }
    (void)net_tcp_flush_tx(&s->tcp, &ops, 250);
    for (int p = 0; p < 2; p++) {
        e1000_poll();
        (void)net_tcp_service(&s->tcp, &ops, 8);
    }
    (void)net_tcp_window_update(&s->tcp, &ops);
    return (ssize_t)total;
}

/* ---------- Linux epoll (LT default; EPOLLET + EPOLLRDHUP + close-auto-del) ---------- */
enum {
    EPOLL_CTL_ADD_K = 1,
    EPOLL_CTL_DEL_K = 2,
    EPOLL_CTL_MOD_K = 3,
    EPOLLIN_K = 0x001,
    EPOLLPRI_K = 0x002,
    EPOLLOUT_K = 0x004,
    EPOLLERR_K = 0x008,
    EPOLLHUP_K = 0x010,
    EPOLLRDHUP_K = 0x2000,
    EPOLLONESHOT_K = 1u << 30,
    EPOLLET_K = 1u << 31,
    POLLIN_K = 0x001,
    POLLOUT_K = 0x004,
    POLLERR_K = 0x008,
    POLLHUP_K = 0x010,
    POLLNVAL_K = 0x020,
    POLLRDHUP_K = 0x2000,
    EPOLL_MAX_ITEMS = 256,
    EPOLL_CLOEXEC_K = 02000000
};

typedef struct {
    uint32_t events;
    uint64_t data;
} __attribute__((packed)) epoll_event_k;

typedef struct {
    int fd;
    uint32_t events;
    uint64_t data;
    uint8_t et_delivered; /* EPOLLET: already reported while still ready */
} epoll_item_t;

typedef struct {
    int flags;
    int nitems;
    epoll_item_t items[EPOLL_MAX_ITEMS];
} kepoll_t;

void epoll_fs_file_destroy(struct fs_file *f) {
    if (!f) return;
    if (f->type != SYSCALL_FTYPE_EPOLL) return;
    kepoll_t *ep = (kepoll_t *)f->driver_private;
    f->driver_private = NULL;
    if (ep) kfree(ep);
    if (f->path) {
        kfree((void *)f->path);
        f->path = NULL;
    }
    kfree(f);
}

static int epoll_find_item(kepoll_t *ep, int fd);

/* Drop fd from every epoll set owned by this process (Linux close semantics). */
void epoll_notify_fd_closed(thread_t *thr, int fd) {
    if (!thr || fd < 0) return;
    struct fs_file **table = thr->process ? thr->process->fds : thr->fds;
    if (!table) return;
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        struct fs_file *f = table[i];
        if (!f || f->type != SYSCALL_FTYPE_EPOLL || !f->driver_private) continue;
        kepoll_t *ep = (kepoll_t *)f->driver_private;
        int idx = epoll_find_item(ep, fd);
        if (idx < 0) continue;
        ep->items[idx] = ep->items[ep->nitems - 1];
        ep->nitems--;
    }
}

/* Shared readiness used by poll and epoll (level-triggered). */
static short fd_poll_revents(thread_t *thr, int fd, short events) {
    short revents = 0;
    if (fd < 0) return 0;
    if (fd >= THREAD_MAX_FD) return POLLNVAL_K;
    struct fs_file *f = syscall_fd_get(thr, fd);
    if (!f) return POLLNVAL_K;
    if (devfs_is_tty_file(f)) {
        int tidx = devfs_get_tty_index_from_file(f);
        if (tidx < 0) tidx = devfs_get_active();
        if ((events & POLLIN_K) && devfs_tty_available(tidx) > 0) revents |= POLLIN_K;
        if (events & POLLOUT_K) revents |= POLLOUT_K;
        return revents;
    }
    if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
        ksock_net_t *s = (ksock_net_t *)f->driver_private;
        if (events & POLLOUT_K) {
            if (s->unix_domain_stub) {
                if (!s->unix_listening && s->connected && !unix_stream_peer_closed(s) &&
                    unix_stream_avail_to_write(s) > 0)
                    revents |= POLLOUT_K;
            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL &&
                       s->dns_tcp_udp_bridge) {
                revents |= POLLOUT_K;
            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                if (s->tcp.connect_pending) {
                    e1000_poll();
                    if (net_tcp_connect_poll(&s->tcp, &ops, 0) == 0) {
                        s->connected = 1;
                        revents |= POLLOUT_K;
                    } else if (s->tcp.connect_refused) {
                        revents |= POLLERR_K | POLLHUP_K;
                    }
                } else {
                    e1000_poll();
                    (void)net_tcp_service(&s->tcp, &ops, 64);
                    if (s->tcp.established) revents |= POLLOUT_K;
                    if (s->tcp.peer_rst) revents |= POLLERR_K | POLLHUP_K;
                }
            } else {
                revents |= POLLOUT_K;
            }
        }
        if ((events & POLLIN_K) && s->sock_domain == AF_NETLINK_LOCAL) {
            if (s->nl_rx_off < s->nl_rx_len) revents |= POLLIN_K;
        } else if (s->unix_domain_stub) {
            if (s->unix_listening) {
                if ((events & POLLIN_K) && s->unix_accept_count > 0) revents |= POLLIN_K;
            } else if (s->connected) {
                if ((events & POLLIN_K) &&
                    (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s)))
                    revents |= POLLIN_K;
                if ((events & POLLOUT_K) && !unix_stream_peer_closed(s) &&
                    unix_stream_avail_to_write(s) > 0)
                    revents |= POLLOUT_K;
                if ((events & POLLRDHUP_K) && unix_stream_peer_closed(s))
                    revents |= POLLRDHUP_K;
                if (unix_stream_peer_closed(s) && unix_stream_avail_to_read(s) == 0)
                    revents |= POLLHUP_K;
            }
        } else if (s->tcp_listening) {
            net_pump_listen_handshake();
            if ((events & POLLIN_K) && s->unix_accept_count > 0) revents |= POLLIN_K;
        } else if (s->unix_conn && s->type_base == SOCK_STREAM_LOCAL &&
                   s->protocol == IPPROTO_TCP_LOCAL && s->connected) {
            if ((events & POLLIN_K) &&
                (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s)))
                revents |= POLLIN_K;
            if ((events & POLLOUT_K) && !unix_stream_peer_closed(s) &&
                unix_stream_avail_to_write(s) > 0)
                revents |= POLLOUT_K;
            if ((events & POLLRDHUP_K) && unix_stream_peer_closed(s))
                revents |= POLLRDHUP_K;
            if (unix_stream_peer_closed(s) && unix_stream_avail_to_read(s) == 0)
                revents |= POLLHUP_K;
        } else if ((events & POLLIN_K) && s->sock_domain == AF_PACKET_LOCAL) {
            if (!packet_sock_has_data(s))
                net_packet_pump_rx(16);
            if (packet_sock_has_data(s)) revents |= POLLIN_K;
        } else if ((events & POLLIN_K) &&
                   ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                    (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL &&
                     s->dns_tcp_udp_bridge))) {
            if (s->rx_has_pending) revents |= POLLIN_K;
            else {
                uint32_t sip = 0;
                uint16_t sport = 0;
                int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                if (rn > 0) {
                    ksock_rx_pending_install(s, rn);
                    s->rx_pending_src_ip_be = sip;
                    s->rx_pending_src_port = sport;
                    revents |= POLLIN_K;
                }
            }
        } else if ((events & POLLIN_K) && s->type_base == SOCK_STREAM_LOCAL &&
                   s->protocol == IPPROTO_TCP_LOCAL) {
            if (s->tcp.connect_pending) {
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                (void)net_tcp_connect_poll(&s->tcp, &ops, 0);
            }
            net_pump_tcp_sock(s, 1);
            if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst || s->tcp.ooo_valid)
                revents |= POLLIN_K;
            if ((events & POLLRDHUP_K) && s->tcp.peer_fin)
                revents |= POLLRDHUP_K;
            if (s->tcp.peer_rst)
                revents |= POLLERR_K | POLLHUP_K;
            else if (s->tcp.peer_fin && s->tcp.rx_len == 0 && !s->tcp.ooo_valid)
                revents |= POLLHUP_K;
        }
        return revents;
    }
    if (usb_is_devfs_file(f)) {
        if (events & POLLOUT_K) revents |= POLLOUT_K;
        return revents;
    }
    if (f->type == FS_TYPE_PIPE && f->driver_private) {
        pipe_t *p = (pipe_t *)f->driver_private;
        unsigned long fl = 0;
        acquire_irqsave(&p->lock, &fl);
        size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
        size_t freeb = (p->size > 1) ? ((p->size - 1) - used) : 0;
        int is_write_end = fs_pipe_is_write_end(f);
        release_irqrestore(&p->lock, fl);
        if (is_write_end) {
            if ((events & POLLOUT_K) && freeb > 0) revents |= POLLOUT_K;
            if (p->refcount < 2) revents |= POLLHUP_K;
        } else {
            if ((events & POLLIN_K) && used > 0) revents |= POLLIN_K;
            if (p->refcount < 2) {
                revents |= POLLHUP_K;
                if (events & POLLRDHUP_K) revents |= POLLRDHUP_K;
            }
        }
        return revents;
    }
    if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
        eventfd_t *e = (eventfd_t *)f->driver_private;
        unsigned long fl = 0;
        acquire_irqsave(&e->lock, &fl);
        uint64_t c = e->count;
        release_irqrestore(&e->lock, fl);
        if ((events & POLLIN_K) && c > 0) revents |= POLLIN_K;
        if ((events & POLLOUT_K) && c != (uint64_t)-1) revents |= POLLOUT_K;
        return revents;
    }
    if (events & POLLOUT_K) revents |= POLLOUT_K;
    if (events & POLLIN_K) {
        if (f->type == FS_TYPE_DIR) {
            revents |= POLLIN_K;
        } else if ((size_t)f->pos < (size_t)f->size) {
            revents |= POLLIN_K;
        } else if (f->path &&
                   (strcmp(f->path, "/dev/null") == 0 ||
                    strcmp(f->path, "/dev/zero") == 0 ||
                    strcmp(f->path, "/dev/random") == 0 ||
                    strcmp(f->path, "/dev/urandom") == 0 ||
                    strcmp(f->path, "/dev/full") == 0)) {
            revents |= POLLIN_K;
        }
    }
    return revents;
}

static int epoll_interest_to_poll(uint32_t ev) {
    short pe = 0;
    if (ev & (EPOLLIN_K | EPOLLPRI_K)) pe |= POLLIN_K;
    if (ev & EPOLLRDHUP_K) pe |= POLLRDHUP_K | POLLIN_K;
    if (ev & EPOLLOUT_K) pe |= POLLOUT_K;
    /* ERR/HUP are always reported by Linux when they occur. */
    pe |= POLLERR_K | POLLHUP_K;
    return pe;
}

static uint32_t poll_to_epoll_revents(short revents, uint32_t interest) {
    uint32_t out = 0;
    if ((interest & EPOLLIN_K) && (revents & POLLIN_K)) out |= EPOLLIN_K;
    if ((interest & EPOLLPRI_K) && (revents & POLLIN_K)) out |= EPOLLPRI_K;
    if ((interest & EPOLLOUT_K) && (revents & POLLOUT_K)) out |= EPOLLOUT_K;
    if ((interest & EPOLLRDHUP_K) && (revents & POLLRDHUP_K)) out |= EPOLLRDHUP_K;
    /* ERR/HUP always reported even if not in interest (Linux). */
    if (revents & POLLERR_K) out |= EPOLLERR_K;
    if (revents & POLLHUP_K) out |= EPOLLHUP_K;
    return out;
}

static kepoll_t *epoll_from_fd(thread_t *thr, int efd) {
    if (!thr || efd < 0 || efd >= THREAD_MAX_FD) return NULL;
    struct fs_file *f = syscall_fd_get(thr, efd);
    if (!f || f->type != SYSCALL_FTYPE_EPOLL || !f->driver_private) return NULL;
    return (kepoll_t *)f->driver_private;
}

static int epoll_find_item(kepoll_t *ep, int fd) {
    if (!ep) return -1;
    for (int i = 0; i < ep->nitems; i++) {
        if (ep->items[i].fd == fd) return i;
    }
    return -1;
}

/* read()/readv() on sockets; readv uses repeated calls (UDP rx_pending_off preserves datagram). */
static ssize_t net_sock_read_userspace(thread_t *cur, ksock_net_t *s, void *bufp, size_t cnt) {
    (void)cur;
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        if (!s->connected) return -ENOTCONN;
        if (cnt == 0) return 0;
        return unix_stream_read_to_user(s, bufp, cnt, 0);
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (cnt == 0) return 0;
        if (!bufp || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->nl_rx_off >= s->nl_rx_len)
            return 0; /* EOF after dump — ip(8) treats EAGAIN as OVERRUN */
        size_t avail = s->nl_rx_len - s->nl_rx_off;
        size_t ncopy = (avail > cnt) ? cnt : avail;
        if (copy_to_user_safe(bufp, s->nl_rx + s->nl_rx_off, ncopy) != 0) return -EFAULT;
        s->nl_rx_off += ncopy;
        return (ssize_t)ncopy;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->unix_conn) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            if (!s->connected) return -ENOTCONN;
            return unix_stream_read_to_user(s, bufp, cnt, 0);
        }
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            size_t cap = cnt > 8192 ? 8192 : cnt;
            uint8_t *utmp = (uint8_t *)kmalloc(cap);
            if (!utmp) return -ENOMEM;
            if (!s->rx_has_pending) {
                int pr = net_udp_recv_into_pending(s);
                if (pr != 1) {
                    kfree(utmp);
                    if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                    return -EIO;
                }
            }
            int n = 0;
            ksock_rx_pending_normalize(s);
            if (s->rx_has_pending) {
                size_t avail = ksock_rx_pending_avail(s);
                n = (int)((avail > cap) ? cap : avail);
                if (n > 0) memcpy(utmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                s->rx_pending_off += (size_t)n;
                if (s->rx_pending_off >= s->rx_pending_len) {
                    s->rx_has_pending = 0;
                    s->rx_pending_off = 0;
                    s->rx_pending_len = 0;
                }
            }
            if (n > 0 && copy_to_user_safe(bufp, utmp, (size_t)n) != 0) {
                kfree(utmp);
                return -EFAULT;
            }
            kfree(utmp);
            if (n <= 0) return -EAGAIN;
            return (ssize_t)n;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
        if (!s->tcp.established && s->tcp.connect_pending) {
            net_tcp_ops_t cops;
            net_make_tcp_ops(&cops, &s->tcp);
            e1000_poll();
            if (net_tcp_connect_poll(&s->tcp, &cops, 0) == 0)
                s->connected = 1;
        }
        if (!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) {
            if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
            if (s->tcp.rx_len == 0) return -ENOTCONN;
        }
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, &s->tcp);
        size_t chunk = cnt;
        if (chunk > 16384) chunk = 16384;
        uint8_t *tmp = (uint8_t *)kmalloc(chunk);
        if (!tmp) return -ENOMEM;
        size_t total = 0;
        for (;;) {
            for (int pump = 0; pump < 2; pump++) {
                e1000_poll();
                (void)net_tcp_service(&s->tcp, &ops, 8);
                if (s->tcp.rx_len > 0)
                    break;
                if (s->tcp.peer_rst)
                    break;
            }
            if (s->tcp.established && s->tcp.rx_len < sizeof(s->tcp.rx_buf))
                (void)net_tcp_window_update(&s->tcp, &ops);
            uint32_t tmo = s->nonblock ? 0u : 120000u;
            int rr = net_tcp_recv(&s->tcp, &ops, tmp + total, chunk - total, tmo);
            if (rr > 0) {
                total += (size_t)rr;
                if (total >= chunk || rr < (int)(chunk - total))
                    break;
                for (int pump = 0; pump < 2; pump++) {
                    e1000_poll();
                    (void)net_tcp_service(&s->tcp, &ops, 8);
                }
                continue;
            }
            if (total > 0)
                break;
            kfree(tmp);
            if (rr == 0) return 0;
            if (rr == -4) return -ECONNRESET;
            if (rr == -2)
                return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
            return (ssize_t)(s->nonblock ? -EAGAIN : -EIO);
        }
        if (copy_to_user_safe(bufp, tmp, total) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        return (ssize_t)total;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        if (!s->rx_has_pending) {
            int pr = net_udp_recv_into_pending(s);
            if (pr != 1) {
                kfree(tmp);
                if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                return -EIO;
            }
        }
        int n = 0;
        ksock_rx_pending_normalize(s);
        if (s->rx_has_pending) {
            size_t avail = ksock_rx_pending_avail(s);
            n = (int)((avail > cap) ? cap : avail);
            if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
            s->rx_pending_off += (size_t)n;
            if (s->rx_pending_off >= s->rx_pending_len) {
                s->rx_has_pending = 0;
                s->rx_pending_off = 0;
                s->rx_pending_len = 0;
            }
        }
        if (n > 0 && copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        if (n <= 0) return -EAGAIN;
        return (ssize_t)n;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_ICMP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
        int n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, NULL);
        if (n < 0) {
            kfree(tmp);
            return -EIO;
        }
        if (n == 0) {
            kfree(tmp);
            return -ETIMEDOUT;
        }
        if (copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        return (ssize_t)n;
    }
    return -EINVAL;
}

/* Linux x86_64 rt_sigframe / ucontext layout for signal delivery.
 * Must match kernel/glibc x86_64: pretcode, ucontext (mcontext before sigmask),
 * then siginfo. x86_64 SysV ABI also reserves a 128-byte red zone below RSP. */
#pragma pack(push, 1)
typedef struct {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx;
    uint64_t rsp, rip, eflags;
    uint16_t cs, gs, fs;
    uint16_t ss;
    uint64_t err, trapno, oldmask, cr2;
    uint64_t fpstate;
    uint64_t reserved1[8];
} k_sigcontext_t;
typedef struct {
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_ss_sp, uc_stack_ss_size;
    uint32_t uc_stack_ss_flags, uc_pad;
    k_sigcontext_t uc_mcontext;
    uint64_t uc_sigmask[2];
} k_ucontext_t;
typedef struct {
    int32_t si_signo;
    int32_t si_errno;
    int32_t si_code;
    int32_t si_pad;
    uint64_t si_addr;
    uint8_t  si_tail[128 - 24];
} k_siginfo_t;
#pragma pack(pop)
#define RT_SIGFRAME_UC_OFF    8
#define RT_SIGFRAME_INFO_OFF  (8 + sizeof(k_ucontext_t))
#define RT_SIGFRAME_SIZE      (RT_SIGFRAME_INFO_OFF + sizeof(k_siginfo_t))
#define X86_REDZONE           128ULL

/* Prefer sigaltstack when SA_ONSTACK is set and an alt stack is armed. */
static uint64_t signal_pick_handler_rsp(thread_t *cur, const user_sigaction_t *sa,
                                        uint64_t normal_rsp) {
    if (!cur || !sa) return normal_rsp;
    if (!(sa->flags & SA_ONSTACK)) return normal_rsp;
    if (cur->sas_ss_flags & SS_DISABLE) return normal_rsp;
    if (!cur->sas_ss_sp || cur->sas_ss_size < MINSIGSTKSZ_AXON) return normal_rsp;
    uint64_t top = cur->sas_ss_sp + cur->sas_ss_size;
    if (top <= cur->sas_ss_sp || top > (uint64_t)MMIO_IDENTITY_LIMIT) return normal_rsp;
    return top;
}

/* Pick next deliverable signal. Returns:
 *   0  — nothing to do
 *   1  — *sa_out ready for user handler delivery (*sig_out set)
 *  -1  — signal consumed (IGN / bad handler / non-fatal DFL); caller should retry
 * Never returns on fatal SIG_DFL (yields / hlt). */
static int signal_prepare_next(thread_t *cur, int *sig_out, user_sigaction_t *sa_out) {
    if (!cur || cur->ring != 3 || cur->state == THREAD_TERMINATED) return 0;
    uint64_t blocked = cur->saved_sig_mask;
    /* Linux: SIGKILL and SIGSTOP cannot be blocked. */
    blocked &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    uint64_t pending = cur->pending_signals & ~blocked;
    if (!pending) return 0;
    int sig = 0;
    for (int s = 1; s <= 63 && !sig; s++) {
        if (pending & (1ULL << (s - 1))) sig = s;
    }
    if (sig <= 0) return 0;

    user_sigaction_t *sa = &user_sig_actions[sig];
    if (cur->process) {
        memset(sa_out, 0, sizeof(*sa_out));
        sa_out->handler = (user_sighandler_t)(uintptr_t)
            cur->process->signal_handlers[sig];
        sa_out->flags = cur->process->signal_flags[sig];
        sa_out->restorer = cur->process->signal_restorer[sig];
        sa_out->mask = cur->process->signal_masks[sig];
        sa = sa_out;
    } else {
        *sa_out = *sa;
        sa = sa_out;
    }

    user_sighandler_t h = sa->handler;
    /* Linux: SIGKILL/SIGSTOP cannot be caught or ignored. */
    if (sig == SIGKILL || sig == SIGSTOP)
        h = SIG_DFL;
    if (!sighandler_user_plausible((uint64_t)(uintptr_t)h)) {
        if (sig == SIGKILL) {
            h = SIG_DFL;
        } else {
            kprintf("sig-deliver: drop bad handler=0x%llx sig=%d tid=%d\n",
                    (unsigned long long)(uintptr_t)h, sig,
                    (int)(cur->tid ? cur->tid : 1));
            cur->pending_signals &= ~(1ULL << (sig - 1));
            if (cur->process)
                cur->process->signal_handlers[sig] = 0;
            user_sig_actions[sig].handler = SIG_DFL;
            return -1;
        }
    }
    if (h == SIG_IGN) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        return -1;
    }
    if (h == SIG_DFL) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        /*
         * Linux default Term/Core. SIGKILL was missing — kill -9 cleared
         * pending with no effect (success, process still alive).
         */
        int fatal = (sig == SIGHUP || sig == SIGINT || sig == SIGQUIT ||
                     sig == SIGILL || sig == SIGABRT || sig == SIGBUS ||
                     sig == SIGFPE || sig == SIGKILL || sig == SIGSEGV ||
                     sig == SIGPIPE || sig == SIGALRM || sig == SIGTERM ||
                     sig == 24 /*SIGXCPU*/ || sig == 25 /*SIGXFSZ*/ ||
                     sig == 31 /*SIGSYS*/);
        if (fatal) {
            cur->exit_status = sig; /* WIFSIGNALED, WTERMSIG = sig */
            exit_group_reap_peer_threads(cur);
            thread_close_all_fds(cur);
            if (cur->parent_tid >= 0) {
                thread_t *pt = thread_get(cur->parent_tid);
                if (pt) {
                    thread_set_pending_signal(pt, SIGCHLD);
                    thread_unblock((int)(pt->tid ? pt->tid : 1));
                    if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty)
                        devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                }
            }
            process_release_vfork_parent(cur->process, PROCESS_VFORK_FATAL);
            process_mark_zombie(cur->process, cur->exit_status);
            if (cur->process) {
                process_t *init_process = NULL;
                int init_tid = thread_get_init_user_tid();
                thread_t *init_thread = init_tid >= 0 ? thread_get(init_tid) : NULL;
                if (init_thread)
                    init_process = init_thread->process;
                process_reparent_children(cur->process, init_process);
            }
            if (cur->waiter_tid >= 0) thread_unblock(cur->waiter_tid);
            if (user_range_ok((const void *)(uintptr_t)cur->clear_child_tid, 4)) {
                uint32_t zero = 0;
                copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                { extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                  futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0); }
                cur->clear_child_tid = 0;
            } else if (cur->clear_child_tid != 0) {
                cur->clear_child_tid = 0;
            }
            cur->state = THREAD_TERMINATED;
            if (cur->mm && cur->mm != mm_kernel()) {
                mm_t *dead_mm = cur->mm;
                cur->mm = NULL;
                (void)mm_switch_away_from(dead_mm);
                mm_release(dead_mm);
            }
            thread_yield();
            for (;;) asm volatile("sti; hlt" ::: "memory");
        }
        return -1;
    }
    if (!sa->restorer) return 0;
    *sig_out = sig;
    return 1;
}

/* Write rt_sigframe below old_rsp (skipping red zone). Does not clear pending —
 * caller commits pending/mask after user regs are patched. */
static uintptr_t signal_write_rt_frame(thread_t *cur, int sig, const user_sigaction_t *sa,
                                       uint64_t old_rsp, const k_sigcontext_t *sc) {
    if (!cur || !sa || !sc || !old_rsp) return 0;
    uintptr_t sp = (uintptr_t)old_rsp;
    if (sp > X86_REDZONE)
        sp -= X86_REDZONE;
    /*
     * Linux get_sigframe(): sp = round_down(sp - frame_size, 16) - 8.
     * x86-64 SysV requires RSP%16==8 on handler entry (as after CALL). Aligning
     * only to 16 left RSP≡0; htop's SIGINT path then #GP on movaps locals
     * (seen: rip movaps [rsp+0x30] with rsp=…888).
     */
    if (sp < RT_SIGFRAME_SIZE + 8ULL)
        return 0;
    uintptr_t frame_start = ((sp - RT_SIGFRAME_SIZE) & ~15ULL) - 8ULL;
    if (frame_start < 0x200000ULL) return 0;
    if (mark_user_identity_range_2m_sys((uint64_t)frame_start,
            (uint64_t)(frame_start + RT_SIGFRAME_SIZE)) != 0)
        return 0;

    k_ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    uc.uc_mcontext = *sc;
    uc.uc_mcontext.cs = 0x1B;
    uc.uc_mcontext.gs = 0;
    uc.uc_mcontext.fs = 0;
    uc.uc_mcontext.ss = 0x23;
    /* Best-effort stack_t fields (layout historically mismatched size/flags). */
    uc.uc_stack_ss_sp = cur->sas_ss_sp;
    uc.uc_stack_ss_size = cur->sas_ss_size;
    uc.uc_stack_ss_flags = (uint32_t)cur->sas_ss_flags;
    uc.uc_sigmask[0] = cur->saved_sig_mask;
    if (copy_to_user_safe((void *)(uintptr_t)(frame_start + RT_SIGFRAME_UC_OFF),
                          &uc, sizeof(uc)) != 0)
        return 0;

    k_siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = -6; /* SI_KERNEL */
    if (copy_to_user_safe((void *)(uintptr_t)(frame_start + RT_SIGFRAME_INFO_OFF),
                          &info, sizeof(info)) != 0)
        return 0;

    if (copy_to_user_safe((void *)(uintptr_t)frame_start,
                          &sa->restorer, sizeof(sa->restorer)) != 0)
        return 0;

    return frame_start;
}

static void signal_commit_delivery(thread_t *cur, int sig, const user_sigaction_t *sa) {
    if (!cur || !sa || sig <= 0) return;
    cur->pending_signals &= ~(1ULL << (sig - 1));
    cur->saved_sig_mask = cur->saved_sig_mask | sa->mask;
    if (!(sa->flags & SA_NODEFER))
        cur->saved_sig_mask |= (1ULL << (sig - 1));
}

/* Build signal frame and patch syscall return for delivery. Called from syscall_entry64. */
int maybe_deliver_pending_signal(uint64_t syscall_ret) {
    thread_t *cur = syscall_resolve_thread();
    if (!cur || cur->ring != 3) return 0;

    for (;;) {
        int sig = 0;
        user_sigaction_t sa;
        int prep = signal_prepare_next(cur, &sig, &sa);
        if (prep == 0) return 0;
        if (prep < 0) continue;

        uint64_t old_rsp = cur->saved_user_rsp;
        uint64_t old_rip = cur->saved_user_rip;
        if (!old_rsp || !old_rip) return 0;
        uint64_t *frame = cur->saved_syscall_frame;
        if (!frame) return 0;

        int restart_syscall = 0;
        if ((sa.flags & 0x10000000ULL) && /* SA_RESTART */
            (int64_t)syscall_ret == -(int64_t)EINTR &&
            old_rip >= 2) {
            uint8_t insn[2];
            if (copy_from_user_raw(insn, (const void *)(uintptr_t)(old_rip - 2),
                                   sizeof(insn)) == 0 &&
                insn[0] == 0x0f && insn[1] == 0x05) {
                old_rip -= 2;
                restart_syscall = 1;
            }
        }

        k_sigcontext_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.r8  = cur->saved_user_r8;
        sc.r9  = cur->saved_user_r9;
        sc.r10 = cur->saved_user_r10;
        sc.r11 = cur->saved_user_r11;
        sc.r12 = cur->saved_user_r12;
        sc.r13 = cur->saved_user_r13;
        sc.r14 = cur->saved_user_r14;
        sc.r15 = cur->saved_user_r15;
        sc.rdi = cur->saved_user_rdi;
        sc.rsi = cur->saved_user_rsi;
        sc.rbp = cur->saved_user_rbp;
        sc.rbx = cur->saved_user_rbx;
        sc.rdx = cur->saved_user_rdx;
        sc.rax = restart_syscall ? frame[14] : syscall_ret;
        sc.rcx = cur->saved_user_rcx;
        sc.rsp = old_rsp;
        sc.rip = old_rip;
        sc.eflags = cur->saved_user_r11;

        uint64_t handler = (uint64_t)(uintptr_t)sa.handler;
        if (handler < 0x10000ULL) return 0;

        uint64_t frame_rsp = signal_pick_handler_rsp(cur, &sa, old_rsp);
        uintptr_t frame_start = signal_write_rt_frame(cur, sig, &sa, frame_rsp, &sc);
        if (!frame_start) return 0;

        frame[8]  = (uint64_t)sig;
        if (sa.flags & SA_SIGINFO) {
            frame[9]  = (uint64_t)(frame_start + RT_SIGFRAME_INFO_OFF); /* rsi = info */
            frame[12] = (uint64_t)(frame_start + RT_SIGFRAME_UC_OFF);   /* rdx = uc */
        }
        frame[13] = handler;
        frame[15] = (uint64_t)frame_start;
        syscall_user_rsp_saved = (uint64_t)frame_start;
        signal_commit_delivery(cur, sig, &sa);
        asm volatile("mfence" ::: "memory");
        return 1;
    }
}

/* Deliver pending signal by rewriting the interrupt return frame (ring3). */
int maybe_deliver_pending_signal_iretq(cpu_registers_t *regs) {
    if (!regs || (regs->cs & 3) != 3) return 0;

    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur || cur->ring != 3 || cur->state == THREAD_TERMINATED) return 0;

    for (;;) {
        int sig = 0;
        user_sigaction_t sa;
        int prep = signal_prepare_next(cur, &sig, &sa);
        if (prep == 0) return 0;
        if (prep < 0) continue;

        uint64_t handler = (uint64_t)(uintptr_t)sa.handler;
        if (handler < 0x10000ULL) return 0;

        uint64_t old_rsp = regs->rsp;
        uint64_t old_rip = regs->rip;
        if (!old_rsp || !old_rip) return 0;
        /* Refuse nonsense return sites (prevents building a frame then iretq to 0). */
        if (old_rip < 0x10000ULL) return 0;

        k_sigcontext_t sc;
        memset(&sc, 0, sizeof(sc));
        sc.r8  = regs->r8;
        sc.r9  = regs->r9;
        sc.r10 = regs->r10;
        sc.r11 = regs->r11;
        sc.r12 = regs->r12;
        sc.r13 = regs->r13;
        sc.r14 = regs->r14;
        sc.r15 = regs->r15;
        sc.rdi = regs->rdi;
        sc.rsi = regs->rsi;
        sc.rbp = regs->rbp;
        sc.rbx = regs->rbx;
        sc.rdx = regs->rdx;
        sc.rax = regs->rax;
        sc.rcx = regs->rcx;
        sc.rsp = old_rsp;
        sc.rip = old_rip;
        sc.eflags = regs->rflags;

        uint64_t frame_rsp = signal_pick_handler_rsp(cur, &sa, old_rsp);
        uintptr_t frame_start = signal_write_rt_frame(cur, sig, &sa, frame_rsp, &sc);
        if (!frame_start) return 0;

        regs->rdi = (uint64_t)sig;
        if (sa.flags & SA_SIGINFO) {
            regs->rsi = (uint64_t)(frame_start + RT_SIGFRAME_INFO_OFF);
            regs->rdx = (uint64_t)(frame_start + RT_SIGFRAME_UC_OFF);
        }
        regs->rip = handler;
        regs->rsp = (uint64_t)frame_start;
        /* IF on, DF off — string ops in the handler must run forward. */
        regs->rflags |= 0x200ULL;
        regs->rflags &= ~0x400ULL;

        cur->saved_user_rdi = regs->rdi;
        cur->saved_user_rsi = regs->rsi;
        cur->saved_user_rdx = regs->rdx;
        cur->saved_user_rip = regs->rip;
        cur->saved_user_rsp = regs->rsp;
        cur->saved_user_r11 = regs->rflags;
        signal_commit_delivery(cur, sig, &sa);
        asm volatile("mfence" ::: "memory");
        return 1;
    }
}

/* Simple getrandom() state (non-crypto). */
static uint32_t user_rand_state = 0xA53C9E11u;

static inline int is_leap_year(int y) {
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

/* Convert rtc_datetime_t (year full e.g. 2025) to unix epoch seconds (UTC assumed). */
static uint64_t rtc_datetime_to_epoch(const rtc_datetime_t *dt) {
    if (!dt) return 0;
    int year = (int)dt->year;
    int month = (int)dt->month;
    int day = (int)dt->day;
    int hour = (int)dt->hour;
    int minute = (int)dt->minute;
    int second = (int)dt->second;
    /* Normalize month/year for algorithm: treat March as month 1 */
    if (month <= 2) {
        year -= 1;
        month += 12;
    }
    /* Days since epoch (1970-01-01) using proleptic Gregorian calendar */
    int64_t y = year;
    int64_t m = month;
    int64_t days = 365 * (y - 1970) + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
    /* month days cumulative for months starting at March=3 .. Feb=14 in this scheme */
    static const int mdays[] = {
        0,31,61,92,122,153,184,214,245,275,306,337, /* not used fully */
    };
    /* Simpler add days from months */
    static const int month_days_norm[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
    for (int mo = 1; mo < month; mo++) {
        days += month_days_norm[mo];
        if (mo == 2 && is_leap_year(year + (month <= 2 ? 1 : 0))) days += 1;
    }
    days += (day - 1);
    uint64_t secs = (uint64_t)days * 86400ULL + (uint64_t)hour * 3600ULL + (uint64_t)minute * 60ULL + (uint64_t)second;
    return secs;
}

/* Minimal signal numbers we use here */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif

/* Send simple signals to all threads in given pgrp.
   SIGHUP -> mark terminated (default action).
   SIGCONT -> move sleeping/blocked to ready.
*/
static void send_signal_to_pgrp(int pgrp, int signum) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->pgid != pgrp) continue;
        if (signum == SIGHUP) {
            if (t->state != THREAD_TERMINATED) {
                t->exit_status = (0 & 0xFF) << 8;
                t->state = THREAD_TERMINATED;
                if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
            }
        } else if (signum == SIGCONT) {
            if (t->state == THREAD_SLEEPING || t->state == THREAD_BLOCKED) {
                t->sleep_until = 0;
                thread_note_ready(t);
            }
        }
    }
}

/* Send SIGHUP to all members of a session (except leader) */
static void send_hup_to_session(int sid) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->sid != sid) continue;
        if ((int)t->tid == sid) continue; /* skip leader */
        if (t->state != THREAD_TERMINATED) {
            t->exit_status = (0 & 0xFF) << 8;
            t->state = THREAD_TERMINATED;
            if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
        }
    }
    /* Also clear controlling_sid on dev ttys owned by this session */
    devfs_clear_controlling_by_sid(sid);
}

static uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);

/* Verbose per-syscall trace for /usr/bin/wget (budget-limited). Set left=0 to disable. */
static void axon_wget_sc_log(uint64_t num, uint64_t rax, uint64_t a1, uint64_t a2, uint64_t a3) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (!t || !t->name[0]) return;
    if (!strstr(t->name, "wget")) return;
    static int wget_sc_left = 512;
    static int wget_sc_warned;
    if (wget_sc_left <= 0) {
        if (!wget_sc_warned) {
            wget_sc_warned = 1;
            qemu_debug_printf("WGET-SC: trace budget exhausted (disable in axon_wget_sc_log)\n");
        }
        return;
    }
    wget_sc_left--;
    int64_t sr = (int64_t)rax;
    if (sr < 0 && sr >= -4096) {
        qemu_debug_printf("WGET-SC nr=%llu ERR=%d a1=0x%llx a2=0x%llx a3=0x%llx\n",
            (unsigned long long)num, (int)(-sr),
            (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
    } else {
        qemu_debug_printf("WGET-SC nr=%llu rax=0x%llx a1=0x%llx a2=0x%llx\n",
            (unsigned long long)num, (unsigned long long)rax,
            (unsigned long long)a1, (unsigned long long)a2);
    }
}

/* Resolve the ring-3 thread that issued a syscall.
 *
 * A syscall must never be attributed to PID1 or an arbitrary runnable task.
 * Doing so makes fork assign a live child to the wrong parent: BusyBox init
 * can then kill(pid, 0) successfully but wait4(-1) returns ECHILD.  The
 * per-CPU current_user fallback is retained only for the entry/handoff window
 * where scheduler current is temporarily a kernel/idle task. */
static thread_t *syscall_thread_from_kstack(void) {
    uint64_t sp = 0;
    asm volatile("mov %%rsp, %0" : "=r"(sp));
    if (!sp) return NULL;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3 || t->state == THREAD_TERMINATED)
            continue;
        if (!t->syscall_kstack_raw || !t->syscall_kstack_top)
            continue;
        uint64_t bot = (uint64_t)(uintptr_t)t->syscall_kstack_raw;
        uint64_t top = t->syscall_kstack_top;
        if (sp >= bot && sp < top)
            return t;
    }
    return NULL;
}

static thread_t *syscall_resolve_thread(void) {
    /*
     * Task identity is scheduler state, not an inference from the active CR3
     * or kernel-stack address.  In particular, fork_store_child_tid() may
     * inspect a child's mm while the parent is still executing its clone
     * syscall.  Adopting that child here corrupts both syscall return frames.
     */
    thread_t *cur = thread_current();
    if (cur && cur->ring == 3 && cur->state == THREAD_RUNNING)
        return cur;

    /* Diagnostic fallback for early entry paths; never mutate scheduler state. */
    thread_t *stack_owner = syscall_thread_from_kstack();
    if (stack_owner && stack_owner->ring == 3 &&
        stack_owner->state == THREAD_RUNNING)
        return stack_owner;

    thread_t *u = thread_get_current_user();
    if (u && u->ring == 3 && u->state == THREAD_RUNNING)
        return u;
    return NULL;
}

static uint64_t linux_task_tid(const thread_t *task) {
    if (!task) return 0;
    if (task->process && task->process->leader == task)
        return task->process->pid;
    return (uint64_t)(task->tid ? task->tid : 1);
}

static int fork_store_child_tid(thread_t *child, mm_t *parent_mm,
                                uint64_t child_tid_ptr, uint32_t value) {
    if (!child || !child->mm || !parent_mm ||
        !user_range_ok((const void *)(uintptr_t)child_tid_ptr, sizeof(value)))
        return -1;
    /*
     * Fork has already marked TLS/stack private-COW. A ring-0 store cannot use
     * the user-mode COW #PF path, so break COW explicitly before implementing
     * CLONE_CHILD_SETTID. Write through the child's translated physical
     * address: switching CR3 and calling the ordinary current-task uaccess
     * path used to make syscall identity change from parent to child.
     */
    mm_t *share = child->mm_ptemplate ?
        child->mm_ptemplate : parent_mm;
    return mm_copy_to_user(child->mm, share, child_tid_ptr,
                           &value, sizeof(value));
}

enum {
	CLONE_VM		= 0x00000100ULL,
	CLONE_FS		= 0x00000200ULL,
	CLONE_FILES		= 0x00000400ULL,
	CLONE_SIGHAND		= 0x00000800ULL,
	CLONE_VFORK		= 0x00004000ULL,
	CLONE_THREAD		= 0x00010000ULL,
	CLONE_SYSVSEM		= 0x00040000ULL,
	CLONE_SETTLS		= 0x00080000ULL,
	CLONE_PARENT_SETTID	= 0x00100000ULL,
	CLONE_CHILD_CLEARTID	= 0x00200000ULL,
	CLONE_CHILD_SETTID	= 0x01000000ULL,
};

struct kernel_clone_args {
	uint64_t flags;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t parent_tid;
	uint64_t child_tid;
	uint64_t tls;
	int exit_signal;
};

static uint64_t do_linux_fork(thread_t *cur,
			      const struct kernel_clone_args *args)
{
    if (!cur) return ret_err(ESRCH);
            uint64_t saved_rcx = fork_caller_user_rip(cur);
            if (!saved_rcx && cur->saved_syscall_frame)
                saved_rcx = cur->saved_syscall_frame[13];
            if (!saved_rcx)
                saved_rcx = cur->fork_locked_syscall_rip;
            uint64_t saved_rsp = cur->saved_user_rsp;
            /* Lazy Linux COW only needs a few PT pages + task struct. */
            if (heap_free_bytes() < (1u << 20) || heap_largest_free() < (8u << 10)) {
                kprintf("fork-fail: low heap free=%llu largest=%llu tid=%llu\n",
                    (unsigned long long)heap_free_bytes(),
                    (unsigned long long)heap_largest_free(),
                    (unsigned long long)(cur->tid ? cur->tid : 1));
                return ret_err(ENOMEM);
            }
            if (cur->name[0] && strstr(cur->name, "linuxrc")) {
                static int linuxrc_fork_begin_left = 24;
                if (linuxrc_fork_begin_left-- > 0)
                    devel_printf("fork-begin: tid=%llu rip=0x%llx rsp=0x%llx heap=%llu largest=%llu share=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (unsigned long long)saved_rcx,
                        (unsigned long long)saved_rsp,
                        (unsigned long long)heap_free_bytes(),
                        (unsigned long long)heap_largest_free(),
                        !!(args->flags & CLONE_VM));
            }
            fork_dbg(cur, 1, "enter",
                (unsigned long long)(cur->tid ? cur->tid : 0),
                (unsigned long long)saved_rcx,
                (unsigned long long)saved_rsp);
            if (saved_rcx == 0 || saved_rsp == 0 ||
                (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                fork_dbg(cur, -1, "EINVAL args", saved_rcx, saved_rsp, 0);
                return ret_err(EINVAL);
            }
            {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) != 0) {
                    fork_dbg(cur, -2, "EINVAL mark-rip", (unsigned long long)begin,
                        (unsigned long long)end, 0);
                    return ret_err(EINVAL);
                }
            }
            fork_dbg(cur, 2, "mark-rip ok", saved_rcx, saved_rsp, 0);
            (void)user_map_ensure_present_us_2m(0x10000, 0x200000);
            (void)thread_reap_unwaited_zombies();
            char child_name[32];
            strncpy(child_name, cur->name, sizeof(child_name) - 1);
            child_name[sizeof(child_name) - 1] = '\0';
            thread_t *child = thread_create_blocked(fork_child_return_entry, child_name);
            if (!child) {
                int z = thread_reap_unwaited_zombies();
                child = thread_create_blocked(fork_child_return_entry, child_name);
                if (!child) {
                    fork_dbg(cur, -3, "ENOMEM thread",
                        (unsigned long long)thread_get_count(),
                        (unsigned long long)heap_free_bytes(),
                        (unsigned long long)z);
                    return ret_err(ENOMEM);
                }
            }
            fpu_thread_fork(cur, child);
            fork_dbg(cur, 3, "child created",
                (unsigned long long)(child->tid ? child->tid : 0), 0, 0);
            int share_mm = !!(args->flags & CLONE_VM);
            mm_t *parent_mm = cur->mm ? cur->mm : mm_kernel();
            uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(cur->tid ? cur->tid : 1);
            uintptr_t parent_slot_lo = (parent_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
            if (cur->user_stack_limit > cur->user_stack_base &&
                cur->user_stack_base >= 0x200000u &&
                saved_rsp >= cur->user_stack_base &&
                saved_rsp < cur->user_stack_limit) {
                parent_stack_top = (uintptr_t)cur->user_stack_limit;
                parent_slot_lo = (uintptr_t)cur->user_stack_base;
            }
            uintptr_t child_rsp = (uintptr_t)saved_rsp;
            uintptr_t child_stack_top = parent_stack_top;
            uintptr_t child_slot_lo = parent_slot_lo;
            if (share_mm) {
                /*
                 * Linux vfork/CLONE_VM: share parent's mm until exec/exit.
                 * Parent is frozen (vfork_waiting); do not Soft_COW-mark.
                 * No identity-detach: kernel must not store to user VA via
                 * identity CR3 while the mm is shared (use leaf-PA copies).
                 */
                if (child->mm) mm_release(child->mm);
                child->mm = mm_retain(parent_mm);
                if (!child->mm) {
                    fork_stop_child(child);
                    return ret_err(ENOMEM);
                }
                if (child->mm_ptemplate) {
                    mm_release(child->mm_ptemplate);
                    child->mm_ptemplate = NULL;
                }
                child->user_fs_base = cur->user_fs_base;
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                if (cur->user_mmap_next) child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                child->user_stack_base = cur->user_stack_base ? cur->user_stack_base : (uint64_t)parent_slot_lo;
                child->user_stack_limit = cur->user_stack_limit ? cur->user_stack_limit : (uint64_t)parent_stack_top;
                child->ring = 3;
                (void)user_vma_clone_for_tid((uint64_t)(cur->tid ? cur->tid : 1),
                    (uint64_t)(child->tid ? child->tid : 1));
                if (cur->name[0] &&
                    (strstr(cur->name, "linuxrc") || strstr(cur->name, "init")))
                    devel_printf("fork-vfork-share: child=%llu mm_cr3=0x%llx brk=0x%llx-0x%llx\n",
                        (unsigned long long)(child->tid ? child->tid : 1),
                        (unsigned long long)(child->mm->cr3 ? child->mm->cr3 : 0),
                        (unsigned long long)child->user_brk_base,
                        (unsigned long long)child->user_brk_cur);
                fork_dbg(cur, 15, "vfork-share-mm",
                    (unsigned long long)(child->mm->cr3 ? child->mm->cr3 : 0),
                    (unsigned long long)heap_free_bytes(),
                    (unsigned long long)heap_largest_free());
                /*
                 * No stack/brk copying here.  Linux vfork shares the exact mm;
                 * correctness comes from all user leaves having frame-owned
                 * lifetime and from the parent sleeping until exec/_exit.
                 */
            } else {
                if (child->mm)
                    mm_release(child->mm);
                child->mm = mm_dup_user(parent_mm,
                    (uint64_t)(cur->tid ? cur->tid : 1));
                if (!child->mm) {
                    fork_dbg(cur, -4, "dup-mm failed",
                        (unsigned long long)heap_free_bytes(),
                        (unsigned long long)heap_largest_free(), 0);
                    fork_stop_child(child);
                    return ret_err(ENOMEM);
                }

                child->user_fs_base = cur->user_fs_base;
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                child->user_stack_base = cur->user_stack_base ?
                    cur->user_stack_base : (uint64_t)parent_slot_lo;
                child->user_stack_limit = cur->user_stack_limit ?
                    cur->user_stack_limit : (uint64_t)parent_stack_top;
                child->ring = 3;

                if (user_vma_clone_for_tid(
                        (uint64_t)(cur->tid ? cur->tid : 1),
                        (uint64_t)(child->tid ? child->tid : 1))) {
                    fork_stop_child(child);
                    return ret_err(ENOMEM);
                }

                if (child->mm_ptemplate) {
                    mm_release(child->mm_ptemplate);
                    child->mm_ptemplate = NULL;
                }
                mm_switch(parent_mm);
                fork_dbg(cur, 71, "dup-mm",
                    (unsigned long long)child->mm->cr3,
                    (unsigned long long)parent_slot_lo,
                    (unsigned long long)parent_stack_top);
            } /* !share_mm */
            (void)child_slot_lo;
            child->uid = cur->uid;
            child->euid = cur->euid;
            child->suid = cur->suid;
            child->gid = cur->gid;
            child->egid = cur->egid;
            child->sgid = cur->sgid;
            child->ngroups = cur->ngroups;
            if (child->ngroups < 0) child->ngroups = 0;
            if (child->ngroups > AXON_NGROUPS_MAX) child->ngroups = AXON_NGROUPS_MAX;
            if (child->ngroups > 0)
                memcpy(child->groups, cur->groups, (size_t)child->ngroups * sizeof(gid_t));
            child->saved_sig_mask = cur->saved_sig_mask;
            child->sas_ss_sp = cur->sas_ss_sp;
            child->sas_ss_size = cur->sas_ss_size;
            child->sas_ss_flags = cur->sas_ss_flags;
            child->pending_signals = 0;
            child->attached_tty = cur->attached_tty;
            child->parent_tid = (int)(cur->tid ? cur->tid : 1);
            {
                /* BusyBox waitfor() does waitpid(-1) then kill(spawn_pid,0). If the
                 * child is alive but not linked under parent->first_child, wait4
                 * returns ECHILD while kill succeeds — infinite spin. */
                if (!cur->process) {
                    process_t *pp = process_create_init();
                    if (pp)
                        process_attach_thread(pp, cur);
                }
                process_t *child_process = process_create(cur->process);
                if (!child_process) {
                    if (cur->name[0] && strstr(cur->name, "linuxrc"))
                        kprintf("fork-fail: process_create parent_proc=%p\n",
                            (void *)cur->process);
                    fork_stop_child(child);
                    return ret_err(ENOMEM);
                }
                /* Inherit session before attach so process_attach does not
                 * overwrite parent pgid/sid with unset thread zeros. */
                child->sid = cur->sid;
                child->pgid = cur->pgid;
                process_attach_thread(child_process, child);
                child_process->mm = child->mm;
            }
            if (cur->name[0] && strstr(cur->name, "linuxrc")) {
                static int init_fork_parent_dbg_left = 16;
                if (init_fork_parent_dbg_left-- > 0) {
                    devel_printf("fork-parent: cpu=%d parent=%llu child=%llu parent_tid=%d\n",
                        smp_sched_cpu_id(),
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (unsigned long long)(child->tid ? child->tid : 1),
                        child->parent_tid);
                }
            }
            child->clear_child_tid = 0;
            child->sid = cur->sid;
            child->pgid = cur->pgid;
            strncpy(child->cwd, cur->cwd, sizeof(child->cwd) - 1);
            child->cwd[sizeof(child->cwd) - 1] = '\0';
            fork_inherit_fd_table(child, cur);
            process_sync_from_thread(child->process, child);
            thread_proc_env_inherit(child, cur);
            if (!cur->fork_from_clone)
                rebuild_syscall_frame(cur);
            fork_assign_child_return_rip(cur, child);
            /*
             * fork_child_user_rip arms Soft_COW/_Fork identity fixes. Linux
             * vfork already shares mm — leave the marker cleared so
             * syscall-fork-child-wins does not fire on every pre-exec syscall.
             */
            if (share_mm)
                child->fork_child_user_rip = 0;
            /*
             * Linux: wake_up_new_task before copy_process returns. Parent then
             * returns the child's pid (or waits in wait_for_vfork_done for VFORK).
             * Child enters userspace via fork_child_return_entry with rax=0.
             */
            fork_wake_up_new_task(cur, child);
            fork_dbg(cur, 8, "wake_up_new_task",
                (unsigned long long)(cur->tid ? cur->tid : 1),
                (unsigned long long)(child->tid ? child->tid : 1), 0);
            fork_dbg(cur, 9, "return pid",
                (unsigned long long)process_pid(child), 0, 0);
            return process_pid(child);
}

static uint64_t kernel_clone(thread_t *parent,
			     const struct kernel_clone_args *args)
{
	process_t *child_process;
	thread_t *child;
	uint64_t nr;
	uint32_t tid;

	if (!parent || !args)
		return ret_err(EINVAL);
	if ((args->flags & CLONE_SIGHAND) && !(args->flags & CLONE_VM))
		return ret_err(EINVAL);
	if ((args->flags & CLONE_THREAD) &&
	    !(args->flags & CLONE_SIGHAND))
		return ret_err(EINVAL);
	if ((args->flags & CLONE_VFORK) && !(args->flags & CLONE_VM))
		return ret_err(EINVAL);
	if (args->exit_signal < 0 || args->exit_signal > 64)
		return ret_err(EINVAL);
	if ((args->flags & CLONE_PARENT_SETTID) &&
	    !user_range_ok((void *)(uintptr_t)args->parent_tid, sizeof(tid)))
		return ret_err(EFAULT);
	if ((args->flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) &&
	    !user_range_ok((void *)(uintptr_t)args->child_tid, sizeof(tid)))
		return ret_err(EFAULT);
	if (args->flags & CLONE_THREAD)
		return ret_err(EINVAL);

	nr = do_linux_fork(parent, args);
	if ((int64_t)nr < 0)
		return nr;

	child_process = process_find(nr);
	child = child_process ? child_process->leader : NULL;
	if (!child)
		return ret_err(ESRCH);

	tid = (uint32_t)linux_task_tid(child);
	if (args->flags & CLONE_SETTLS)
		child->user_fs_base = args->tls;
	if (args->flags & CLONE_CHILD_CLEARTID)
		child->clear_child_tid = args->child_tid;
	if (args->flags & CLONE_CHILD_SETTID) {
		mm_t *parent_mm = parent->mm ? parent->mm : mm_kernel();

		if (fork_store_child_tid(child, parent_mm, args->child_tid, tid)) {
			if (parent->fork_child_to_publish == child)
				parent->fork_child_to_publish = NULL;
			fork_stop_child(child);
			return ret_err(EFAULT);
		}
	}
	if (args->flags & CLONE_PARENT_SETTID) {
		if (copy_to_user_safe((void *)(uintptr_t)args->parent_tid,
				      &tid, sizeof(tid))) {
			if (parent->fork_child_to_publish == child)
				parent->fork_child_to_publish = NULL;
			fork_stop_child(child);
			return ret_err(EFAULT);
		}
	}

	if (args->flags & CLONE_VFORK) {
		if (!parent->process)
			return ret_err(EINVAL);
		/* Linux: child already woken in do_linux_fork; then parent waits. */
		process_set_vfork_parent(child_process, parent->process);
		parent->vfork_waiting = 1;
		parent->vfork_saved_ret = nr;
		if (!thread_block_current_atomic())
			thread_block((int)(parent->tid ? parent->tid : 1));
	}

	return nr;
}

/* Linux resource numbers used by getrlimit/setrlimit/prlimit64. */
enum {
    RLIMIT_CPU_K = 0,
    RLIMIT_FSIZE_K = 1,
    RLIMIT_DATA_K = 2,
    RLIMIT_STACK_K = 3,
    RLIMIT_CORE_K = 4,
    RLIMIT_RSS_K = 5,
    RLIMIT_NPROC_K = 6,
    RLIMIT_NOFILE_K = 7,
    RLIMIT_MEMLOCK_K = 8,
    RLIMIT_AS_K = 9,
};

static int rlimit_get(thread_t *cur, int resource, uint64_t *soft, uint64_t *hard) {
    process_t *p = cur ? cur->process : NULL;
    uint64_t s = ~0ULL, h = ~0ULL;
    switch (resource) {
        case RLIMIT_STACK_K:
            s = p ? p->rlim_stack_cur : (8ULL * 1024ULL * 1024ULL);
            h = p ? p->rlim_stack_max : s;
            break;
        case RLIMIT_CORE_K:
            s = 0;
            h = ~0ULL;
            break;
        case RLIMIT_NPROC_K:
            s = p ? p->rlim_nproc_cur : 4096ULL;
            h = p ? p->rlim_nproc_max : 4096ULL;
            break;
        case RLIMIT_NOFILE_K:
            s = p ? p->rlim_nofile_cur : PROCESS_RLIMIT_NOFILE_SOFT;
            h = p ? p->rlim_nofile_max : PROCESS_RLIMIT_NOFILE_HARD;
            break;
        case RLIMIT_AS_K:
        case RLIMIT_DATA_K:
        case RLIMIT_RSS_K:
            s = p ? p->rlim_as_cur : ~0ULL;
            h = p ? p->rlim_as_max : ~0ULL;
            break;
        case RLIMIT_CPU_K:
        case RLIMIT_FSIZE_K:
        case RLIMIT_MEMLOCK_K:
            s = h = ~0ULL;
            break;
        default:
            /* Unknown resource: Linux returns EINVAL for get; accept infinity. */
            s = h = ~0ULL;
            break;
    }
    if (soft) *soft = s;
    if (hard) *hard = h;
    return 0;
}

static int rlimit_set(thread_t *cur, int resource, uint64_t soft, uint64_t hard) {
    if (!cur) return EINVAL;
    /* RLIM_INFINITY is ~0ULL; soft must be <= hard when both finite. */
    if (soft != ~0ULL && hard != ~0ULL && soft > hard)
        return EINVAL;
    process_t *p = cur->process;
    if (!p) {
        /* No process struct yet — accept and ignore (early threads). */
        return 0;
    }
    switch (resource) {
        case RLIMIT_STACK_K:
            p->rlim_stack_cur = soft;
            p->rlim_stack_max = hard;
            return 0;
        case RLIMIT_NPROC_K:
            p->rlim_nproc_cur = soft;
            p->rlim_nproc_max = hard;
            return 0;
        case RLIMIT_NOFILE_K:
            /* Store requested limits; open paths still cannot exceed THREAD_MAX_FD. */
            p->rlim_nofile_cur = soft;
            p->rlim_nofile_max = hard;
            return 0;
        case RLIMIT_AS_K:
        case RLIMIT_DATA_K:
        case RLIMIT_RSS_K:
            p->rlim_as_cur = soft;
            p->rlim_as_max = hard;
            return 0;
        case RLIMIT_CORE_K:
        case RLIMIT_CPU_K:
        case RLIMIT_FSIZE_K:
        case RLIMIT_MEMLOCK_K:
            return 0; /* accept, not enforced */
        default:
            return EINVAL;
    }
}

static uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    /* IMPORTANT:
       current_user can be stale if some subsystem (e.g. tty switching) overwrote it.
       Syscalls must be handled for the *currently running* thread. */
    thread_t *cur = syscall_resolve_thread();
    if (!cur) {
        kprintf("SYSCALL-NOCUR: syscall=%llu (no ring3 task)\n", (unsigned long long)num);
        return ret_err(ESRCH);
    }
    /* Keep global current_user synchronized with the actually running user thread.
       Exec/job-control code reads thread_get_current_user(); stale value here can
       put parent and child into the same pgrp and break Ctrl+C behavior. */
    if (cur->ring == 3) {
        thread_set_current_user(cur);
        /* Always run the syscall against the thread's own mm. */
        if (cur->mm)
            mm_switch(cur->mm);
        syscall_bind_kstack_for_thread(cur);
        if (cur->user_fs_base)
            set_user_fs_base(cur->user_fs_base);
    }
    cur->sc_a1 = a1;
    cur->sc_a2 = a2;
    cur->sc_a3 = a3;
    cur->sc_a4 = a4;
    cur->sc_a5 = a5;
    cur->sc_a6 = a6;
    /* saved_user_* are normally captured in syscall_entry64 via syscall_snapshot_user_regs().
       If that path wasn't used (fallback/int0x80), fall back to globals once. */
    /* If return RIP wasn't recorded by entry path, dump stack once for diagnosis. */
    if (cur->saved_user_rip == 0) debug_dump_kernel_syscall_stack();

    /* record last syscall for debug logging of ENOSYS */
    last_syscall_debug = num;

    /* Uncomment if there is some syscall issue — floods the console and
     * hides the shell prompt (ash setjobctl alone is getpgrp/kill/ioctl). */
    /* if (num != 1) kprintf("syscall: num=%llu\n", (unsigned long long)num); */

    switch (num) {
        case SYS_clone: {
            /* Old Linux clone(flags, child_stack, parent_tid, child_tid, tls).
               glibc fork() uses this as a fork-like clone with child_stack == 0
               and no CLONE_VM, but still passes CHILD_SETTID/CLEARTID flags.
               glibc pthread_create uses CLONE_VM|CLONE_THREAD + child_stack. */
            enum {
                CLONE_VM_OLD = 0x00000100u,
                CLONE_FS_OLD = 0x00000200u,
                CLONE_FILES_OLD = 0x00000400u,
                CLONE_SIGHAND_OLD = 0x00000800u,
                CLONE_THREAD_OLD = 0x00010000u,
                CLONE_SYSVSEM_OLD = 0x00040000u,
                CLONE_SETTLS_OLD = 0x00080000u,
                CLONE_PARENT_SETTID_OLD = 0x00100000u,
                CLONE_CHILD_CLEARTID_OLD = 0x00200000u,
                CLONE_CHILD_SETTID_OLD = 0x01000000u
            };
            uint64_t flags = a1;
            uint64_t child_stack = a2;
            uint64_t parent_tid_ptr = a3;
            uint64_t child_tid_ptr = a4;
            uint64_t tls = a5;
            if ((flags & CLONE_SIGHAND_OLD) && !(flags & CLONE_VM_OLD))
                return ret_err(EINVAL);
            if ((flags & CLONE_THREAD_OLD) &&
                !(flags & CLONE_SIGHAND_OLD))
                return ret_err(EINVAL);
            if ((flags & CLONE_PARENT_SETTID_OLD) &&
                !user_range_ok((const void *)(uintptr_t)parent_tid_ptr, 4))
                return ret_err(EFAULT);
            if ((flags & (CLONE_CHILD_SETTID_OLD |
                          CLONE_CHILD_CLEARTID_OLD)) &&
                !user_range_ok((const void *)(uintptr_t)child_tid_ptr, 4))
                return ret_err(EFAULT);

            /* Always log — docker pthread_create is clone(CLONE_VM|THREAD)+stack. */
            {
                static int clone_log_left = 16;
                if (clone_log_left-- > 0)
                    devel_printf("clone: flags=0x%llx stack=0x%llx ptid=0x%llx ctid=0x%llx tls=0x%llx tid=%d\n",
                        (unsigned long long)flags,
                        (unsigned long long)child_stack,
                        (unsigned long long)parent_tid_ptr,
                        (unsigned long long)child_tid_ptr,
                        (unsigned long long)tls,
                        (int)(cur->tid ? cur->tid : 1));
            }

            /* Linux copy_thread(): a CLONE_VM task uses the caller-provided
             * stack in the already shared mm. Never identity-map an assumed
             * 8 MiB span: pthread stacks are ordinary mmap VMAs with guards. */
            if (child_stack != 0 && (flags & CLONE_VM_OLD)) {
                uint64_t saved_rcx = fork_caller_user_rip(cur);
                if (!saved_rcx && cur->saved_syscall_frame)
                    saved_rcx = cur->saved_syscall_frame[13];
                if (!saved_rcx)
                    return ret_err(EINVAL);

                uintptr_t child_rsp = (uintptr_t)child_stack;
                if (child_rsp < 0x1000 || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                    return ret_err(EINVAL);
                uintptr_t stack_lo = child_rsp & ~((uintptr_t)PAGE_SIZE_4K - 1u);
                /*
                 * Linux copy_thread(): use newsp exactly. musl __clone does
                 *   and $-16,%rsi; sub $8,%rsi; mov %arg,(%rsi)
                 * so RSP is 8 mod 16 on entry; the child pops the start arg
                 * then call. Rounding RSP down to 16 bytes drops that slot
                 * and SIGSEGVs in the pthread child (curl DNS worker).
                 *
                 * glibc often passes the exclusive end of the mmap (stack+size).
                 * Prefault that VA can hit the next VMA (Go PROT_NONE) → EFAULT
                 * "pthread_create failed: Bad address". Touch the first slot
                 * below SP, same as SYS_clone3 below.
                 */
                {
                    uint64_t stack_touch = (uint64_t)child_rsp;
                    if (stack_touch >= 8u)
                        stack_touch -= 8u;
                    if (!cur->mm ||
                        clone_ensure_user_va(cur->mm, saved_rcx, 0) != 0 ||
                        clone_ensure_user_va(cur->mm, stack_touch, 1) != 0)
                        return ret_err(EFAULT);
                    if ((flags & CLONE_SETTLS_OLD) && tls >= 0x1000 &&
                        tls < (uint64_t)MMIO_IDENTITY_LIMIT &&
                        clone_ensure_user_va(cur->mm, tls, 1) != 0)
                        return ret_err(EFAULT);
                }

                char child_name[32];
                strncpy(child_name, cur->name, sizeof(child_name) - 1);
                child_name[sizeof(child_name) - 1] = '\0';
                thread_t *child = thread_create_blocked(fork_child_return_entry, child_name);
                if (!child) return ret_err(ENOMEM);
                fpu_thread_fork(cur, child);
                if (child->mm) mm_release(child->mm);
                child->mm = mm_retain(cur->mm ? cur->mm : mm_kernel());

                child->saved_user_r15 = cur->saved_user_r15;
                child->saved_user_r14 = cur->saved_user_r14;
                child->saved_user_r13 = cur->saved_user_r13;
                child->saved_user_r12 = cur->saved_user_r12;
                child->saved_user_r11 = cur->saved_user_r11;
                child->saved_user_r10 = cur->saved_user_r10;
                child->saved_user_r9 = cur->saved_user_r9;
                child->saved_user_r8 = cur->saved_user_r8;
                child->saved_user_rdi = cur->saved_user_rdi;
                child->saved_user_rsi = cur->saved_user_rsi;
                child->saved_user_rbp = cur->saved_user_rbp;
                child->saved_user_rbx = cur->saved_user_rbx;
                child->saved_user_rdx = cur->saved_user_rdx;
                child->saved_user_rcx = saved_rcx;
                child->saved_user_rip = saved_rcx;
                child->saved_user_rsp = (uint64_t)child_rsp;
                child->user_rip = saved_rcx;
                /* snap[13] holds iretq RIP; leave fork_child_user_rip clear so
                 * shared-mm Soft_COW does not treat this pthread like a vfork child. */
                child->fork_child_user_rip = 0;
                /* Linux __clone: fn lives on the new stack; rdx need not be kept.
                 * Still preserve parent GPRs for any caller that expects them. */
                child->clone_preserve_rdx = 0;
                fork_build_gpr_snap_from_thread(child);
                child->fork_gpr_snap[13] = saved_rcx;
                child->fork_gpr_snap[14] = 0;
                child->fork_gpr_snap[15] = (uint64_t)child_rsp;

                child->user_stack = (uint64_t)child_rsp;
                child->user_stack_base = (uint64_t)stack_lo;
                child->user_stack_limit = (uint64_t)child_rsp;
                child->ring = 3;

                /*
                 * Linux copy_process/CLONE_SETTLS: only install the child's
                 * FS base. The TCB lives in the caller-provided pthread stack
                 * (already mmap'd). Stamping identity US/RW over that range
                 * re-shared Soft_COW/identity leaves into a private stack and
                 * musl's child then SIGSEGVs on the first TCB store.
                 */
                if ((flags & CLONE_SETTLS_OLD) && tls >= 0x1000 &&
                    tls < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    child->user_fs_base = tls;
                } else {
                    child->user_fs_base = cur->user_fs_base;
                }

                child->uid = cur->uid;
                child->euid = cur->euid;
                child->suid = cur->suid;
                child->gid = cur->gid;
                child->egid = cur->egid;
                child->sgid = cur->sgid;
                child->ngroups = cur->ngroups;
                if (child->ngroups < 0) child->ngroups = 0;
                if (child->ngroups > AXON_NGROUPS_MAX) child->ngroups = AXON_NGROUPS_MAX;
                if (child->ngroups > 0)
                    memcpy(child->groups, cur->groups, (size_t)child->ngroups * sizeof(gid_t));
                child->umask = cur->umask;
                child->attached_tty = cur->attached_tty;
                child->parent_tid = (int)(cur->tid ? cur->tid : 1);
                child->saved_sig_mask = cur->saved_sig_mask;
                child->sas_ss_sp = 0;
                child->sas_ss_size = 0;
                child->sas_ss_flags = SS_DISABLE;
                /* CLONE_THREAD: same process / signal handlers (Linux tgid). */
                if (flags & CLONE_THREAD_OLD) {
                    if (!cur->process) {
                        process_t *pp = process_create_init();
                        if (pp) process_attach_thread(pp, cur);
                    }
                    if (cur->process) {
                        if (!cur->process->leader)
                            process_attach_thread(cur->process, cur);
                        process_attach_thread(cur->process, child);
                    } else {
                        child->process = NULL;
                    }
                    child->sid = cur->sid;
                    child->pgid = cur->pgid;
                } else {
                    if (!cur->process) {
                        process_t *pp = process_create_init();
                        if (pp) process_attach_thread(pp, cur);
                    }
                    process_t *child_process = process_create(cur->process);
                    if (!child_process) {
                        thread_stop((int)(child->tid ? child->tid : 1));
                        return ret_err(ENOMEM);
                    }
                    process_attach_thread(child_process, child);
                    child->sid = cur->sid;
                    child->pgid = cur->pgid;
                }
                strncpy(child->cwd, cur->cwd, sizeof(child->cwd) - 1);
                child->cwd[sizeof(child->cwd) - 1] = '\0';
                /*
                 * CLONE_THREAD: do NOT process_sync_from_thread(leader) here.
                 * That copied leader->fds over the shared process table and
                 * wiped UDP DNS sockets opened by earlier workers (leader
                 * slots stay NULL). Orphaned ksocks stayed in the registry
                 * and stole the next curl's replies (error 6); mid-download
                 * loss truncated bash -c "$(curl …)" → syntax error near fi.
                 * fork_inherit still refcounts onto the child thread slots.
                 */
                fork_inherit_fd_table(child, cur);
                if (!(flags & CLONE_THREAD_OLD))
                    process_sync_from_thread(child->process, child);
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                {
                    /* mmap owns the pthread stack VMA/cursor. clone must not
                     * move the process mmap cursor based on a guessed span. */
                }

                uint32_t child_user_tid = (uint32_t)linux_task_tid(child);
                if ((flags & CLONE_PARENT_SETTID_OLD) &&
                    user_range_ok((const void *)(uintptr_t)parent_tid_ptr, 4)) {
                    (void)copy_to_user_safe((void *)(uintptr_t)parent_tid_ptr,
                                            &child_user_tid, 4);
                }
                if ((flags & CLONE_CHILD_SETTID_OLD) &&
                    user_range_ok((const void *)(uintptr_t)child_tid_ptr, 4)) {
                    (void)copy_to_user_safe((void *)(uintptr_t)child_tid_ptr,
                                            &child_user_tid, 4);
                }
                if ((flags & CLONE_CHILD_CLEARTID_OLD) &&
                    user_range_ok((const void *)(uintptr_t)child_tid_ptr, 4)) {
                    child->clear_child_tid = child_tid_ptr;
                }

                rebuild_syscall_frame(cur);
                if (flags & CLONE_THREAD_OLD) {
                    cur->fork_child_to_publish = child;
                } else {
                    thread_unblock((int)(child->tid ? child->tid : 1));
                }
                {
                    static int clone_ok_left = 8;
                    if (clone_ok_left-- > 0)
                        devel_printf("clone-ok: child_tid=%u rip=0x%llx rsp=0x%llx fs=0x%llx\n",
                            (unsigned)child_user_tid,
                            (unsigned long long)saved_rcx,
                            (unsigned long long)child_rsp,
                            (unsigned long long)child->user_fs_base);
                }
                return (uint64_t)child_user_tid;
            }

            {
                uint64_t clone_ret_rip =
                    (cur->saved_syscall_frame && cur->saved_syscall_frame[13])
                        ? cur->saved_syscall_frame[13]
                        : (cur->syscall_frame_kbuf ? cur->syscall_frame_kbuf[13] : 0);
                struct kernel_clone_args args = {
                    .flags = flags & ~0xffULL,
                    .parent_tid = parent_tid_ptr,
                    .child_tid = child_tid_ptr,
                    .tls = tls,
                    .exit_signal = (int)(flags & 0xff),
                };
                uint64_t nr;

                if (!clone_ret_rip)
                    return ret_err(EINVAL);

                cur->fork_from_clone = 1;
                cur->fork_child_trap_rip = clone_ret_rip;
                nr = kernel_clone(cur, &args);
                cur->fork_from_clone = 0;
                if ((int64_t)nr >= 0) {
                    process_t *process = process_find(nr);
                    thread_t *child = process ? process->leader : NULL;

                    if (child)
                        child->clone_preserve_rdx = 0;
                }
                return nr;
            }
        }
        case SYS_clone3: {
            /* clone3(cl_args, size) - glibc pthreads passes user stack; must use it or advise_stack_range assert fails */
            const void *cl_args_u = (const void*)(uintptr_t)a1;
            size_t cl_size = (size_t)a2;
            if (!cl_args_u || cl_size < 64 || (uintptr_t)cl_args_u + 64 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            uint64_t cl_buf[8];
            if (copy_from_user_raw(cl_buf, cl_args_u, 64) != 0) return ret_err(EFAULT);
            uint64_t flags = cl_buf[0];
            uint64_t child_tid_ptr = cl_buf[2];
            uint64_t parent_tid_ptr = cl_buf[3];
            uint64_t exit_signal = cl_buf[4];
            uint64_t stack = cl_buf[5];
            uint64_t stack_size = cl_buf[6];
            uint64_t tls = cl_buf[7];
            uint64_t saved_rcx = fork_caller_user_rip(cur);
            if (saved_rcx == 0) return ret_err(EINVAL);
            enum {
                CLONE3_CLONE_VM = 0x00000100u,
                CLONE3_CLONE_SIGHAND = 0x00000800u,
                CLONE3_CLONE_THREAD = 0x00010000u,
                CLONE3_CLONE_SETTLS = 0x00080000u,
                CLONE3_PARENT_SETTID = 0x00100000u,
                CLONE3_CHILD_CLEARTID = 0x00200000u,
                CLONE3_CHILD_SETTID = 0x01000000u
            };
            if ((flags & CLONE3_CLONE_SIGHAND) &&
                !(flags & CLONE3_CLONE_VM))
                return ret_err(EINVAL);
            if ((flags & CLONE3_CLONE_THREAD) &&
                !(flags & CLONE3_CLONE_SIGHAND))
                return ret_err(EINVAL);
            if ((flags & CLONE3_PARENT_SETTID) &&
                !user_range_ok((const void *)(uintptr_t)parent_tid_ptr, 4))
                return ret_err(EFAULT);
            if ((flags & (CLONE3_CHILD_SETTID |
                          CLONE3_CHILD_CLEARTID)) &&
                !user_range_ok((const void *)(uintptr_t)child_tid_ptr, 4))
                return ret_err(EFAULT);
            /* pthread clone3 uses an mmap-owned stack in the shared mm. */
            if (stack != 0 && (flags & CLONE3_CLONE_VM)) {
                clone3_dbg(cur, 1, "enter",
                    (unsigned long long)flags,
                    (unsigned long long)stack,
                    (unsigned long long)stack_size);
                /*
                 * Linux clone3: stack = lowest byte of the mapping; stack_size =
                 * length. Kernel sets initial RSP to stack+stack_size.
                 */
                if (stack_size == 0)
                    return ret_err(EINVAL);
                uintptr_t stack_lo = (uintptr_t)stack;
                if (stack_lo < 0x1000 || stack_lo >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                    return ret_err(EINVAL);
                if (stack_size > (uint64_t)((uintptr_t)MMIO_IDENTITY_LIMIT - stack_lo))
                    return ret_err(EINVAL);
                uintptr_t child_rsp = stack_lo + (uintptr_t)stack_size;
                if (child_rsp <= stack_lo || child_rsp > (uintptr_t)MMIO_IDENTITY_LIMIT)
                    return ret_err(EINVAL);
                /* Linux clone3: sp = stack + stack_size, no kernel re-align. */
                if (child_rsp <= stack_lo || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                    return ret_err(EINVAL);

                {
                    if (!cur->mm ||
                        clone_ensure_user_va(cur->mm, saved_rcx, 0) != 0 ||
                        clone_ensure_user_va(cur->mm, (uint64_t)child_rsp - 8u, 1) != 0)
                        return ret_err(EFAULT);
                    if ((flags & CLONE3_CLONE_SETTLS) &&
                        (tls < 0x1000u ||
                         clone_ensure_user_va(cur->mm, tls, 0) != 0))
                        return ret_err(EFAULT);
                }
                char child_name[32];
                strncpy(child_name, cur->name, sizeof(child_name) - 1);
                child_name[sizeof(child_name) - 1] = '\0';
                thread_t *child = thread_create_blocked(fork_child_return_entry, child_name);
                if (!child) return ret_err(ENOMEM);
                fpu_thread_fork(cur, child);
                if (child->mm) mm_release(child->mm);
                child->mm = mm_retain(cur->mm ? cur->mm : mm_kernel());
                clone3_dbg(cur, 2, "child created",
                    (unsigned long long)(child->tid ? child->tid : 0),
                    (unsigned long long)saved_rcx,
                    (unsigned long long)saved_rcx);
                child->saved_user_r15 = cur->saved_user_r15;
                child->saved_user_r14 = cur->saved_user_r14;
                child->saved_user_r13 = cur->saved_user_r13;
                child->saved_user_r12 = cur->saved_user_r12;
                child->saved_user_r11 = cur->saved_user_r11;
                child->saved_user_r10 = cur->saved_user_r10;
                child->saved_user_r9 = cur->saved_user_r9;
                child->saved_user_r8 = cur->saved_user_r8;
                child->saved_user_rdi = cur->saved_user_rdi;
                child->saved_user_rsi = cur->saved_user_rsi;
                child->saved_user_rbp = cur->saved_user_rbp;
                child->saved_user_rbx = cur->saved_user_rbx;
                child->saved_user_rdx = cur->saved_user_rdx;
                child->saved_user_rcx = saved_rcx;
                child->saved_user_rip = saved_rcx;
                child->saved_user_rsp = (uint64_t)child_rsp;
                child->user_rip = saved_rcx;
                child->fork_child_user_rip = 0;
                /* glibc clone3.S: call *%rdx with start_routine. */
                child->clone_preserve_rdx = 1;
                fork_build_gpr_snap_from_thread(child);
                child->fork_gpr_snap[13] = saved_rcx;
                child->fork_gpr_snap[14] = 0;
                child->fork_gpr_snap[15] = (uint64_t)child_rsp;
                clone3_dbg(cur, 3, "return-frame",
                    (unsigned long long)saved_rcx,
                    (unsigned long long)child_rsp,
                    (unsigned long long)flags);
                child->user_stack = (uint64_t)child_rsp;
                child->user_stack_base = (uint64_t)stack_lo;
                child->user_stack_limit = (uint64_t)child_rsp;
                child->ring = 3;
                child->saved_sig_mask = cur->saved_sig_mask;
                child->sas_ss_sp = 0;
                child->sas_ss_size = 0;
                child->sas_ss_flags = SS_DISABLE;
                if ((flags & CLONE3_CLONE_SETTLS) && tls != 0 &&
                    tls >= 0x1000 && tls < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    child->user_fs_base = tls;
                } else {
                    child->user_fs_base = cur->user_fs_base;
                }
                child->uid = cur->uid;
                child->euid = cur->euid;
                child->suid = cur->suid;
                child->gid = cur->gid;
                child->egid = cur->egid;
                child->sgid = cur->sgid;
                child->ngroups = cur->ngroups;
                if (child->ngroups < 0) child->ngroups = 0;
                if (child->ngroups > AXON_NGROUPS_MAX) child->ngroups = AXON_NGROUPS_MAX;
                if (child->ngroups > 0)
                    memcpy(child->groups, cur->groups, (size_t)child->ngroups * sizeof(gid_t));
                child->umask = cur->umask;
                child->attached_tty = cur->attached_tty;
                child->parent_tid = (int)(cur->tid ? cur->tid : 1);
                /* Linux: CLONE_THREAD shares TGID; otherwise new process. */
                if (flags & CLONE3_CLONE_THREAD) {
                    if (!cur->process) {
                        process_t *pp = process_create_init();
                        if (pp) process_attach_thread(pp, cur);
                    }
                    if (cur->process) {
                        if (!cur->process->leader)
                            process_attach_thread(cur->process, cur);
                        process_attach_thread(cur->process, child);
                    } else {
                        child->process = NULL;
                    }
                    child->sid = cur->sid;
                    child->pgid = cur->pgid;
                } else {
                    if (!cur->process) {
                        process_t *pp = process_create_init();
                        if (pp) process_attach_thread(pp, cur);
                    }
                    process_t *child_process = process_create(cur->process);
                    if (!child_process) {
                        thread_stop((int)(child->tid ? child->tid : 1));
                        return ret_err(ENOMEM);
                    }
                    process_attach_thread(child_process, child);
                    child->sid = cur->sid;
                    child->pgid = cur->pgid;
                }
                strncpy(child->cwd, cur->cwd, sizeof(child->cwd)-1);
                child->cwd[sizeof(child->cwd)-1] = '\0';
                /* See clone(): never sync leader→process on CLONE_THREAD. */
                fork_inherit_fd_table(child, cur);
                if (!(flags & CLONE3_CLONE_THREAD))
                    process_sync_from_thread(child->process, child);
                /* Shared mm (CLONE_VM): inherit brk/mmap state so child mmap doesn't overwrite parent's regions. */
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                /* clone3 semantics: touch TID pointers only when the matching flags are set. */
                uint32_t child_tid = (uint32_t)linux_task_tid(child);
                if (flags & CLONE3_PARENT_SETTID) {
                    copy_to_user_safe((void*)(uintptr_t)parent_tid_ptr,
                                      &child_tid, 4);
                }
                if (flags & CLONE3_CHILD_SETTID) {
                    copy_to_user_safe((void*)(uintptr_t)child_tid_ptr,
                                      &child_tid, 4);
                }
                if (flags & CLONE3_CHILD_CLEARTID) {
                    child->clear_child_tid = child_tid_ptr;
                }
                rebuild_syscall_frame(cur);
                {
                    int ctid = (int)(child->tid ? child->tid : 1);
                    /* CLONE_VM harness path: unblock now (per-thread syscall stacks). */
                    if (flags & CLONE3_CLONE_THREAD) {
                        cur->fork_child_to_publish = child;
                        clone3_dbg(cur, 4, "defer child",
                            (unsigned long long)ctid,
                            (unsigned long long)child->user_rip,
                            (unsigned long long)child->user_stack);
                    } else {
                        thread_unblock(ctid);
                        clone3_dbg(cur, 4, "unblock child",
                            (unsigned long long)ctid,
                            (unsigned long long)child->user_rip,
                            (unsigned long long)child->user_stack);
                    }
                }
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            {
                uint64_t clone3_ret_rip =
                    (cur->saved_syscall_frame && cur->saved_syscall_frame[13])
                        ? cur->saved_syscall_frame[13]
                        : (cur->syscall_frame_kbuf ? cur->syscall_frame_kbuf[13] : 0);
                struct kernel_clone_args args = {
                    .flags = flags,
                    .parent_tid = parent_tid_ptr,
                    .child_tid = child_tid_ptr,
                    .tls = tls,
                    .exit_signal = (int)exit_signal,
                };
                uint64_t nr;

                if (clone3_ret_rip == 0) return ret_err(EINVAL);
                cur->fork_from_clone = 1;
                cur->fork_child_trap_rip = clone3_ret_rip;
                nr = kernel_clone(cur, &args);
                cur->fork_from_clone = 0;
                if ((int64_t)nr >= 0) {
                    process_t *process = process_find(nr);
                    thread_t *child = process ? process->leader : NULL;

                    if (child)
                        child->clone_preserve_rdx = 0;
                }
                return nr;
            }
        }
        case SYS_set_tid_address: {
            /* set_tid_address(int *tidptr): used by glibc to set clear_child_tid. */
            uint64_t tidptr = a1;
            if (tidptr != 0) {
                if (!user_range_ok((const void *)(uintptr_t)tidptr, 4)) return ret_err(EFAULT);
                cur->clear_child_tid = tidptr;
            }
            return linux_task_tid(cur);
        }
        case SYS_vfork: {
            struct kernel_clone_args args = {
                .flags = CLONE_VFORK | CLONE_VM,
                .exit_signal = SIGCHLD,
            };

            return kernel_clone(cur, &args);
#if 0
            /* Old in-syscall wait loop — unsafe. */
            return syscall_do_inner(SYS_fork, 0, 0, 0, 0, 0, 0);
            /* Minimal vfork semantics:
               - create child thread that shares parent's address space and fds
               - parent is blocked until child calls execve or exit
               - parent returns child's pid, child returns 0
             */
            thread_t *p = cur;
            if (!p) return ret_err(EINVAL);
            /* Read saved return RIP and user RSP saved by syscall_entry64.
               The assembly syscall entry writes the saved return RIP into
               global `syscall_saved_ret_rip` for reliable access from C. */
            /* prefer recorded user return RIP (works for both int0x80 and SYSCALL paths) */
            uint64_t saved_rcx = p->saved_user_rip;
            uint64_t saved_rsp = p->saved_user_rsp;

            /* If we still don't have a valid saved_rcx at this point, fail early. */
            if (saved_rcx == 0) {
                return ret_err(EINVAL);
            }
            /* Try to ensure the user pages around saved_rcx are user-accessible to avoid PF
               when the child enters user mode. This sets PG_US on the containing 2MiB region. */
            if (saved_rcx != 0) {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) == 0) {
                } else {
                    /* If we cannot make the candidate return site user-accessible, refuse vfork
                       rather than heuristically using an unmapped/privileged address which
                       leads to immediate #PF err=0x5 when the child enters user mode. */
                    qemu_debug_printf("vfork: aborting due to unmapped/privileged saved return site\n");
                    return ret_err(EINVAL);
                }
                /* Also try to broadly ensure common user ranges are user-accessible (helps when writes hit elsewhere). */
                (void)user_map_ensure_present_us_2m(0x10000, 0x200000);
                if (mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP) == 0) {
                } else {
                }
            }
            // kprintf("DBG: vfork: syscall_user_return_rip=0x%llx syscall_user_rsp_saved=0x%llx (saved_rcx=0x%llx saved_rsp=0x%llx)\n",
            //         (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved,
            //         (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* vfork semantics for AxonOS (safe variant):
               - create child thread, but do NOT run it on the parent's stack
               - copy active portion of parent's stack into a dedicated child stack
               - parent is NOT blocked in-kernel (avoids returning from a blocked syscall frame)
               This behaves closer to fork(), but avoids the post-exit #GP caused by
               corruption of the parent's syscall frame while it is blocked in-kernel. */
            if (saved_rcx == 0) {
                /* cannot create child if we don't have return site */
                return ret_err(EINVAL);
            }
            /* create child kernel thread that will enter user mode at user_thread_entry.
               Create it BLOCKED first to avoid it running before we finish initializing
               user_rip/user_stack/user_fs_base (race became visible once we added an always-READY idle thread). */
            thread_t *child = thread_create_blocked(user_thread_entry, "vfork-child");
            if (!child) return ret_err(ENOMEM);
            /* initialize child's user context and inherit parent's FDs/credentials */
            /* Create a small user-mode trampoline that zeroes RAX and jumps to saved_rcx.
               This avoids executing user code directly in an unknown register/stack snapshot. */
            {
                /* ---- clone parent's active stack slice into child's own stack ---- */
                uintptr_t parent_fs = (uintptr_t)p->user_fs_base;
                uintptr_t parent_tls_region = (parent_fs >= 0x1000u) ? (parent_fs - 0x1000u) : 0;
                if ((uintptr_t)saved_rsp == 0 || (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    return ret_err(EINVAL);
                }
                uintptr_t max_copy = (uintptr_t)USER_STACK_SIZE;
                if (max_copy > (uintptr_t)(1024 * 1024)) max_copy = (uintptr_t)(1024 * 1024);
                uintptr_t avail = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
                uintptr_t copy_bytes = (avail < max_copy) ? avail : max_copy;
                if (copy_bytes < 256) {
                    return ret_err(EINVAL);
                }

                /* pick child's stack_top based on child tid to avoid overlap */
                uintptr_t child_stack_top = (uintptr_t)USER_STACK_TOP;
                /* reuse the same layout helper as exec uses: stack_top = tls + sizes */
                {
                    extern uintptr_t user_stack_top_for_tid(uint64_t tid); /* in core/elf.c (static), can't call */
                    (void)user_stack_top_for_tid;
                }
                /* We can't call elf.c static helper here, so derive stack_top from parent's
                   canonical layout by using child's tls base region below USER_STACK_TOP:
                   stack_top = USER_STACK_TOP - (tid+1)*stride. Keep stride in sync with elf.c. */
                {
                    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
                    const uint64_t slot = (uint64_t)child->tid + 1ULL;
                    /* Avoid overflow and avoid (off + 0x10000) wrap. If tid is out of range, use top slot. */
                    if (stride != 0 && slot <= (uint64_t)((uintptr_t)-1) / (uint64_t)stride) {
                        const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
                        const uintptr_t top = (uintptr_t)USER_STACK_TOP;
                        const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
                        if (top > min_room && off < (top - min_room)) {
                            child_stack_top = (uintptr_t)USER_STACK_TOP - off;
                        }
                    }
                }
                child_stack_top &= ~((uintptr_t)0xFULL);
                uintptr_t child_rsp = (child_stack_top - copy_bytes);
                uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(p->tid ? p->tid : 1);
                const uintptr_t parent_slot_lo =
                    (parent_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                const uintptr_t child_slot_lo =
                    (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                /* Preserve original stack alignment (SSE movdqa expects this). */
                uintptr_t align_mask = (uintptr_t)0xFULL;
                uintptr_t want = (uintptr_t)saved_rsp & align_mask;
                uintptr_t have = (uintptr_t)child_rsp & align_mask;
                if (have != want) {
                    child_rsp += (want - have) & align_mask;
                }

                /* ensure child stack region is user-accessible */
                {
                    uintptr_t sb = (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                    if (mark_user_identity_range_2m_sys((uint64_t)sb, (uint64_t)child_stack_top) != 0) {
                        return ret_err(EFAULT);
                    }
                }
                /* copy active stack slice */
                memcpy((void*)child_rsp, (void*)(uintptr_t)saved_rsp, (size_t)copy_bytes);
                {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = 0;
                        if (user_read_u64((const void *)(uintptr_t)pp, &v) != 0) return ret_err(EFAULT);
                        uint64_t nv = fork_reloc_user_ptr(v, parent_lo, parent_hi,
                            (uintptr_t)child_rsp, parent_slot_lo, parent_stack_top, child_slot_lo);
                        if (nv != v && user_write_u64((void *)(uintptr_t)pp, nv) != 0)
                            return ret_err(EFAULT);
                    }
                }

                /* ---- set up separate TLS (copy 4KiB from parent) ---- */
                uintptr_t child_tls_region = child_stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
                /* Use same layout as exec: FS base inside region, fake pthread on next page. */
                uintptr_t child_fs = child_tls_region + 0x1000u;
                uintptr_t child_pthread_fake = child_tls_region + 0x2000u;
                if (mark_user_identity_range_2m_sys((uint64_t)child_tls_region, (uint64_t)(child_pthread_fake + 0x1000u)) != 0) {
                    return ret_err(EFAULT);
                }
                /* clear/clone minimal TLS layout (3 pages) */
                memset((void*)child_tls_region, 0, 0x3000u);
                if (parent_tls_region != 0 && parent_tls_region + 0x3000u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy((void*)child_tls_region, (void*)parent_tls_region, 0x3000u);
                } else {
                    /* already zeroed */
                }
                fork_seed_glibc_tls(child_tls_region, child_fs, child_pthread_fake);
                /* Ensure the self pointer slot used by glibc pthread_getspecific is valid. */
                if (user_write_u64((void *)(uintptr_t)(child_fs - 0x78u), (uint64_t)child_pthread_fake) != 0)
                    return ret_err(EFAULT);
                /* Provide default "C" locale string for specifics[5] (see core/elf.c). */
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        if (user_write_u8((void *)(uintptr_t)(c_str + 0), (uint8_t)'C') != 0) return ret_err(EFAULT);
                        if (user_write_u8((void *)(uintptr_t)(c_str + 1), 0) != 0) return ret_err(EFAULT);
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        /* The TLS region may have been cloned from parent and contain garbage/non-canonical
                           pointers in the specifics area. Clear a small window and force slot 5. */
                        for (int si = 0; si < 32; si++) {
                            if (user_write_u64((void *)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)), 0) != 0)
                                return ret_err(EFAULT);
                        }
                        if (user_write_u64((void *)(uintptr_t)specific5_slot, (uint64_t)c_str) != 0)
                            return ret_err(EFAULT);
                    }
                }
                child->user_fs_base = (uint64_t)child_fs;

                uintptr_t tramp = (uintptr_t)USER_VFORK_TRAMP;
                /* ensure tramp region is user-accessible */
                mark_user_identity_range_2m_sys((uint64_t)(tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))),
                                               (uint64_t)((tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))) + PAGE_SIZE_2M));
                if ((uintptr_t)tramp + 64 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    #define VFORK_RELOC(val64) \
                        fork_reloc_user_ptr((uint64_t)(val64), parent_lo, parent_hi, \
                            (uintptr_t)child_rsp, parent_slot_lo, parent_stack_top, child_slot_lo)
                    /* Build a vfork trampoline that restores a full user register snapshot
                       (as if we returned from a real SYSCALL instruction):
                         - restore caller-saved regs: RDI,RSI,RDX,R8,R9,R10,RCX,R11
                         - restore callee-saved regs: RBX,RBP,R12-R15
                         - set RAX=0 (vfork return value in child)
                         - set RSP=saved stack
                         - jump to RCX (return RIP) */
                    unsigned char stub[160];
                    int off = 0;
                    /* movabs rdi, imm64 */
                    uint64_t imm_rdi = VFORK_RELOC(p->saved_user_rdi);
                    stub[off++] = 0x48; stub[off++] = 0xBF; memcpy(&stub[off], &imm_rdi, 8); off += 8;
                    /* movabs rsi, imm64 */
                    uint64_t imm_rsi = VFORK_RELOC(p->saved_user_rsi);
                    stub[off++] = 0x48; stub[off++] = 0xBE; memcpy(&stub[off], &imm_rsi, 8); off += 8;
                    /* movabs rdx, imm64 */
                    uint64_t imm_rdx = VFORK_RELOC(p->saved_user_rdx);
                    stub[off++] = 0x48; stub[off++] = 0xBA; memcpy(&stub[off], &imm_rdx, 8); off += 8;
                    /* movabs r8, imm64 */
                    uint64_t imm_r8 = VFORK_RELOC(p->saved_user_r8);
                    stub[off++] = 0x49; stub[off++] = 0xB8; memcpy(&stub[off], &imm_r8, 8); off += 8;
                    /* movabs r9, imm64 */
                    uint64_t imm_r9 = VFORK_RELOC(p->saved_user_r9);
                    stub[off++] = 0x49; stub[off++] = 0xB9; memcpy(&stub[off], &imm_r9, 8); off += 8;
                    /* movabs r10, imm64 */
                    uint64_t imm_r10 = VFORK_RELOC(p->saved_user_r10);
                    stub[off++] = 0x49; stub[off++] = 0xBA; memcpy(&stub[off], &imm_r10, 8); off += 8;
                    /* movabs rcx, imm64 (return RIP) */
                    uint64_t imm_rcx = (uint64_t)saved_rcx;
                    stub[off++] = 0x48; stub[off++] = 0xB9; memcpy(&stub[off], &imm_rcx, 8); off += 8;
                    /* movabs r11, imm64 (saved RFLAGS from SYSCALL) */
                    uint64_t imm_r11_flags = p->saved_user_r11;
                    stub[off++] = 0x49; stub[off++] = 0xBB; memcpy(&stub[off], &imm_r11_flags, 8); off += 8;
                    /* movabs rbx, imm64 */
                    uint64_t imm_rbx = VFORK_RELOC(p->saved_user_rbx);
                    stub[off++] = 0x48; stub[off++] = 0xBB; memcpy(&stub[off], &imm_rbx, 8); off += 8;
                    /* movabs rbp, imm64 */
                    uint64_t imm_rbp = VFORK_RELOC(p->saved_user_rbp);
                    stub[off++] = 0x48; stub[off++] = 0xBD; memcpy(&stub[off], &imm_rbp, 8); off += 8;
                    /* movabs r12, imm64 */
                    uint64_t imm_r12 = VFORK_RELOC(p->saved_user_r12);
                    stub[off++] = 0x49; stub[off++] = 0xBC; memcpy(&stub[off], &imm_r12, 8); off += 8;
                    /* movabs r13, imm64 */
                    uint64_t imm_r13 = VFORK_RELOC(p->saved_user_r13);
                    stub[off++] = 0x49; stub[off++] = 0xBD; memcpy(&stub[off], &imm_r13, 8); off += 8;
                    /* movabs r14, imm64 */
                    uint64_t imm_r14 = VFORK_RELOC(p->saved_user_r14);
                    stub[off++] = 0x49; stub[off++] = 0xBE; memcpy(&stub[off], &imm_r14, 8); off += 8;
                    /* movabs r15, imm64 */
                    uint64_t imm_r15 = VFORK_RELOC(p->saved_user_r15);
                    stub[off++] = 0x49; stub[off++] = 0xBF; memcpy(&stub[off], &imm_r15, 8); off += 8;
                    /* xor rax, rax -> return value 0 in child */
                    stub[off++] = 0x48; stub[off++] = 0x31; stub[off++] = 0xC0;
                    /* movabs rsp, saved_rsp -> 48 BC imm64 */
                    uint64_t imm_rsp = (uint64_t)child_rsp;
                    stub[off++] = 0x48; stub[off++] = 0xBC; memcpy(&stub[off], &imm_rsp, 8); off += 8;
                    /* jmp rcx -> FF E1 */
                    stub[off++] = 0xFF; stub[off++] = 0xE1;
                    #undef VFORK_RELOC
                    /* pad with NOPs */
                    for (int z = off; z < (int)sizeof(stub); z++) stub[z] = 0x90;
                    memcpy((void*)(uintptr_t)tramp, stub, (size_t)off);
                    /* Read back bytes to verify write succeeded */
                    unsigned char verify[16];
                    memcpy(verify, (void*)(uintptr_t)tramp, sizeof(verify));
                    child->user_rip = (uint64_t)tramp;
                } else {
                    /* fallback: use saved_rcx if tramp can't be used */
                    child->user_rip = saved_rcx;
                }
                child->user_stack = (uint64_t)child_rsp;
                child->user_stack_base = (uint64_t)((child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL);
                child->user_stack_limit = (uint64_t)child_stack_top;
                child->ring = 3;
            }
            child->parent_tid = (int)(p->tid ? p->tid : 1);
            child->sid = p->sid;
            child->pgid = p->pgid;
            child->uid = p->uid; child->euid = p->euid; child->suid = p->suid;
            child->gid = p->gid; child->egid = p->egid; child->sgid = p->sgid;
            child->ngroups = p->ngroups;
            if (child->ngroups < 0) child->ngroups = 0;
            if (child->ngroups > AXON_NGROUPS_MAX) child->ngroups = AXON_NGROUPS_MAX;
            if (child->ngroups > 0)
                memcpy(child->groups, p->groups, (size_t)child->ngroups * sizeof(gid_t));
            child->attached_tty = p->attached_tty;
            strncpy(child->cwd, p->cwd, sizeof(child->cwd) - 1);
            child->cwd[sizeof(child->cwd) - 1] = '\0';
            qemu_debug_printf("vfork: parent=%llu child=%llu saved_rcx=0x%llx saved_rsp=0x%llx\n",
                (unsigned long long)(p->tid ? p->tid : 1),
                (unsigned long long)(child->tid ? child->tid : 1),
                (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            child->vfork_parent_mem_backup = NULL;
            child->vfork_parent_stack_backup = NULL;
            /* duplicate file descriptors (increase refcounts) */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                child->fds[i] = p->fds[i];
                if (child->fds[i]) {
                    if (child->fds[i]->refcount <= 0) child->fds[i]->refcount = 1;
                    else child->fds[i]->refcount++;
                }
            }
            qemu_debug_printf("vfork: defer child %llu\n",
                (unsigned long long)(child->tid ? child->tid : 1));
            cur->fork_child_to_publish = child;
            return (uint64_t)(child->tid ? child->tid : 1);
#endif
        }
        case SYS_set_robust_list: {
            thread_t *tcur = cur;
            if (tcur && tcur->name[0] && strstr(tcur->name, "linuxrc")) {
                static int linuxrc_robust_enter_left = 24;
                if (linuxrc_robust_enter_left-- > 0)
                    devel_printf("robust-enter: tid=%llu head=0x%llx len=%llu owner=%llu\n",
                        (unsigned long long)(tcur->tid ? tcur->tid : 1),
                        (unsigned long long)a1,
                        (unsigned long long)a2,
                        (unsigned long long)(thread_current() && thread_current()->tid
                            ? thread_current()->tid : 0));
            }
            if (a2 < 24 || a2 > 4096) return ret_err(EINVAL);
            if (a1 && !user_range_ok((const void *)(uintptr_t)a1, (size_t)a2)) return ret_err(EFAULT);
            if (tcur) {
                tcur->robust_list_head = a1;
                tcur->robust_list_len = (uint32_t)a2;
            }
            /*
             * glibc _Fork / BusyBox after set_robust_list: mov %edx,%eax; ret.
             * Zero edx for Soft_COW fork markers and for Linux vfork children
             * (shared mm) — otherwise the child takes the parent path.
             */
            if (tcur && (tcur->fork_child_user_rip ||
                         (tcur->process && tcur->process->vfork_parent_blocked))) {
                tcur->saved_user_rdx = 0;
                if (tcur->saved_syscall_frame)
                    tcur->saved_syscall_frame[12] = 0;
                if (tcur->syscall_frame_kbuf)
                    tcur->syscall_frame_kbuf[12] = 0;
            }
            if (tcur && tcur->name[0] && strstr(tcur->name, "linuxrc")) {
                static int linuxrc_robust_done_left = 24;
                if (linuxrc_robust_done_left-- > 0)
                    devel_printf("robust-done: tid=%llu\n",
                        (unsigned long long)(tcur->tid ? tcur->tid : 1));
            }
            return 0;
        }
        case SYS_get_robust_list: {
            thread_t *tcur = cur;
            if (!tcur) return ret_err(ESRCH);
            if (a1) {
                uint64_t head = tcur->robust_list_head;
                if (copy_to_user_safe((void *)(uintptr_t)a1, &head, sizeof(head)) != 0)
                    return ret_err(EFAULT);
            }
            if (a2) {
                if (!user_range_ok((const void *)(uintptr_t)a2, 4)) return ret_err(EFAULT);
                uint32_t len = tcur->robust_list_len;
                if (copy_to_user_safe((void *)(uintptr_t)a2, &len, sizeof(len)) != 0)
                    return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_futex: {
            /* minimal futex handler: FUTEX_WAIT / FUTEX_WAKE */
            extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
            {
                thread_t *ft = cur;
                int op = (int)a2 & 0x7f; /* strip PRIVATE */
                if (ft && ft->fork_child_user_rip && ft->name[0] &&
                    strstr(ft->name, "linuxrc") && op == 0 /* FUTEX_WAIT */) {
                    static int futex_wait_dbg = 16;
                    if (futex_wait_dbg-- > 0)
                        devel_printf("linuxrc-futex-wait: tid=%llu uaddr=0x%llx val=%d rip=0x%llx\n",
                            (unsigned long long)(ft->tid ? ft->tid : 1),
                            (unsigned long long)a1, (int)a3,
                            (unsigned long long)ft->saved_user_rip);
                }
            }
            int res = futex_syscall((uintptr_t)a1, (int)a2, (int)a3, (const void*)(uintptr_t)a4, (uintptr_t)a5, (int)a6);
            if (res < 0) return ret_err(-res);
            return (uint64_t)res;
        }
        case SYS_rseq:
            /* Minimal rseq registration:
               int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig)
               We accept a non-NULL pointer and length (basic validation) and store it
               per-thread so userspace can use rseq registration checks. This is not a
               full rseq implementation but enough for libc compatibility. */
            {
                const void *rseq_ptr = (const void*)(uintptr_t)a1;
                uint32_t rseq_len = (uint32_t)a2;
                int flags = (int)a3;
                (void)flags;
                thread_t *tcur = thread_get_current_user();
                if (!tcur) tcur = thread_current();
                if (rseq_ptr == NULL) {
                    /* unregister */
                    if (tcur) tcur->rseq_ptr = NULL;
                    return 0;
                }
                if ((uintptr_t)rseq_ptr + (uintptr_t)rseq_len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (rseq_len < 16 || rseq_len > 4096) return ret_err(EINVAL);
                if (tcur) tcur->rseq_ptr = (void*)rseq_ptr;
                return 0;
            }
        case SYS_prlimit64: {
            /* prlimit64(pid, resource, new_limit, old_limit) — current process only. */
            uint64_t pid = a1;
            int resource = (int)a2;
            const void *new_u = (const void*)(uintptr_t)a3;
            void *old_u = (void*)(uintptr_t)a4;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (cur->process && cur->process->pid)
                self = cur->process->pid;
            if (!(pid == 0 || pid == self)) return ret_err(ESRCH);

            struct rlimit64_k { uint64_t rlim_cur; uint64_t rlim_max; } rl;
            int gr = rlimit_get(cur, resource, &rl.rlim_cur, &rl.rlim_max);
            if (gr != 0) return ret_err(gr);
            if (old_u) {
                if (copy_to_user_safe(old_u, &rl, sizeof(rl)) != 0) return ret_err(EFAULT);
            }
            if (new_u) {
                struct rlimit64_k nr;
                if (copy_from_user_raw(&nr, new_u, sizeof(nr)) != 0) return ret_err(EFAULT);
                int sr = rlimit_set(cur, resource, nr.rlim_cur, nr.rlim_max);
                if (sr != 0) return ret_err(sr);
            }
            return 0;
        }
        case SYS_setrlimit: {
            /* setrlimit(resource, rlim) — Linux x86_64 #160; Go 1.7 docker uses this. */
            int resource = (int)a1;
            const void *rlim_u = (const void *)(uintptr_t)a2;
            if (!rlim_u || !user_range_ok(rlim_u, 16)) return ret_err(EFAULT);
            uint64_t soft = 0, hard = 0;
            if (copy_from_user_raw(&soft, rlim_u, 8) != 0) return ret_err(EFAULT);
            if (copy_from_user_raw(&hard, (const char *)rlim_u + 8, 8) != 0) return ret_err(EFAULT);
            int sr = rlimit_set(cur, resource, soft, hard);
            if (sr != 0) return ret_err(sr);
            return 0;
        }
        case SYS_readlink: {
            /* readlink(pathname, buf, bufsiz) */
            const char *path = (const char*)(uintptr_t)a1;
            char *buf = (char*)(uintptr_t)a2;
            size_t bufsiz = (size_t)a3;
            if (!path || !buf) return ret_err(EFAULT);
            if ((uintptr_t)path >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)buf + bufsiz > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);

            char kpath[256];
            resolve_user_path(cur, path, kpath, sizeof(kpath));
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(kpath))
                pid1_dl_log_stat("readlink-req", kpath);

            /* /proc/self/fd/N and /proc/<pid>/fd/N must resolve to the open file path
               before the generic "non-symlink => return path" hack. glibc _dl_get_file_id
               relies on this for shared-library identity checks. */
            if (strncmp(kpath, "/proc/", 6) == 0) {
                const char *p = kpath + 6;
                int self_ok = 0;
                if (strncmp(p, "self/", 5) == 0) {
                    p += 5;
                    self_ok = 1;
                } else {
                    int saw_digit = 0;
                    while (*p >= '0' && *p <= '9') { p++; saw_digit = 1; }
                    if (saw_digit && *p == '/') {
                        p++;
                        self_ok = 1;
                    }
                }
                if (self_ok && strncmp(p, "fd/", 3) == 0) {
                    int fd = 0;
                    const char *q = p + 3;
                    if (*q) {
                        while (*q >= '0' && *q <= '9') {
                            fd = fd * 10 + (*q - '0');
                            q++;
                        }
                        if (*q == '\0' && fd >= 0 && fd < THREAD_MAX_FD) {
                            struct fs_file *ff = cur->fds[fd];
                            const char *target = (ff && ff->path) ? ff->path : NULL;
                            if (!target) return ret_err(ENOENT);
                            if (pid1_dl_trace_thread(cur)) {
                                kprintf("dl-trace readlink /proc/fd/%d -> %s\n", fd, target);
                                if (pid1_dl_trace_path(target))
                                    pid1_dl_log_fd(cur, "readlink-fd", fd);
                                pid1_dl_verify_file_id(cur, fd);
                            }
                            size_t L = strlen(target);
                            if (bufsiz == 0) return ret_err(EINVAL);
                            if (L > bufsiz) L = bufsiz;
                            if (copy_to_user_safe(buf, target, L) != 0) return ret_err(EFAULT);
                            return (uint64_t)L;
                        }
                    }
                }
            }

            /* Workaround: realpath/canonicalize and Busybox adduser readlink paths to resolve
               them. When a path exists as regular file or dir (not symlink), POSIX readlink
               would fail with EINVAL. Return the path as link target so programs succeed. */
            {
                struct stat st;
                if (vfs_lstat(kpath, &st) == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
                    if (bufsiz == 0) return ret_err(EINVAL);
                    size_t L = strlen(kpath);
                    if (L > bufsiz) L = bufsiz;
                    memcpy(buf, kpath, L);
                    return (uint64_t)L;
                }
            }

            ssize_t rr = vfs_readlink(kpath, buf, bufsiz);
            if (rr >= 0) {
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(kpath)) {
                    char tmp[256];
                    size_t tl = (size_t)rr < sizeof(tmp) - 1 ? (size_t)rr : sizeof(tmp) - 1;
                    memcpy(tmp, buf, tl);
                    tmp[tl] = '\0';
                    kprintf("dl-trace readlink ok path=%s target=%s len=%zd\n", kpath, tmp, rr);
                }
                return (uint64_t)rr;
            }

            /* Fallbacks for common procfs symlinks used by libc/busybox. */
            if (strcmp(kpath, "/proc/self/exe") == 0) {
                const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                size_t L = strlen(target);
                if (bufsiz == 0) return ret_err(EINVAL);
                if (L > bufsiz) L = bufsiz;
                memcpy(buf, target, L);
                return (uint64_t)L; /* no NUL terminator */
            }
            if (strncmp(kpath, "/proc/", 6) == 0) {
                const char *p = kpath + 6;
                int self_ok = 0;
                if (strncmp(p, "self/", 5) == 0) {
                    p += 5;
                    self_ok = 1;
                } else {
                    /* /proc/<pid>/... */
                    int saw_digit = 0;
                    while (*p >= '0' && *p <= '9') { p++; saw_digit = 1; }
                    if (saw_digit && *p == '/') {
                        p++;
                        self_ok = 1; /* best-effort: map any pid to current process view */
                    }
                }
                if (self_ok) {
                    if (strcmp(p, "exe") == 0) {
                        const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                        size_t L = strlen(target);
                        if (bufsiz == 0) return ret_err(EINVAL);
                        if (L > bufsiz) L = bufsiz;
                        memcpy(buf, target, L);
                        return (uint64_t)L;
                    }
                    if (strncmp(p, "fd/", 3) == 0) {
                        int fd = 0;
                        const char *q = p + 3;
                        if (!*q) return ret_err(ENOENT);
                        while (*q >= '0' && *q <= '9') {
                            fd = fd * 10 + (*q - '0');
                            q++;
                        }
                        if (*q == '\0' && fd >= 0 && fd < THREAD_MAX_FD) {
                            struct fs_file *ff = cur->fds[fd];
                            const char *target = (ff && ff->path) ? ff->path : NULL;
                            if (!target) return ret_err(ENOENT);
                            if (pid1_dl_trace_thread(cur)) {
                                kprintf("dl-trace readlink fallback /proc/fd/%d -> %s\n", fd, target);
                                if (pid1_dl_trace_path(target))
                                    pid1_dl_log_fd(cur, "readlink-fd-fb", fd);
                                pid1_dl_verify_file_id(cur, fd);
                            }
                            size_t L = strlen(target);
                            if (bufsiz == 0) return ret_err(EINVAL);
                            if (L > bufsiz) L = bufsiz;
                            memcpy(buf, target, L);
                            return (uint64_t)L;
                        }
                    }
                }
            }
            if (cur && cur->name[0]) {
                if (strstr(cur->name, "addgroup") || strstr(cur->name, "adduser") || strstr(cur->name, "wget")) {
                    qemu_debug_printf("READLINK-ENOENT: %s path=%s\n", cur->name, kpath);
                    qemu_debug_printf("READLINK-ENOENT: name=%s path=%s\n", cur->name, kpath);
                }
            }
            return ret_err(ENOENT);
        }
        case SYS_readlinkat: {
            int dirfd = (int)a1;
            const char *path_u = (const char *)(uintptr_t)a2;
            char *buf = (char *)(uintptr_t)a3;
            size_t bufsiz = (size_t)a4;
            if (!buf) return ret_err(EFAULT);
            if ((uintptr_t)buf + bufsiz > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                pid1_dl_log_stat("readlinkat-req", path);

            if (strncmp(path, "/proc/", 6) == 0) {
                const char *p = path + 6;
                int self_ok = 0;
                if (strncmp(p, "self/", 5) == 0) {
                    p += 5;
                    self_ok = 1;
                } else {
                    int saw_digit = 0;
                    while (*p >= '0' && *p <= '9') { p++; saw_digit = 1; }
                    if (saw_digit && *p == '/') {
                        p++;
                        self_ok = 1;
                    }
                }
                if (self_ok && strncmp(p, "fd/", 3) == 0) {
                    int fd = 0;
                    const char *q = p + 3;
                    if (*q) {
                        while (*q >= '0' && *q <= '9') {
                            fd = fd * 10 + (*q - '0');
                            q++;
                        }
                        if (*q == '\0' && fd >= 0 && fd < THREAD_MAX_FD) {
                            struct fs_file *ff = cur->fds[fd];
                            const char *target = (ff && ff->path) ? ff->path : NULL;
                            if (!target) return ret_err(ENOENT);
                            if (pid1_dl_trace_thread(cur)) {
                                kprintf("dl-trace readlinkat /proc/fd/%d -> %s\n", fd, target);
                                if (pid1_dl_trace_path(target))
                                    pid1_dl_log_fd(cur, "readlinkat-fd", fd);
                                pid1_dl_verify_file_id(cur, fd);
                            }
                            if (bufsiz == 0) return ret_err(EINVAL);
                            size_t L = strlen(target);
                            if (L > bufsiz) L = bufsiz;
                            memcpy(buf, target, L);
                            return (uint64_t)L;
                        }
                    }
                }
            }

            {
                struct stat st;
                if (vfs_lstat(path, &st) == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
                    if (bufsiz == 0) return ret_err(EINVAL);
                    size_t L = strlen(path);
                    if (L > bufsiz) L = bufsiz;
                    memcpy(buf, path, L);
                    return (uint64_t)L;
                }
            }

            ssize_t rr = vfs_readlink(path, buf, bufsiz);
            if (rr >= 0) {
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                    char tmp[256];
                    size_t tl = (size_t)rr < sizeof(tmp) - 1 ? (size_t)rr : sizeof(tmp) - 1;
                    memcpy(tmp, buf, tl);
                    tmp[tl] = '\0';
                    kprintf("dl-trace readlinkat ok path=%s target=%s len=%zd\n", path, tmp, rr);
                }
                return (uint64_t)rr;
            }
            return ret_err(ENOENT);
        }
        case SYS_link: {
            /* link(oldpath, newpath) - create hard link */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            int r = fs_link(oldpath, newpath);
            if (r == 0) return 0;
            return ret_err(r < 0 ? -r : EIO);
        }
        case 87: { /* unlink(path) */
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 263: { /* unlinkat(dirfd, path, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)flags; /* we don't support AT_REMOVEDIR etc yet */
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 265: { /* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            int flags = (int)a5;
            (void)flags;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
            int r = fs_link(oldpath, newpath);
            if (r == 0) return 0;
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_rename: {
            /* rename(oldpath, newpath) - syscall 82; rpm needs this for move */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            /* If newpath is a directory, target is newpath/basename(oldpath) (POSIX) */
            {
                struct stat st;
                if (vfs_stat(newpath, &st) == 0 && (st.st_mode & S_IFDIR)) {
                    const char *base = strrchr(oldpath, '/');
                    base = base ? base + 1 : oldpath;
                    size_t nlen = strlen(newpath);
                    size_t blen = strlen(base);
                    if (nlen + 1 + blen + 1 <= sizeof(newpath)) {
                        if (nlen > 0 && newpath[nlen - 1] != '/') {
                            newpath[nlen] = '/';
                            newpath[nlen + 1] = '\0';
                            nlen++;
                        }
                        memcpy(newpath + nlen, base, blen + 1);
                    }
                }
            }
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
            /* Map fs driver internal codes to Linux errno (ramfs uses -1,-2,-3,-5) */
            if (r == -2) return ret_err(ENOENT);
            if (r == -3) return ret_err(ENOTDIR);
            if (r == -5) return ret_err(ENOMEM);
            if (r == -17) return ret_err(EEXIST);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 264: { /* renameat(olddirfd, oldpath, newdirfd, newpath) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
            if (r == -2) return ret_err(ENOENT);
            if (r == -3) return ret_err(ENOTDIR);
            if (r == -5) return ret_err(ENOMEM);
            if (r == -17) return ret_err(EEXIST);
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_umask: {
            /* umask(mask) - syscall 95; returns previous mask, sets new mask */
            unsigned int mask = (unsigned int)(a1 & 07777u);
            unsigned int prev = cur->umask;
            cur->umask = mask;
            return (uint64_t)prev;
        }
        case SYS_mkdir: {
            /* mkdir(path, mode) - syscall 83; init often runs "mkdir -p /dev" before mount */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (path[0] == '\0') return ret_err(EINVAL);
            /* root "/" always exists; rpm may do mkdir -p / and fail with EPERM otherwise */
            if (path[0] == '/' && path[1] == '\0') return 0;
            int r = fs_mkdir(path);
            if (r == 0) {
                (void)fs_chmod(path, (mode & 07777u) | S_IFDIR);
                return 0;
            }
            return ret_err(fs_mkdir_errno(r));
        }
        case 258: { /* mkdirat(dirfd, pathname, mode) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            mode_t mode = (mode_t)(a3 & 0xFFFFu);
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (path[0] == '\0') return ret_err(EINVAL);
            if (path[0] == '/' && path[1] == '\0') return 0;
            int r = fs_mkdir(path);
            if (r == 0) {
                (void)fs_chmod(path, (mode & 07777u) | S_IFDIR);
                return 0;
            }
            return ret_err(fs_mkdir_errno(r));
        }
        case SYS_chmod: {
            /* chmod(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            int r = fs_chmod(path, mode);
            if (r == 0) return 0;
            return ret_err(EPERM);
        }
        case 268: { /* fchmodat(dirfd, pathname, mode, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            mode_t mode = (mode_t)a3;
            int flags = (int)a4;
            (void)flags; /* AT_SYMLINK_NOFOLLOW not supported yet */
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            int r = fs_chmod(path, mode);
            if (r == 0) return 0;
            return ret_err(EPERM);
        }
        case SYS_chown: {
            /* chown(path, uid, gid) - syscall 92; rpm may set ownership; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case 91: { /* fchmod(fd, mode) */
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur ? cur->fds[fd] : NULL;
            if (!f) return ret_err(EBADF);
            if (f->path) {
                int r = fs_chmod(f->path, (mode_t)a2);
                if (r == 0) return 0;
            }
            return 0;
        }
        case 93:  /* fchown(fd, uid, gid) */
        case 94:  /* lchown(path, uid, gid) */
        case 260: /* fchownat(dirfd, pathname, uid, gid, flags) */
            return 0;
        case SYS_utimensat: {
            /* utimensat(dirfd, path, times, flags) - syscall 280; rpm may set mtime; stub success */
            (void)a1; (void)a2; (void)a3; (void)a4;
            return 0;
        }
        case SYS_getrandom: {
            void *bufp = (void*)(uintptr_t)a1;
            size_t len = (size_t)a2;
            (void)a3; /* flags */
            if (!bufp) return ret_err(EFAULT);
            if ((uintptr_t)bufp + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint8_t *p = (uint8_t*)bufp;
            for (size_t i = 0; i < len; i++) {
                /* xorshift32 */
                user_rand_state ^= user_rand_state << 13;
                user_rand_state ^= user_rand_state >> 17;
                user_rand_state ^= user_rand_state << 5;
                p[i] = (uint8_t)(user_rand_state & 0xFF);
            }
            return (uint64_t)len;
        }
        case SYS_clock_gettime: {
            int clk = (int)a1;
            void *tp = (void*)(uintptr_t)a2;
            if (!tp) return ret_err(EFAULT);
            if (!user_range_ok(tp, 16)) return ret_err(EFAULT);
            /* vsyslog already holds dielock; next is localtime (tzlock). */
            if (cur->name[0] && strstr(cur->name, "linuxrc") &&
                cur->fork_child_user_rip && cur->mm) {
                mm_switch(cur->mm);
                *(volatile uint32_t *)(uintptr_t)0x63c940ULL = 0;
            }
            /* Linux clock ids (glibc wget uses MONOTONIC_RAW, COARSE, BOOTTIME, …). */
            enum {
                CLOCK_REALTIME = 0,
                CLOCK_MONOTONIC = 1,
                CLOCK_PROCESS_CPUTIME_ID = 2,
                CLOCK_THREAD_CPUTIME_ID = 3,
                CLOCK_MONOTONIC_RAW = 4,
                CLOCK_REALTIME_COARSE = 5,
                CLOCK_MONOTONIC_COARSE = 6,
                CLOCK_BOOTTIME = 7
            };
            if (clk < 0 || clk > 15) return ret_err(EINVAL);
            int64_t sec, nsec;
            uint64_t mono_us = time_monotonic_us();
            if (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE) {
                rtc_datetime_t dt;
                rtc_read_datetime(&dt);
                uint64_t secs = rtc_datetime_to_epoch(&dt);
                sec = (int64_t)secs;
                nsec = (int64_t)((mono_us % 1000000ull) * 1000ull);
            } else {
                /* Monotonic / boottime: TSC-backed µs when calibrated. */
                sec = (int64_t)(mono_us / 1000000ull);
                nsec = (int64_t)((mono_us % 1000000ull) * 1000ull);
            }
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            ts.tv_sec = sec;
            ts.tv_nsec = nsec;
            if (copy_to_user_safe(tp, &ts, sizeof(ts)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_gettimeofday: { /* Linux x86_64 nr 96 */
            /* gettimeofday(struct timeval *tv, struct timezone *tz) */
            void *tv_u = (void*)(uintptr_t)a1;
            (void)a2;
            if (!tv_u) return ret_err(EFAULT);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv;
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            uint64_t secs = rtc_datetime_to_epoch(&dt);
            uint64_t usec = time_monotonic_us() % 1000000ull;
            tv.tv_sec = (int64_t)secs;
            tv.tv_usec = (int64_t)usec;
            if (copy_to_user_safe(tv_u, &tv, sizeof(tv)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_time: { /* Linux x86_64 nr 201 — also vsyscall+0x400 */
            int64_t *tloc = (int64_t *)(uintptr_t)a1;
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            int64_t secs = (int64_t)rtc_datetime_to_epoch(&dt);
            if (tloc) {
                if (!user_range_ok(tloc, sizeof(*tloc)) ||
                    copy_to_user_safe(tloc, &secs, sizeof(secs)) != 0)
                    return ret_err(EFAULT);
            }
            return (uint64_t)secs;
        }
        case SYS_getcpu: { /* Linux x86_64 nr 309 — also vsyscall+0x800 */
            uint32_t *cpu_u = (uint32_t *)(uintptr_t)a1;
            uint32_t *node_u = (uint32_t *)(uintptr_t)a2;
            uint32_t zero = 0;
            if (cpu_u) {
                if (!user_range_ok(cpu_u, 4) ||
                    copy_to_user_safe(cpu_u, &zero, 4) != 0)
                    return ret_err(EFAULT);
            }
            if (node_u) {
                if (!user_range_ok(node_u, 4) ||
                    copy_to_user_safe(node_u, &zero, 4) != 0)
                    return ret_err(EFAULT);
            }
            (void)a3;
            return 0;
        }
        case SYS_reboot: {
            /* Linux reboot(magic1, magic2, cmd, arg) — BusyBox reboot/halt/poweroff. */
            enum {
                LINUX_REBOOT_MAGIC1 = 0xFEE1DEADu,
                LINUX_REBOOT_MAGIC2 = 672274793u,  /* 0x28121969 */
                LINUX_REBOOT_MAGIC2A = 0x05121996u,
                LINUX_REBOOT_CMD_RESTART   = 0x01234567u,
                LINUX_REBOOT_CMD_HALT      = 0xCDEF0123u,
                LINUX_REBOOT_CMD_CAD_ON    = 0x89ABCDEFu,
                LINUX_REBOOT_CMD_CAD_OFF   = 0u,
                LINUX_REBOOT_CMD_POWER_OFF = 0x4321FEDCu,
                LINUX_REBOOT_CMD_RESTART2  = 0xA1B2C3D4u,
            };
            uint32_t magic1 = (uint32_t)a1;
            uint32_t magic2 = (uint32_t)a2;
            uint32_t cmd    = (uint32_t)a3;
            const void *arg_u = (const void *)(uintptr_t)a4;
            if (magic1 != LINUX_REBOOT_MAGIC1)
                return ret_err(EINVAL);
            if (magic2 != LINUX_REBOOT_MAGIC2 && magic2 != LINUX_REBOOT_MAGIC2A)
                return ret_err(EINVAL);
            if (cmd == LINUX_REBOOT_CMD_CAD_ON || cmd == LINUX_REBOOT_CMD_CAD_OFF)
                return 0;
            if (cmd == LINUX_REBOOT_CMD_POWER_OFF || cmd == LINUX_REBOOT_CMD_HALT) {
                power_request_shutdown("reboot syscall");
                return 0;
            }
            if (cmd == LINUX_REBOOT_CMD_RESTART2) {
                if (arg_u && !user_range_ok(arg_u, 1))
                    return ret_err(EFAULT);
                power_request_reboot("reboot syscall RESTART2");
                return 0;
            }
            if (cmd == LINUX_REBOOT_CMD_RESTART) {
                power_request_reboot("reboot syscall");
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_clock_nanosleep: {
            /* clock_nanosleep(clockid, flags, req, rem) */
            uintptr_t req_addr = (uintptr_t)a1;
            uint64_t flags = a2;
            const void *req_u = (const void*)(uintptr_t)a3;
            void *rem_u = (void*)(uintptr_t)a4;
            (void)rem_u;
            if (flags != 0) return ret_err(EINVAL);
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)ms);
            return 0;
        }
        case SYS_access: {
            /* access(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            int mode = (int)a2;
            if (!path_u) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                pid1_dl_log_stat("access-req", path);
                kprintf("dl-trace access path=%s mode=0%o\n", path, (unsigned)mode);
            }
            struct stat st;
            if (vfs_stat(path, &st) == 0) {
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                    kprintf("dl-trace access ok path=%s\n", path);
                return 0;
            }
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                kprintf("dl-trace access ENOENT path=%s\n", path);
            return ret_err(ENOENT);
        }
        case SYS_uname: {
            void *up = (void*)(uintptr_t)a1;
            if (!up) return ret_err(EFAULT);
            /* Linux: struct utsname has 6 fields of 65 bytes each. */
            struct utsname_k {
                char sysname[65];
                char nodename[65];
                char release[65];
                char version[65];
                char machine[65];
                char domainname[65];
            } u;
            memset(&u, 0, sizeof(u));
            /*
             * Linux ABI: utsname.sysname must be "Linux". Homebrew and most
             * userspace gate on `uname -s` / $(uname). Branding stays in
             * version /etc/os-release, not in sysname.
             */
            snprintf(u.sysname, sizeof(u.sysname), "Linux");
            snprintf(u.nodename, sizeof(u.nodename), "axoniso");
            snprintf(u.release, sizeof(u.release), "%s-%s", OS_VERSION, OS_NAME);
            snprintf(u.version, sizeof(u.version), "#1 SMP %s %s", OS_NAME, OS_PREFIX);
            snprintf(u.machine, sizeof(u.machine), "x86_64");
            snprintf(u.domainname, sizeof(u.domainname), "local");
            if (copy_to_user_safe(up, &u, sizeof(u)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 170: { /* gethostname — BusyBox getty login prompt */
            char *buf = (char *)(uintptr_t)a1;
            size_t len = (size_t)a2;
            if (!buf || len == 0) return ret_err(EINVAL);
            static const char host[] = "axoniso";
            size_t n = sizeof(host) - 1;
            if (n >= len) n = len - 1;
            char k[64];
            memcpy(k, host, n);
            k[n] = '\0';
            if (copy_to_user_safe(buf, k, n + 1) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getcwd: {
            char *bufp = (char*)(uintptr_t)a1;
            size_t size = (size_t)a2;
            const char *cwd = (cur && cur->process && cur->process->cwd[0]) ?
                cur->process->cwd : ((cur && cur->cwd[0]) ? cur->cwd : "/");
            size_t need = strlen(cwd) + 1;
            if (!bufp) return ret_err(EFAULT);
            if (size < need) return ret_err(EINVAL);
            if ((uintptr_t)bufp + need > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            memcpy(bufp, cwd, need);
            return (uint64_t)need;
        }
        case SYS_chdir: {
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct fs_file *f = fs_open(path);
            if (!f) return ret_err(ENOENT);
            /* Don't trust f->type: some drivers don't set it consistently.
               Use stat mode to decide directory-ness so chdir("/") never regresses. */
            struct stat st;
            int is_dir = 0;
            if (vfs_fstat(f, &st) == 0) {
                is_dir = ((st.st_mode & S_IFDIR) == S_IFDIR);
            } else {
                is_dir = (f->type == FS_TYPE_DIR);
            }
            fs_file_free(f);
            if (!is_dir) return ret_err(EINVAL);
            size_t n = strlen(path);
            while (n > 1 && path[n - 1] == '/') path[--n] = '\0';
            strncpy(cur->cwd, path, sizeof(cur->cwd));
            cur->cwd[sizeof(cur->cwd) - 1] = '\0';
            if (cur->process) {
                strncpy(cur->process->cwd, path, sizeof(cur->process->cwd));
                cur->process->cwd[sizeof(cur->process->cwd) - 1] = '\0';
            }
            return 0;
        }
        case SYS_syslog: {

            return ENOSYS;
        }
        case SYS_writev: {
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            struct fs_file *f = syscall_fd_get(cur, fd);
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t sum64 = 0;
                for (int i = 0; i < iovcnt; i++) sum64 += (uint64_t)iov[i].len;
                if (sum64 == 0) return 0;
                if (sum64 > 65536u) return ret_err(EINVAL);
                size_t sum = (size_t)sum64;
                uint8_t *flat = (uint8_t *)kmalloc(sum);
                if (!flat) return ret_err(ENOMEM);
                size_t at = 0;
                for (int i = 0; i < iovcnt; i++) {
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    const void *base = (const void *)(uintptr_t)iov[i].base;
                    if (!user_range_ok(base, len)) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    if (copy_from_user_raw(flat + at, base, len) != 0) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    at += len;
                }
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                    if (s->tcp.peer_rst) { kfree(flat); return ret_err(ECONNRESET); }
                    if (s->tcp.peer_fin) { kfree(flat); return ret_err(EPIPE); }
                    if (!s->connected || !s->tcp.established) { kfree(flat); return ret_err(ENOTCONN); }
                    size_t total = 0;
                    net_tcp_ops_t ops;
                    net_make_tcp_ops(&ops, &s->tcp);
                    while (total < sum) {
                        size_t chunk = sum - total;
                        if (chunk > 4096) chunk = 4096;
                        if (total == 0)
                            net_debug_log_tls443_tx(s, flat, chunk, "writev");
                        int wr = net_tcp_send(&s->tcp, &ops, flat + total, chunk, 30000);
                        if (wr < 0) {
                            kfree(flat);
                            return total ? (uint64_t)total : ret_err(EIO);
                        }
                        total += (size_t)wr;
                        if ((size_t)wr < chunk) break;
                    }
                    (void)net_tcp_flush_tx(&s->tcp, &ops, 5000);
                    kfree(flat);
                    return (uint64_t)total;
                }
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                    if (!s->connected) { kfree(flat); return ret_err(EDESTADDRREQ); }
                    if (sum > 2048u) { kfree(flat); return ret_err(EINVAL); }
                    if (s->local_port == 0) s->local_port = net_alloc_ephemeral_port();
                    int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, flat, sum);
                    kfree(flat);
                    if (r != 0) return ret_err(net_l3_send_errno());
                    return (uint64_t)sum;
                }
                kfree(flat);
                ssize_t wr = net_sock_write_userspace(cur, fd, s, (const void *)(uintptr_t)iov[0].base, (size_t)iov[0].len);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp && chunk > 512) { chunk = 512; tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 512, &copied); }
                    if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                    ssize_t wr;
                    if (f->type == FS_TYPE_PIPE && fs_pipe_is_write_end(f) && f->driver_private) {
                        wr = pipe_write_bytes((pipe_t *)f->driver_private, tmp, copied, cur);
                    } else {
                        wr = fs_write(f, tmp, copied, f->pos);
                    }
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err((int)(-wr ? -wr : EINVAL));
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_pwritev: {
            /* pwritev(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 296 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp) return (total > 0) ? total : ret_err(EFAULT);
                    ssize_t wr = fs_write(f, tmp, copied, cur_off);
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                    cur_off += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_dup3: {
            /* dup3(oldfd, newfd, flags) — Linux x86_64 292.
               Many tools (including busybox applets) use dup3() internally. */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int flags = (int)a3;
            /* Only allow O_CLOEXEC (ignored) or 0. */
            const int O_CLOEXEC = 02000000;
            if (flags & ~O_CLOEXEC) return ret_err(EINVAL);
            if (oldfd == newfd) return ret_err(EINVAL);
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
        }
        case SYS_getpid: {
            uint64_t pid = process_pid(cur);
            linuxrc_trace_post_getpid(cur, pid);
            return pid;
        }
        case SYS_getppid:
            return process_ppid(cur);
        case SYS_gettid:
            return linux_task_tid(cur);
        case SYS_getuid:
            return (uint64_t)(cur->process ? cur->process->uid : cur->uid);
        case SYS_geteuid:
            return (uint64_t)(cur->process ? cur->process->euid : cur->euid);
        case SYS_getgid:
            return (uint64_t)(cur->process ? cur->process->gid : cur->gid);
        case SYS_getegid:
            return (uint64_t)(cur->process ? cur->process->egid : cur->egid);
        case SYS_getgroups: {
            /* getgroups(size, list): supplementary GIDs. size==0 → count only. */
            int size = (int)a1;
            gid_t *list_u = (gid_t *)(uintptr_t)a2;
            int n;
            const gid_t *g;
            if (cur->process) {
                n = cur->process->ngroups;
                g = cur->process->groups;
            } else {
                n = cur->ngroups;
                g = cur->groups;
            }
            if (n < 0) n = 0;
            if (n > AXON_NGROUPS_MAX) n = AXON_NGROUPS_MAX;
            if (size < 0) return ret_err(EINVAL);
            if (size == 0) return (uint64_t)(uint32_t)n;
            if (size < n) return ret_err(EINVAL);
            if (n > 0) {
                if (!list_u || !user_range_ok(list_u, (size_t)n * sizeof(gid_t)))
                    return ret_err(EFAULT);
                if (copy_to_user_safe(list_u, g, (size_t)n * sizeof(gid_t)) != 0)
                    return ret_err(EFAULT);
            }
            return (uint64_t)(uint32_t)n;
        }
        case SYS_setgroups: {
            /* setgroups(size, list): replace supplementary group list (root only). */
            size_t size = (size_t)a1;
            const gid_t *list_u = (const gid_t *)(uintptr_t)a2;
            gid_t tmp[AXON_NGROUPS_MAX];
            uid_t euid = cur->process ? cur->process->euid : cur->euid;
            if (euid != 0) return ret_err(EPERM);
            if (size > AXON_NGROUPS_MAX) return ret_err(EINVAL);
            if (size > 0) {
                if (!list_u || !user_range_ok(list_u, size * sizeof(gid_t)))
                    return ret_err(EFAULT);
                if (copy_from_user_raw(tmp, list_u, size * sizeof(gid_t)) != 0)
                    return ret_err(EFAULT);
            }
            cur->ngroups = (int)size;
            if (size > 0)
                memcpy(cur->groups, tmp, size * sizeof(gid_t));
            if (cur->process) {
                cur->process->ngroups = (int)size;
                if (size > 0)
                    memcpy(cur->process->groups, tmp, size * sizeof(gid_t));
            }
            return 0;
        }
        case SYS_capget:
        case SYS_capset: {
            /* Linux capabilities (htop, libcap). Minimal v1/v2/v3; no per-thread cap storage. */
            enum {
                _CAP_VERSION_1 = 0x19980330u,
                _CAP_VERSION_2 = 0x20071026u,
                _CAP_VERSION_3 = 0x20080522u,
            };
            typedef struct { uint32_t version; int32_t pid; } cap_user_header_t;
            typedef struct { uint32_t effective; uint32_t permitted; uint32_t inheritable; } cap_user_data_t;

            void *hdr_u = (void *)(uintptr_t)a1;
            void *dat_u = (void *)(uintptr_t)a2;
            if (!hdr_u) return ret_err(EFAULT);
            if (!user_range_ok(hdr_u, sizeof(cap_user_header_t))) return ret_err(EFAULT);

            cap_user_header_t hdr;
            if (copy_from_user_raw(&hdr, hdr_u, sizeof(hdr)) != 0) return ret_err(EFAULT);

            int ndata = 0;
            if (hdr.version == _CAP_VERSION_1) ndata = 1;
            else if (hdr.version == _CAP_VERSION_2 || hdr.version == _CAP_VERSION_3) ndata = 2;
            else return ret_err(EINVAL);

            int target_pid = hdr.pid;
            if (target_pid == 0)
                target_pid = (int)(cur->tid ? cur->tid : 1);
            thread_t *target = thread_get(target_pid);
            if (!target || target->state == THREAD_TERMINATED) return ret_err(ESRCH);

            int privileged = (target->euid == 0);
            uint32_t lo = privileged ? 0xFFFFFFFFu : 0u;
            uint32_t hi = privileged ? 0x1FFu : 0u; /* caps 32..40 (CAP_LAST_CAP=40) */

            if (num == SYS_capset) {
                if (cur->euid != 0) return ret_err(EPERM);
                if (!dat_u) return ret_err(EFAULT);
                if (!user_range_ok(dat_u, (size_t)ndata * sizeof(cap_user_data_t))) return ret_err(EFAULT);
                return 0;
            }

            /* capget: datap==NULL probes version/pid only */
            if (!dat_u) return 0;
            if (!user_range_ok(dat_u, (size_t)ndata * sizeof(cap_user_data_t))) return ret_err(EFAULT);

            cap_user_data_t data[2];
            memset(data, 0, sizeof(data));
            data[0].effective = lo;
            data[0].permitted = lo;
            data[0].inheritable = 0;
            if (ndata >= 2) {
                data[1].effective = hi;
                data[1].permitted = hi;
                data[1].inheritable = 0;
            }
            if (copy_to_user_safe(dat_u, data, (size_t)ndata * sizeof(cap_user_data_t)) != 0)
                return ret_err(EFAULT);
            return 0;
        }
        case SYS_setuid: {
            /* setuid(uid): set uid, euid, suid. Root can set any; otherwise uid must equal uid/euid/suid. */
            uid_t uid = (uid_t)a1;
            if (cur->euid == 0) {
                cur->uid = cur->euid = cur->suid = uid;
                if (cur->process)
                    cur->process->uid = cur->process->euid =
                        cur->process->suid = uid;
                return 0;
            }
            if (uid != cur->uid && uid != cur->euid && uid != cur->suid)
                return ret_err(EPERM);
            cur->uid = cur->euid = cur->suid = uid;
            if (cur->process)
                cur->process->uid = cur->process->euid =
                    cur->process->suid = uid;
            return 0;
        }
        case SYS_setgid: {
            /* setgid(gid): same as setuid for groups. */
            gid_t gid = (gid_t)a1;
            if (cur->euid == 0) {
                cur->gid = cur->egid = cur->sgid = gid;
                if (cur->process)
                    cur->process->gid = cur->process->egid =
                        cur->process->sgid = gid;
                return 0;
            }
            if (gid != cur->gid && gid != cur->egid && gid != cur->sgid)
                return ret_err(EPERM);
            cur->gid = cur->egid = cur->sgid = gid;
            if (cur->process)
                cur->process->gid = cur->process->egid =
                    cur->process->sgid = gid;
            return 0;
        }
        case SYS_setreuid: {
            /* setreuid(ruid, euid): -1 means don't change. seteuid(uid) = setreuid(-1, uid). */
            uid_t ruid = (uid_t)(int)a1;
            uid_t euid = (uid_t)(int)a2;
            int do_ruid = (int)a1 != -1;
            int do_euid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_ruid) cur->uid = ruid;
                if (do_euid) cur->euid = euid;
                cur->suid = cur->euid; /* Linux: suid = new euid when euid changed */
                return 0;
            }
            if (do_ruid && ruid != cur->uid && ruid != cur->euid && ruid != cur->suid)
                return ret_err(EPERM);
            if (do_euid && euid != cur->uid && euid != cur->euid && euid != cur->suid)
                return ret_err(EPERM);
            if (do_ruid) cur->uid = ruid;
            if (do_euid) { cur->euid = euid; cur->suid = euid; }
            return 0;
        }
        case SYS_setregid: {
            /* setregid(rgid, egid): -1 means don't change. */
            gid_t rgid = (gid_t)(int)a1;
            gid_t egid = (gid_t)(int)a2;
            int do_rgid = (int)a1 != -1;
            int do_egid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_rgid) cur->gid = rgid;
                if (do_egid) cur->egid = egid;
                cur->sgid = cur->egid;
                return 0;
            }
            if (do_rgid && rgid != cur->gid && rgid != cur->egid && rgid != cur->sgid)
                return ret_err(EPERM);
            if (do_egid && egid != cur->gid && egid != cur->egid && egid != cur->sgid)
                return ret_err(EPERM);
            if (do_rgid) cur->gid = rgid;
            if (do_egid) { cur->egid = egid; cur->sgid = egid; }
            return 0;
        }
        case SYS_setsid:
            /*
             * Linux: fail with EPERM if the caller is already a process group
             * leader. BusyBox getty always calls setsid() after fork from init;
             * if pgid was incorrectly set to pid (exec/ensure_stdio), getty
             * exits and ::respawn loops.
             *
             * If already a session leader (sid == pid), return sid (idempotent).
             * If PG leader but not session leader, still form a new session —
             * small kernels often allow this so getty can take the ctty.
             */
            if (cur && cur->process) {
                int pid = (int)cur->process->pid;
                if (cur->process->sid == pid && cur->process->pgid == pid) {
                    cur->sid = pid;
                    cur->pgid = pid;
                    cur->attached_tty = -1;
                    user_pgrp = (uint64_t)pid;
                    return (uint64_t)pid;
                }
                cur->process->sid = pid;
                cur->process->pgid = pid;
                cur->sid = pid;
                cur->pgid = pid;
                cur->attached_tty = -1;
                user_pgrp = (uint64_t)pid;
                return (uint64_t)pid;
            } else if (cur) {
                int pid = (int)(cur->tid ? cur->tid : 1);
                if (cur->sid == pid && cur->pgid == pid) {
                    cur->attached_tty = -1;
                    user_pgrp = (uint64_t)pid;
                    return (uint64_t)pid;
                }
                cur->sid = pid;
                cur->pgid = pid;
                cur->attached_tty = -1;
                user_pgrp = (uint64_t)pid;
                return (uint64_t)pid;
            }
            return ret_err(EINVAL);
        case 37: /* alarm(seconds) */
            {
                process_t *p = cur && cur->process ? cur->process : NULL;
                uint32_t old_v = 0, old_i = 0;
                uint64_t now = pit_get_time_ms();
                if (p)
                    process_get_itimer_real(p, &old_v, &old_i, now);
                if (a1 == 0) {
                    if (p)
                        process_arm_itimer_real(p, 0, 0);
                    user_itimer_interval_ms = 0;
                } else {
                    uint64_t ms = a1 * 1000ULL;
                    if (ms > 0xFFFFFFFFULL) ms = 0xFFFFFFFFULL;
                    if (p)
                        process_arm_itimer_real(p, now + ms, 0);
                    user_itimer_interval_ms = (uint32_t)ms; /* ping compat */
                }
                return (uint64_t)((old_v + 999u) / 1000u);
            }
        case SYS_getpgrp:
            if (cur && cur->process)
                return (uint64_t)cur->process->pgid;
            if (cur) {
                if (cur->pgid != 0) return (uint64_t)cur->pgid;
            }
            return user_pgrp;
        case SYS_setpgid:
            /* Linux job-control setpgid(pid, pgid). */
            {
                int pid = (int)a1;
                int pgid = (int)a2;
                if (cur->process) {
                    process_t *target;
                    if (pid == 0 || (uint64_t)(unsigned)pid == cur->process->pid)
                        target = cur->process;
                    else
                        target = process_find((uint64_t)(unsigned)pid);
                    if (!target)
                        return ret_err(ESRCH);
                    if (target != cur->process && target->parent != cur->process)
                        return ret_err(EPERM);
                    if (pgid == 0)
                        pgid = (int)target->pid;
                    /* Linux: one pgid for every thread in the process. */
                    target->pgid = pgid;
                    for (int i = 0; i < thread_get_count(); i++) {
                        thread_t *th = thread_get_by_index(i);
                        if (th && th->process == target)
                            th->pgid = pgid;
                    }
                    return 0;
                }
                uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
                if (pid == 0) pid = (int)self;
                if (pgid == 0) pgid = pid;
                if (cur && cur->ring == 3) {
                    if ((uint64_t)pid != self) {
                        thread_t *t = thread_get(pid);
                        if (!t) return ret_err(ESRCH);
                        t->pgid = pgid;
                    } else {
                        cur->pgid = pgid;
                    }
                    if (pgid != 0) user_pgrp = (uint64_t)pgid;
                    return 0;
                }
                if (is_init_user(cur) && (uint64_t)pid == self) {
                    if (cur) cur->pgid = pgid;
                    if (pgid != 0) user_pgrp = (uint64_t)pgid;
                    return 0;
                }
                /* Allow setting pgid for current process or a child process.
                   If pid refers to another thread, verify it's a child of current (simple permission). */
                if ((uint64_t)pid != self) {
                    thread_t *t = thread_get(pid);
                    if (!t) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> ESRCH (not found)\n", pid, pgid);
                        return ret_err(ESRCH);
                    }
                    /* simple permission: only parent can change child's pgid */
                    if (t->parent_tid != (int)self) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not parent)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid==1 (init) unless
                       caller is pid 1. This avoids user processes mistakenly moving into
                       init's pgrp which later confuses job control and can cause shells to exit. */
                    if (pgid == 1 && (int)self != 1 && !is_init_user(cur)) {
                        //kprintf("sys_setpgid: pid=%d attempted to set pgid=1 -> EPERM (denied)\n", pid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid different from current
                       unless caller is session leader. */
                    int caller_tid = (int)self;
                    int caller_sid = cur ? cur->sid : -1;
                    if ((int)pgid != t->pgid && caller_sid != caller_tid) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not session leader)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    t->pgid = pgid;
                } else {
                    if (cur) cur->pgid = pgid;
                }
                if (pgid != 0) user_pgrp = (uint64_t)pgid;
                //kprintf("sys_setpgid: pid=%d pgid=%d -> OK (user_pgrp=%llu)\n", pid, pgid, (unsigned long long)user_pgrp);
                return 0;
            }
        case SYS_tgkill: {
            /* The current process model has one userspace thread per process,
               so tgid and tid must name the same live thread. */
            int tgid = (int)a1;
            int tid = (int)a2;
            int sig = (int)a3;
            if (sig < 0 || sig > 63) return ret_err(EINVAL);
            thread_t *target = thread_get(tid);
            if (!target || target->state == THREAD_TERMINATED ||
                process_pid(target) != (uint64_t)(unsigned)tgid)
                return ret_err(ESRCH);
            if (sig != 0)
                thread_set_pending_signal(target, sig);
            return 0;
        }
        case SYS_sched_yield: {
            thread_yield();
            return 0;
        }
        case SYS_select:
        select_common: { /* select / pselect6 (via case 270) */
            /* Minimal but functional select():
               - supports readfds/writefds (exceptfds ignored)
               - readiness model mirrors SYS_poll implementation (TTY/pipe/file/socket)
               - services TCP (net_tcp_service) and polls e1000 while blocking */
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; };
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; };
            int nfds = (int)a1;
            void *readfds_u  = (void*)(uintptr_t)a2;
            void *writefds_u = (void*)(uintptr_t)a3;
            (void)a4; /* exceptfds */
            void *timeout_u  = (void*)(uintptr_t)a5;
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);

            /*
             * Linux copies only FDS_BYTES(nfds) =
             *   DIV_ROUND_UP(nfds, BITS_PER_LONG) * sizeof(long)
             * Always reading a full FD_SETSIZE (128) buffer EFAULTs when
             * userspace (nginx select module) allocated a tight fd_set.
             */
            size_t fdset_bytes = 0;
            if (nfds > 0)
                fdset_bytes = (((size_t)nfds + 63u) / 64u) * sizeof(uint64_t);

            uint64_t *rin = NULL, *win = NULL;
            uint64_t *rout = NULL, *wout = NULL;
            if (readfds_u && fdset_bytes) {
                if (!user_range_ok(readfds_u, fdset_bytes)) return ret_err(EFAULT);
                rin  = (uint64_t *)kmalloc(fdset_bytes);
                rout = (uint64_t *)kmalloc(fdset_bytes);
                if (!rin || !rout) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    return ret_err(ENOMEM);
                }
                if (copy_from_user_raw(rin, readfds_u, fdset_bytes) != 0) {
                    kfree(rin); kfree(rout);
                    return ret_err(EFAULT);
                }
            }
            if (writefds_u && fdset_bytes) {
                if (!user_range_ok(writefds_u, fdset_bytes)) return ret_err(EFAULT);
                win  = (uint64_t *)kmalloc(fdset_bytes);
                wout = (uint64_t *)kmalloc(fdset_bytes);
                if (!win || !wout) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(ENOMEM);
                }
                if (copy_from_user_raw(win, writefds_u, fdset_bytes) != 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    kfree(win); kfree(wout);
                    return ret_err(EFAULT);
                }
            }

            int timeout_ms = -1; /* NULL => infinite */
            if (timeout_u) {
                if (num == 270) {
                    /* pselect6: timespec* (do NOT convert to a kernel pointer then
                     * copy_from_user — that was a hard EFAULT for musl select). */
                    if (!user_range_ok(timeout_u, sizeof(struct timespec_k))) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EFAULT);
                    }
                    struct timespec_k ts;
                    if (copy_from_user_raw(&ts, timeout_u, sizeof(ts)) != 0) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EFAULT);
                    }
                    if (ts.tv_sec < 0 || ts.tv_nsec < 0) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EINVAL);
                    }
                    uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL +
                                  (uint64_t)(ts.tv_nsec / 1000000ULL);
                    if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                    if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                    timeout_ms = (int)ms;
                } else {
                    if (!user_range_ok(timeout_u, sizeof(struct timeval_k))) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EFAULT);
                    }
                    struct timeval_k tv;
                    if (copy_from_user_raw(&tv, timeout_u, sizeof(tv)) != 0) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EFAULT);
                    }
                    if (tv.tv_sec < 0 || tv.tv_usec < 0) {
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return ret_err(EINVAL);
                    }
                    uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
                    if (ms == 0 && tv.tv_usec > 0) ms = 1;
                    if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                    timeout_ms = (int)ms;
                }
            }

            thread_t *curth = cur;

            auto_select_check:
            {
                if (thread_has_interrupt_signal(curth)) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EINTR);
                }
                if (rout) memset(rout, 0, fdset_bytes);
                if (wout) memset(wout, 0, fdset_bytes);
                int ready = 0;
                int has_net_socket = 0;

                for (int fd = 0; fd < nfds; fd++) {
                    int want_r = 0, want_w = 0;
                    if (rin)  want_r = (int)((rin[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (win)  want_w = (int)((win[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (!want_r && !want_w) continue;

                    struct fs_file *f = syscall_fd_get(curth, fd);
                    int can_r = 0, can_w = 0;
                    if (!f) {
                        /* invalid fd: POSIX would error via EBADF; keep it simple for now */
                        continue;
                    }

                    if (want_r) {
                        if (devfs_is_tty_file(f)) {
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_available(tidx) > 0) can_r = 1;
                        } else if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                s->sock_domain == AF_PACKET_LOCAL)
                                has_net_socket = 1;

                            if (s->sock_domain == AF_NETLINK_LOCAL) {
                                if (s->nl_rx_off < s->nl_rx_len) can_r = 1;
                            } else if (s->sock_domain == AF_PACKET_LOCAL) {
                                if (!packet_sock_has_data(s))
                                    net_packet_pump_rx(8);
                                if (packet_sock_has_data(s)) can_r = 1;
                            } else if (s->unix_domain_stub) {
                                if (s->unix_listening) {
                                    if (s->unix_accept_count > 0) can_r = 1;
                                } else if (s->connected) {
                                    if (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s)) can_r = 1;
                                }
                            } else if (s->tcp_listening) {
                                /* Complete SYN/ACK even if RX thread is busy. */
                                net_pump_listen_handshake();
                                if (s->unix_accept_count > 0) can_r = 1;
                            } else if (s->unix_conn && s->type_base == SOCK_STREAM_LOCAL &&
                                       s->protocol == IPPROTO_TCP_LOCAL && s->connected) {
                                if (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s)) can_r = 1;
                            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                                if (s->rx_has_pending) can_r = 1;
                                else {
                                    uint32_t sip = 0;
                                    uint16_t sport = 0;
                                    int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                                    if (rn > 0) {
                                        ksock_rx_pending_install(s, rn);
                                        s->rx_pending_src_ip_be = sip;
                                        s->rx_pending_src_port = sport;
                                        can_r = 1;
                                    }
                                }
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops, &s->tcp);
                                if (s->tcp.connect_pending)
                                    (void)net_tcp_connect_poll(&s->tcp, &ops, 0);
                                net_pump_tcp_sock(s, 1);
                                if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst || s->tcp.ooo_valid) can_r = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            int is_write_end = fs_pipe_is_write_end(f);
                            release_irqrestore(&p->lock, fl);
                            if (!is_write_end && (used > 0 || p->refcount < 2)) can_r = 1;
                        } else if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
                            eventfd_t *e = (eventfd_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&e->lock, &fl);
                            if (e->count > 0) can_r = 1;
                            release_irqrestore(&e->lock, fl);
                        } else {
                            if (f->type == FS_TYPE_DIR) can_r = 1;
                            else if ((size_t)f->pos < (size_t)f->size) can_r = 1;
                        }
                    }

                    if (want_w) {
                        if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                                has_net_socket = 1;
                            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                                can_w = 1;
                            } else if (s->unix_domain_stub) {
                                if (!s->unix_listening && s->connected && !unix_stream_peer_closed(s) && unix_stream_avail_to_write(s) > 0)
                                    can_w = 1;
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops, &s->tcp);
                                if (s->tcp.connect_pending) {
                                    e1000_poll();
                                    /* timeout 0: progress only — never abort pending SYN. */
                                    if (net_tcp_connect_poll(&s->tcp, &ops, 0) == 0) {
                                        s->connected = 1;
                                        can_w = 1;
                                    } else if (s->tcp.connect_refused) {
                                        can_w = 1;
                                    }
                                } else {
                                    e1000_poll();
                                    (void)net_tcp_service(&s->tcp, &ops, 64);
                                    if (s->tcp.established || s->tcp.peer_rst) can_w = 1;
                                }
                            } else {
                                can_w = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            size_t free = (p->size > 1) ? ((p->size - 1) - used) : 0;
                            int is_write_end = fs_pipe_is_write_end(f);
                            release_irqrestore(&p->lock, fl);
                            if (is_write_end && free > 0) can_w = 1;
                        } else if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
                            eventfd_t *e = (eventfd_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&e->lock, &fl);
                            if (e->count != (uint64_t)-1) can_w = 1;
                            release_irqrestore(&e->lock, fl);
                        } else {
                            /* regular files: writable */
                            can_w = 1;
                        }
                    }

                    if (can_r && rout) { rout[fd / 64] |= (1ULL << (fd % 64)); ready++; }
                    if (can_w && wout) { wout[fd / 64] |= (1ULL << (fd % 64)); if (!can_r) ready++; }
                }

                if (ready > 0) {
                    if (readfds_u && rout)  { if (copy_to_user_safe(readfds_u,  rout, fdset_bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (writefds_u && wout) { if (copy_to_user_safe(writefds_u, wout, fdset_bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return (uint64_t)ready;
                }

                if (timeout_ms == 0) {
                    if (readfds_u && rout)  (void)copy_to_user_safe(readfds_u,  rout, fdset_bytes);
                    if (writefds_u && wout) (void)copy_to_user_safe(writefds_u, wout, fdset_bytes);
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return 0;
                }

                /* Wake on tty keypress like poll() — do not sleep fixed 10ms slices. */
                int cur_tid = curth ? (int)curth->tid : -1;
                int tty_waiting[16];
                int n_tty_waiting = 0;
                if (cur_tid >= 0 && rin) {
                    for (int fd = 0; fd < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); fd++) {
                        if (!((rin[fd / 64] >> (fd % 64)) & 1ULL)) continue;
                        struct fs_file *f = syscall_fd_get(curth, fd);
                        if (!f || !devfs_is_tty_file(f)) continue;
                        int tidx = devfs_get_tty_index_from_file(f);
                        if (tidx < 0) tidx = devfs_get_active();
                        if (devfs_tty_add_waiter(tidx, cur_tid) == 0)
                            tty_waiting[n_tty_waiting++] = tidx;
                    }
                }
                if (n_tty_waiting > 0 && !has_net_socket) {
                    if (timeout_ms < 0) {
                        thread_block(cur_tid);
                        thread_yield();
                        for (int w = 0; w < n_tty_waiting; w++)
                            devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_select_check;
                    }
                    uint64_t t0 = pit_get_time_ms();
                    thread_block_with_timeout(cur_tid, (uint32_t)timeout_ms);
                    thread_yield();
                    for (int w = 0; w < n_tty_waiting; w++)
                        devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    int elapsed = (int)(pit_get_time_ms() - t0);
                    if (elapsed >= timeout_ms) {
                        if (readfds_u && rout) (void)copy_to_user_safe(readfds_u, rout, fdset_bytes);
                        if (writefds_u && wout) (void)copy_to_user_safe(writefds_u, wout, fdset_bytes);
                        if (rin) kfree(rin); if (rout) kfree(rout);
                        if (win) kfree(win); if (wout) kfree(wout);
                        return 0;
                    }
                    timeout_ms -= elapsed;
                    goto auto_select_check;
                }
                if (n_tty_waiting > 0) {
                    int step = 2;
                    if (timeout_ms > 0 && timeout_ms < step) step = timeout_ms;
                    net_pump_all_tcp(curth);
                    thread_block_with_timeout(cur_tid, (uint32_t)step);
                    thread_yield();
                    for (int w = 0; w < n_tty_waiting; w++)
                        devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    if (timeout_ms > 0) timeout_ms -= step;
                    goto auto_select_check;
                }

                int step = 2;
                if (timeout_ms > 0 && timeout_ms < step) step = timeout_ms;
                if (has_net_socket)
                    net_pump_all_tcp(curth);
                else
                    e1000_poll();
                thread_sleep((uint32_t)step);
                if (timeout_ms > 0) timeout_ms -= step;
                goto auto_select_check;
            }
        }
        case SYS_nanosleep: { /* nanosleep(req, rem) - Linux 35 */
            const void *req_u = (const void*)(uintptr_t)a1;
            void *rem_u = (void*)(uintptr_t)a2;
            (void)rem_u;
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)(ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (uint32_t)ms));
            if (thread_has_interrupt_signal(cur)) {
                if (rem_u) {
                    struct timespec_k zero = { 0, 0 };
                    if (copy_to_user_safe(rem_u, &zero, sizeof(zero)) != 0)
                        return ret_err(EFAULT);
                }
                return ret_err(EINTR);
            }
            return 0;
        }
        case 222: { /* timer_create(clockid, sevp, timerid) */
            int clockid = (int)a1;
            const void *sev_u = (const void *)(uintptr_t)a2;
            void *tid_u = (void *)(uintptr_t)a3;
            if (!tid_u) return ret_err(EFAULT);
            uint8_t sev_buf[64];
            memset(sev_buf, 0, sizeof(sev_buf));
            size_t sev_len = 0;
            if (sev_u) {
                if (!user_range_ok(sev_u, 64)) return ret_err(EFAULT);
                if (copy_from_user_raw(sev_buf, sev_u, 64) != 0) return ret_err(EFAULT);
                sev_len = 64;
            }
            int32_t kid = 0;
            int rc = process_posix_timer_create(clockid, sev_len ? sev_buf : NULL, sev_len, &kid);
            if (rc < 0) return ret_err(-rc);
            if (copy_to_user_safe(tid_u, &kid, sizeof(kid)) != 0) {
                (void)process_posix_timer_delete(kid);
                return ret_err(EFAULT);
            }
            return 0;
        }
        case 223: { /* timer_settime(timerid, flags, new_value, old_value) */
            int32_t timerid = (int32_t)a1;
            int flags = (int)a2;
            const void *new_u = (const void *)(uintptr_t)a3;
            void *old_u = (void *)(uintptr_t)a4;
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; };
            struct itimerspec_k {
                struct timespec_k it_interval;
                struct timespec_k it_value;
            } nv, ov;
            memset(&ov, 0, sizeof(ov));
            uint64_t old_v = 0;
            uint32_t old_i = 0;
            if (!new_u) {
                int rc = process_posix_timer_settime(timerid, flags, 0, 0, &old_v, &old_i);
                if (rc < 0) return ret_err(-rc);
            } else {
                if (!user_range_ok(new_u, sizeof(nv))) return ret_err(EFAULT);
                if (copy_from_user_raw(&nv, new_u, sizeof(nv)) != 0) return ret_err(EFAULT);
                if (nv.it_interval.tv_sec < 0 || nv.it_interval.tv_nsec < 0 ||
                    nv.it_value.tv_sec < 0 || nv.it_value.tv_nsec < 0 ||
                    nv.it_interval.tv_nsec >= 1000000000LL ||
                    nv.it_value.tv_nsec >= 1000000000LL)
                    return ret_err(EINVAL);
                uint64_t interval_ms = (uint64_t)nv.it_interval.tv_sec * 1000ULL +
                                      (uint64_t)(nv.it_interval.tv_nsec / 1000000LL);
                uint64_t value_ms = (uint64_t)nv.it_value.tv_sec * 1000ULL +
                                   (uint64_t)(nv.it_value.tv_nsec / 1000000LL);
                if (nv.it_interval.tv_nsec > 0 && interval_ms == (uint64_t)nv.it_interval.tv_sec * 1000ULL &&
                    (nv.it_interval.tv_nsec % 1000000LL))
                    interval_ms++;
                if (nv.it_value.tv_nsec > 0 && value_ms == (uint64_t)nv.it_value.tv_sec * 1000ULL &&
                    (nv.it_value.tv_nsec % 1000000LL))
                    value_ms++;
                if (interval_ms > 0xFFFFFFFFULL) interval_ms = 0xFFFFFFFFULL;
                if (value_ms > 0xFFFFFFFFULL) value_ms = 0xFFFFFFFFULL;
                int rc = process_posix_timer_settime(timerid, flags, value_ms,
                                                    (uint32_t)interval_ms, &old_v, &old_i);
                if (rc < 0) return ret_err(-rc);
            }
            if (old_u) {
                ov.it_interval.tv_sec = (int64_t)(old_i / 1000u);
                ov.it_interval.tv_nsec = (int64_t)((old_i % 1000u) * 1000000u);
                ov.it_value.tv_sec = (int64_t)(old_v / 1000u);
                ov.it_value.tv_nsec = (int64_t)((old_v % 1000u) * 1000000u);
                if (!user_range_ok(old_u, sizeof(ov))) return ret_err(EFAULT);
                if (copy_to_user_safe(old_u, &ov, sizeof(ov)) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case 226: { /* timer_delete(timerid) */
            int32_t timerid = (int32_t)a1;
            int rc = process_posix_timer_delete(timerid);
            if (rc < 0) return ret_err(-rc);
            return 0;
        }
        case 38: { /* setitimer(which, new_value, old_value) */
            const int ITIMER_REAL_LOCAL = 0;
            int which = (int)a1;
            const void *new_u = (const void *)(uintptr_t)a2;
            void *old_u = (void *)(uintptr_t)a3;
            if (which != ITIMER_REAL_LOCAL) return ret_err(EINVAL);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; };
            struct itimerval_k {
                struct timeval_k it_interval;
                struct timeval_k it_value;
            } nv, ov;
            process_t *p = cur && cur->process ? cur->process : NULL;
            uint64_t now = pit_get_time_ms();
            uint32_t old_v = 0, old_i = 0;
            if (p)
                process_get_itimer_real(p, &old_v, &old_i, now);
            memset(&ov, 0, sizeof(ov));
            ov.it_interval.tv_sec = (int64_t)(old_i / 1000u);
            ov.it_interval.tv_usec = (int64_t)((old_i % 1000u) * 1000u);
            ov.it_value.tv_sec = (int64_t)(old_v / 1000u);
            ov.it_value.tv_usec = (int64_t)((old_v % 1000u) * 1000u);
            if (old_u && user_range_ok(old_u, sizeof(ov))) {
                if (copy_to_user_safe(old_u, &ov, sizeof(ov)) != 0)
                    return ret_err(EFAULT);
            }
            if (!new_u) return 0;
            if (!user_range_ok(new_u, sizeof(nv))) return ret_err(EFAULT);
            if (copy_from_user_raw(&nv, new_u, sizeof(nv)) != 0) return ret_err(EFAULT);
            if (nv.it_interval.tv_sec < 0 || nv.it_interval.tv_usec < 0 ||
                nv.it_value.tv_sec < 0 || nv.it_value.tv_usec < 0) return ret_err(EINVAL);
            uint64_t interval_ms = (uint64_t)nv.it_interval.tv_sec * 1000ULL +
                                  (uint64_t)(nv.it_interval.tv_usec / 1000ULL);
            uint64_t value_ms = (uint64_t)nv.it_value.tv_sec * 1000ULL +
                               (uint64_t)(nv.it_value.tv_usec / 1000ULL);
            if (nv.it_interval.tv_usec > 0 && (nv.it_interval.tv_usec % 1000) &&
                interval_ms == (uint64_t)nv.it_interval.tv_sec * 1000ULL)
                interval_ms++;
            if (nv.it_value.tv_usec > 0 && value_ms == (uint64_t)nv.it_value.tv_sec * 1000ULL &&
                (nv.it_value.tv_usec % 1000))
                value_ms++;
            if (interval_ms > 0xFFFFFFFFULL) interval_ms = 0xFFFFFFFFULL;
            if (value_ms > 0xFFFFFFFFULL) value_ms = 0xFFFFFFFFULL;
            /* Linux: it_value == 0 disarms the timer. */
            if (!p) {
                user_itimer_interval_ms = (uint32_t)(interval_ms ? interval_ms : value_ms);
                return 0;
            }
            if (value_ms == 0)
                process_arm_itimer_real(p, 0, 0);
            else
                process_arm_itimer_real(p, now + value_ms, (uint32_t)interval_ms);
            /* Keep global for legacy ping paths that still read it. */
            user_itimer_interval_ms = (uint32_t)(interval_ms ? interval_ms : value_ms);
            return 0;
        }
        case SYS_socket: { /* socket(domain, type, protocol) */
            int domain = (int)a1;
            int type = (int)a2;
            int protocol = (int)a3;
            int unix_stub = 0;
            int ipv6_stub = (domain == AF_INET6);
            /* Linux: type may include SOCK_NONBLOCK|SOCK_CLOEXEC in high bits. */
            int type_base = type & ~(O_NONBLOCK_LINUX | SOCK_CLOEXEC_LINUX);
            if (domain == AF_INET_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL || type_base == SOCK_STREAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (type_base == SOCK_RAW_LOCAL) {
                    /* ICMP ping, or IPPROTO_RAW (busybox udhcpc ioctl socket). */
                    if (!(protocol == 0 || protocol == IPPROTO_ICMP_LOCAL || protocol == IPPROTO_RAW_LOCAL))
                        return ret_err(EPROTONOSUPPORT);
                } else if (type_base == SOCK_DGRAM_LOCAL) {
                    /* Protocol is normalized when storing s->protocol (glibc IPv6 path may pass 41, etc.). */
                } else { /* SOCK_STREAM_LOCAL */
                    if (!(protocol == 0 || protocol == IPPROTO_TCP_LOCAL)) return ret_err(EPROTONOSUPPORT);
                }
            } else if (domain == AF_PACKET_LOCAL) {
                if (!(type_base == SOCK_DGRAM_LOCAL || type_base == SOCK_RAW_LOCAL))
                    return ret_err(ESOCKTNOSUPPORT);
            } else if (domain == AF_NETLINK_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (!(protocol == 0 || protocol == NETLINK_ROUTE_LOCAL)) return ret_err(EPROTONOSUPPORT);
                protocol = NETLINK_ROUTE_LOCAL;
            } else if (domain == AF_INET6) {
                /* Stub: create IPv4 socket when tools (wget) request IPv6 */
                domain = AF_INET_LOCAL;
            } else if (domain == AF_UNSPEC) {
                /* getaddrinfo/glibc may pass AF_UNSPEC; treat as IPv4 */
                domain = AF_INET_LOCAL;
            } else if (domain == AF_UNIX_LOCAL) {
                /* Linux PF_UNIX — keep sock_domain=AF_UNIX (not remapped to AF_INET). */
                if (!(type_base == SOCK_STREAM_LOCAL || type_base == SOCK_DGRAM_LOCAL ||
                      type_base == SOCK_SEQPACKET_LOCAL))
                    return ret_err(ESOCKTNOSUPPORT);
                if (protocol != 0)
                    return ret_err(EPROTONOSUPPORT);
                unix_stub = 1;
            } else {
                /* Compatibility: map odd domains to IPv4 (getaddrinfo quirks).
                   Avoids EAFNOSUPPORT causing wget to fail with "out of memory" (fdopen path). */
                domain = AF_INET_LOCAL;
            }
            ksock_net_t *s = (ksock_net_t *)kmalloc(sizeof(*s));
            struct fs_file *f = (struct fs_file *)kmalloc(sizeof(*f));
            char *p = (char *)kmalloc(24);
            if (!s || !f || !p) {
                if (s) kfree(s);
                if (f) kfree(f);
                if (p) kfree(p);
                return ret_err(ENOMEM);
            }
            memset(s, 0, sizeof(*s));
            memset(f, 0, sizeof(*f));
            if (domain == AF_NETLINK_LOCAL) snprintf(p, 24, "socket:[netlink]");
            else if (domain == AF_PACKET_LOCAL) snprintf(p, 24, "socket:[packet]");
            else if (unix_stub) snprintf(p, 24, "socket:[unix]");
            else snprintf(p, 24, "socket:[icmp]");
            s->sock_domain = domain;
            s->ipv6_stub = ipv6_stub;
            s->unix_domain_stub = unix_stub;
            s->type_base = type_base;
            if (domain == AF_NETLINK_LOCAL) {
                s->protocol = NETLINK_ROUTE_LOCAL;
            } else if (domain == AF_PACKET_LOCAL) {
                /* socket() protocol is htons(ethertype); store host-order ethertype. */
                s->protocol = protocol;
                s->packet_proto_host = protocol ? be16((uint16_t)protocol) : ETH_P_ALL_HOST;
                s->packet_ifindex = 0;
            } else if (unix_stub) {
                s->protocol = 0;
            } else if (type_base == SOCK_RAW_LOCAL) {
                s->protocol = (protocol == 0) ? IPPROTO_ICMP_LOCAL : protocol;
            } else if (type_base == SOCK_DGRAM_LOCAL) {
                /* Only SOCK_DGRAM + IPPROTO_ICMP is ping; everything else is UDP (DNS, resolver IPv6 sockets). */
                s->protocol = (protocol == IPPROTO_ICMP_LOCAL) ? IPPROTO_ICMP_LOCAL : IPPROTO_UDP_LOCAL;
            } else s->protocol = (protocol == 0) ? IPPROTO_TCP_LOCAL : protocol;
            s->connected = 0;
            s->peer_ip_be = 0;
            s->peer_port = 0;
            s->local_port = 0;
            s->next_echo_seq = 0;
            s->nonblock = (type & O_NONBLOCK_LINUX) ? 1 : 0;
            s->kref = 1;
            f->path = p;
            f->type = SYSCALL_FTYPE_SOCKET;
            f->driver_private = s;
            f->refcount = 1;
            int fd = thread_fd_alloc(f);
            if (fd < 0) {
                kfree(s);
                kfree((void *)f->path);
                kfree(f);
                return ret_err(EMFILE);
            }
            if (ksock_register(s) != 0) {
                thread_fd_close(fd);
                return ret_err(EMFILE);
            }
            if (domain == AF_PACKET_LOCAL)
                packet_sock_register(s);
            return (uint64_t)fd;
        }
        case SYS_bind: { /* bind */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_pid = sa.nl_pid ? sa.nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                s->nl_groups = sa.nl_groups;
                return 0;
            }
            if (s->sock_domain == AF_PACKET_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_ll_k) || !user_range_ok(addr_u, sizeof(sockaddr_ll_k)))
                    return ret_err(EFAULT);
                sockaddr_ll_k sll;
                if (copy_from_user_raw(&sll, addr_u, sizeof(sll)) != 0) return ret_err(EFAULT);
                if (sll.sll_family != AF_PACKET_LOCAL) return ret_err(EAFNOSUPPORT);
                (void)net_stack_init();
                s->packet_ifindex = sll.sll_ifindex ? sll.sll_ifindex : 2;
                if (sll.sll_protocol)
                    s->packet_proto_host = be16(sll.sll_protocol);
                return 0;
            }
            if (s->unix_domain_stub) {
                char upath[108];
                int is_abs = 0;
                int plen = 0;
                int pr = unix_sockaddr_path_from_user(addr_u, addrlen, upath, sizeof(upath),
                                                      &plen, &is_abs);
                if (pr != 0) return ret_err(pr);
                if (s->unix_bound) return ret_err(EINVAL);
                /* Linux: EADDRINUSE if another sock already owns this name. */
                if (unix_find_listener_by_path(upath, plen, is_abs))
                    return ret_err(EADDRINUSE);
                {
                    unsigned long flags;
                    acquire_irqsave(&g_ksock_registry_lock, &flags);
                    for (int i = 0; i < KSOCK_REGISTRY_MAX; i++) {
                        ksock_net_t *o = g_ksock_registry[i];
                        if (!o || o == s || !o->unix_domain_stub || !o->unix_bound) continue;
                        if (unix_path_equal(o, upath, plen, is_abs)) {
                            release_irqrestore(&g_ksock_registry_lock, flags);
                            return ret_err(EADDRINUSE);
                        }
                    }
                    release_irqrestore(&g_ksock_registry_lock, flags);
                }
                if (!is_abs) {
                    /* unix_bind_bsd: create S_IFSOCK inode on the pathname. */
                    unix_ensure_parent_dirs(upath);
                    (void)fs_unlink(upath);
                    if (!fs_create_file(upath))
                        return ret_err(ENOENT);
                    (void)fs_chmod(upath, S_IFSOCK | 0666);
                }
                memset(s->unix_path, 0, sizeof(s->unix_path));
                if (plen > (int)sizeof(s->unix_path)) plen = (int)sizeof(s->unix_path);
                memcpy(s->unix_path, upath, (size_t)plen);
                s->unix_path_len = plen;
                s->unix_abstract = is_abs ? 1 : 0;
                s->unix_bound = 1;
                return 0;
            }
            if (s->sock_domain == AF_INET_LOCAL) {
                sockaddr_in_k sa;
                int pr = user_sockaddr_to_ipv4_peer(addr_u, addrlen, &sa);
                if (pr != 0) {
                    static int bind_fail_left = 8;
                    if (bind_fail_left-- > 0)
                        klogprintf("net: bind peer-parse err=%d tid=%d\n", pr,
                                   t ? (int)t->tid : -1);
                    return ret_err(pr);
                }
                uint16_t port = be16(sa.sin_port);
                if (port == 0) port = net_alloc_ephemeral_port();
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                    /* Linux checks the port at bind(), not only after listen(). */
                    ksock_net_t *exist = net_tcp_find_bound_port(port);
                    if (exist && exist != s) {
                        /*
                         * Linux: AF_INET and AF_INET6+IPV6_V6ONLY=1 may share a
                         * port. AF_INET6 is an IPv4-backed stub here, so enforce
                         * the same cross-family rule via ipv6_stub+ipv6_only.
                         */
                        int s_v6only = s->ipv6_stub && s->ipv6_only;
                        int e_v6only = exist->ipv6_stub && exist->ipv6_only;
                        int cross_family = (s->ipv6_stub != exist->ipv6_stub) &&
                                           (s_v6only || e_v6only);
                        if (!cross_family)
                            return ret_err(EADDRINUSE);
                    }
                }
                s->local_port = port;
                return 0;
            }
            return 0;
        }
        case SYS_listen: { /* listen — Linux unix_listen / inet_listen */
            int fd = (int)a1;
            int backlog = (int)a2;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->unix_domain_stub) {
                /* Only stream/seqpacket; must be bound (u->addr). */
                if (s->type_base != SOCK_STREAM_LOCAL && s->type_base != SOCK_SEQPACKET_LOCAL)
                    return ret_err(EOPNOTSUPP);
                if (!s->unix_bound) return ret_err(EINVAL);
                if (s->connected && s->unix_conn) return ret_err(EINVAL);
                if (backlog < 0) backlog = 0;
                if (backlog > 128) backlog = 128;
                if (backlog == 0) backlog = 1;
                s->unix_backlog = backlog;
                s->unix_listening = 1;
                {
                    static int unix_listen_log = 8;
                    if (unix_listen_log-- > 0)
                        kprintf("unix: listen ok path=%s abs=%d backlog=%d tid=%d\n",
                                s->unix_abstract ? "(abstract)" :
                                    (s->unix_path[0] ? s->unix_path : "?"),
                                s->unix_abstract, backlog,
                                t ? (int)t->tid : -1);
                }
                return 0;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                if (s->local_port == 0) return ret_err(EINVAL);
                s->tcp_listening = 1;
                return 0;
            }
            return ret_err(EOPNOTSUPP);
        }
        case 48: { /* shutdown */
            int fd = (int)a1;
            (void)a2;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->unix_domain_stub) return 0;
            return ret_err(EOPNOTSUPP);
        }
        case 43:  /* accept */
        case 288: { /* accept4 */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            (void)a4; /* flags for accept4 */
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            if (!t || fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = syscall_fd_get(t, fd);
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) return ret_err(EBADF);
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->unix_domain_stub) {
                if (!s->unix_listening) return ret_err(EINVAL);
                struct fs_file *af = unix_acceptq_pop(s);
                while (!af) {
                    if (s->nonblock) return ret_err(EAGAIN);
                    thread_sleep(1);
                    af = unix_acceptq_pop(s);
                }
                int nfd = thread_fd_alloc(af);
                if (nfd < 0) {
                    net_fs_file_destroy(af);
                    return ret_err(EMFILE);
                }
                if (addr_u && addrlen_u && user_range_ok(addrlen_u, 4)) {
                    uint32_t ulen = 0;
                    ksock_net_t *as = (ksock_net_t *)af->driver_private;
                    if (copy_from_user_raw(&ulen, addrlen_u, 4) == 0 && ulen >= 2) {
                        uint8_t sa[2 + 108];
                        memset(sa, 0, sizeof(sa));
                        uint16_t fam = AF_UNIX_LOCAL;
                        memcpy(sa, &fam, sizeof(fam));
                        int plen = as ? as->unix_path_len : 0;
                        if (plen < 0) plen = 0;
                        if (plen > 108) plen = 108;
                        if (as && plen > 0)
                            memcpy(sa + 2, as->unix_path, (size_t)plen);
                        uint32_t want = (uint32_t)(2 + plen);
                        uint32_t copy_len = (ulen < want) ? ulen : want;
                        if (copy_len > 0 && user_range_ok(addr_u, copy_len))
                            (void)copy_to_user_safe(addr_u, sa, copy_len);
                        ulen = want;
                        (void)copy_to_user_safe(addrlen_u, &ulen, 4);
                    }
                }
                return (uint64_t)nfd;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                if (!s->tcp_listening) return ret_err(EINVAL);
                (void)thread_reap_unwaited_zombies();
                struct fs_file *af = unix_acceptq_pop(s);
                while (!af) {
                    if (s->nonblock) return ret_err(EAGAIN);
                    net_pump_listen_handshake();
                    af = unix_acceptq_pop(s);
                    if (af) break;
                    thread_sleep(1);
                }
                ksock_net_t *as = (ksock_net_t *)af->driver_private;
                int nfd = thread_fd_alloc(af);
                if (nfd < 0) {
                    net_fs_file_destroy(af);
                    return ret_err(EMFILE);
                }
                if (addr_u && addrlen_u && as && user_range_ok(addrlen_u, 4)) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(as->peer_port);
                    sa.sin_addr = be32(as->peer_ip_be);
                    uint32_t ulen = 0;
                    if (copy_from_user_raw(&ulen, addrlen_u, 4) == 0 && ulen >= sizeof(sa) &&
                        user_range_ok(addr_u, sizeof(sa))) {
                        (void)copy_to_user_safe(addr_u, &sa, sizeof(sa));
                        ulen = (uint32_t)sizeof(sa);
                        (void)copy_to_user_safe(addrlen_u, &ulen, 4);
                    }
                }
                return (uint64_t)nfd;
            }
            return ret_err(EOPNOTSUPP);
        }
        case 42: { /* connect */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_peer_pid = sa.nl_pid;
                s->connected = 1;
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                return 0;
            }
            if (s->unix_domain_stub) {
                char upath[108];
                int is_abs = 0;
                int plen = 0;
                int pr = unix_sockaddr_path_from_user(addr_u, addrlen, upath, sizeof(upath),
                                                      &plen, &is_abs);
                if (pr != 0) return ret_err(pr);
                if (s->type_base != SOCK_STREAM_LOCAL && s->type_base != SOCK_SEQPACKET_LOCAL) {
                    s->connected = 1;
                    return 0;
                }
                ksock_net_t *listener = unix_find_listener_by_path(upath, plen, is_abs);
                if (!listener || !listener->unix_listening) return ret_err(ECONNREFUSED);
                if (s->connected && s->unix_conn) return ret_err(EISCONN);

                unix_stream_conn_t *conn = (unix_stream_conn_t *)kmalloc(sizeof(*conn));
                ksock_net_t *srv = (ksock_net_t *)kmalloc(sizeof(*srv));
                struct fs_file *srv_f = (struct fs_file *)kmalloc(sizeof(*srv_f));
                char *srv_p = (char *)kmalloc(24);
                if (!conn || !srv || !srv_f || !srv_p) {
                    if (conn) kfree(conn);
                    if (srv) kfree(srv);
                    if (srv_f) kfree(srv_f);
                    if (srv_p) kfree(srv_p);
                    return ret_err(ENOMEM);
                }
                memset(conn, 0, sizeof(*conn));
                conn->refs = 2;
                memset(srv, 0, sizeof(*srv));
                memset(srv_f, 0, sizeof(*srv_f));
                snprintf(srv_p, 24, "socket:[unix]");
                srv->sock_domain = AF_UNIX_LOCAL;
                srv->unix_domain_stub = 1;
                srv->type_base = SOCK_STREAM_LOCAL;
                srv->protocol = 0;
                srv->connected = 1;
                srv->unix_conn = conn;
                srv->unix_end = 1;
                srv->kref = 1;
                memset(srv->unix_path, 0, sizeof(srv->unix_path));
                if (plen > (int)sizeof(srv->unix_path)) plen = (int)sizeof(srv->unix_path);
                memcpy(srv->unix_path, upath, (size_t)plen);
                srv->unix_path_len = plen;
                srv->unix_abstract = is_abs ? 1 : 0;
                srv_f->path = srv_p;
                srv_f->type = SYSCALL_FTYPE_SOCKET;
                srv_f->driver_private = srv;
                srv_f->refcount = 1;
                if (ksock_register(srv) != 0) {
                    /* Not registered: tear down without registry. conn refs==2. */
                    srv->unix_conn = NULL;
                    kfree(srv_p);
                    kfree(srv_f);
                    kfree(srv);
                    kfree(conn);
                    return ret_err(ENOMEM);
                }

                if (unix_acceptq_push(listener, srv_f) != 0) {
                    /* Registered — drop via destructor (clears registry). Client
                     * never attached; free the leftover conn after srv drops its ref. */
                    net_fs_file_destroy(srv_f);
                    kfree(conn);
                    return ret_err(EAGAIN);
                }

                s->connected = 1;
                s->unix_conn = conn;
                s->unix_end = 0;
                memset(s->unix_path, 0, sizeof(s->unix_path));
                memcpy(s->unix_path, upath, (size_t)plen);
                s->unix_path_len = plen;
                s->unix_abstract = is_abs ? 1 : 0;
                return 0;
            }
            sockaddr_in_k to;
            {
                int pa = user_sockaddr_to_ipv4_peer(addr_u, addrlen, &to);
                if (pa != 0) return ret_err(pa);
            }
            /* Inet peer: must not leave unix stub short-circuit in read/write/sendto paths. */
            s->unix_domain_stub = 0;
            if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                s->connected = 1;
                uint32_t pip = be32(to.sin_addr);
                uint16_t pp = be16(to.sin_port);
                /* resolv.conf on Linux often uses 127.0.0.53/127.0.0.1 — redirect to real DNS. */
                if (pp == 53u && (pip & 0xFF000000u) == 0x7F000000u) {
                    if (net_ensure_ipv4() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) pip = ns;
                    }
                }
                s->peer_ip_be = pip;
                s->peer_port = pp;
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                return 0;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                /* Linux sockaddr: sin_addr is in_addr (wire octets in LE uint32); be32 -> internal MSB-first. */
                uint32_t dst_ip_be = be32(to.sin_addr);
                uint16_t dport = be16(to.sin_port);
                /* glibc may try TCP to 127.0.0.1/127.0.0.53 :53 first; bridge to real nameserver over UDP. */
                if (dport == 53u) {
                    if (net_ensure_ipv4() != 0) return ret_err(ENETDOWN);
                    uint32_t peer = dst_ip_be;
                    if ((dst_ip_be & 0xFF000000u) == 0x7F000000u) {
                        peer = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (peer == 0) return ret_err(ENETDOWN);
                    }
                    s->connected = 1;
                    s->peer_ip_be = peer;
                    s->peer_port = dport;
                    if (s->local_port == 0)
                        s->local_port = net_alloc_ephemeral_port();
                    s->dns_tcp_udp_bridge = 1;
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    return 0;
                }
                if (ip_is_loopback_be(dst_ip_be)) {
                    if (s->local_port == 0)
                        s->local_port = net_alloc_ephemeral_port();
                    {
                        int lr = lo_tcp_stream_connect(s, dst_ip_be, dport, t);
                        if (lr != 0) return ret_err(lr);
                    }
                    return 0;
                }
                if (net_ensure_ipv4() != 0) return ret_err(ENETDOWN);
                /* Must check before teardown — curl may poll-retry the same fd. */
                if (s->tcp.connect_pending && !s->tcp.established)
                    return ret_err(EALREADY);
                if (s->connected && s->tcp.established)
                    return ret_err(EISCONN);
                if (s->tcp.used) {
                    net_tcp_ops_t close_ops;
                    net_make_tcp_ops(&close_ops, &s->tcp);
                    (void)net_tcp_close(&s->tcp, &close_ops, 500);
                }
                memset(&s->tcp, 0, sizeof(s->tcp));
                s->dns_tcp_udp_bridge = 0;
                s->connected = 0;
                net_rxq_flush();
                s->peer_ip_be = dst_ip_be;
                s->peer_port = dport;
                /* Fresh local port on redirect/reconnect (avoids TIME_WAIT / NAT confusion). */
                s->local_port = net_alloc_ephemeral_port();
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                {
                    uint32_t nh = ip_same_subnet(s->peer_ip_be, g_net.ip_be, g_net.mask_be)
                        ? s->peer_ip_be : g_net.gw_be;
                    uint8_t nh_mac[6];
                    if (nh == g_net.gw_be && g_net.gw_mac_valid) {
                        memcpy(nh_mac, g_net.gw_mac, 6);
                    } else if (net_resolve_mac(nh, nh_mac, 3000) != 0) {
                        return ret_err(net_l3_send_errno());
                    } else if (nh == g_net.gw_be) {
                        memcpy(g_net.gw_mac, nh_mac, 6);
                        g_net.gw_mac_valid = 1;
                    }
                    memcpy(g_tcp_xmit_mac, nh_mac, 6);
                    g_tcp_xmit_mac_valid = 1;
                    net_tcp_stage_peer_mac(&s->tcp, nh_mac);
                }
                /* ARP wait may have filled RXQ with unrelated frames — clear before SYN. */
                net_rxq_flush();
                net_nic_drain_connect_priority(&s->tcp, 16);
#if NET_TCP_TRACE
                klogprintf("tcp: connect2 dst=%u.%u.%u.%u:%u sport=%u nb=%d gwmac=%d nh=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                    (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                    (unsigned)dport, (unsigned)s->local_port, s->nonblock, g_net.gw_mac_valid,
                    g_tcp_xmit_mac[0], g_tcp_xmit_mac[1], g_tcp_xmit_mac[2],
                    g_tcp_xmit_mac[3], g_tcp_xmit_mac[4], g_tcp_xmit_mac[5]);
                g_net_tcp_sniff_left = 32;
#else
                g_net_tcp_sniff_left = 0;
#endif
                /* Linux: O_NONBLOCK connect sends SYN and returns EINPROGRESS;
                 * completion is via poll/select + SO_ERROR. curl/musl rely on this. */
                uint32_t conn_tmo = s->nonblock ? 0u : 6000u;
                g_net_tcp_connect_active = 1;
                int rc = net_tcp_connect(&s->tcp, &ops, s->peer_ip_be, s->peer_port, s->local_port, conn_tmo);
                g_net_tcp_connect_active = 0;
                g_net_tcp_sniff_left = 0;
                if (!s->tcp.peer_mac_valid && g_tcp_xmit_mac_valid)
                    net_tcp_stage_peer_mac(&s->tcp, g_tcp_xmit_mac);
                g_tcp_xmit_mac_valid = 0;
                if (s->nonblock && rc == 0 && s->tcp.connect_pending && !s->tcp.established) {
                    s->connected = 0;
                    return ret_err(EINPROGRESS);
                }
                if (rc == -3) {
                    klogprintf("tcp: connect refused dst=%u.%u.%u.%u:%u\n",
                        (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                        (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                        (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(ECONNREFUSED);
                }
                if (rc == -2) {
                    e1000_stats_t est;
                    if (e1000_get_stats(&est) == 0)
                        klogprintf("tcp: timeout dst=%u.%u.%u.%u:%u peer_pkts=%d nic_tx=%u nic_rx=%u\n",
                            (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                            (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                            (unsigned)dport, s->tcp.connect_peer_pkts,
                            (unsigned)est.tx_packets, (unsigned)est.rx_packets);
                    else
                        klogprintf("tcp: connect timeout dst=%u.%u.%u.%u:%u\n",
                            (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                            (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                            (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(ETIMEDOUT);
                }
                if (rc != 0) {
                    klogprintf("tcp: connect failed rc=%d dst=%u.%u.%u.%u:%u\n", rc,
                        (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                        (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                        (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(EIO);
                }
                klogprintf("tcp: connected dst=%u.%u.%u.%u:%u\n",
                    (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                    (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                    (unsigned)dport);
                s->connected = 1;
                return 0;
            }
            return 0;
        }
        case 51: { /* getsockname */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->unix_domain_stub) {
                /* Linux unix_getname: family + sun_path (pathname or abstract). */
                uint8_t sa[2 + 108];
                memset(sa, 0, sizeof(sa));
                uint16_t fam = AF_UNIX_LOCAL;
                memcpy(sa, &fam, sizeof(fam));
                int plen = s->unix_path_len;
                if (plen < 0) plen = 0;
                if (plen > 108) plen = 108;
                if (plen > 0)
                    memcpy(sa + 2, s->unix_path, (size_t)plen);
                uint32_t want = (uint32_t)(2 + plen);
                uint32_t copy_len = (ulen < want) ? ulen : want;
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = want;
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_pid ? s->nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                sa.nl_groups = s->nl_groups;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            if (s->ipv6_stub) {
                sockaddr_in6_k sa6;
                uint16_t lport = 0;
                if ((s->type_base == SOCK_DGRAM_LOCAL || s->type_base == SOCK_STREAM_LOCAL) && s->local_port)
                    lport = s->local_port;
                sockaddr_in6_v4mapped_fill(&sa6, g_net.ip_be, lport);
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa6)) ? ulen : (uint32_t)sizeof(sa6);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa6, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa6);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_addr = be32(g_net.ip_be);
            if ((s->type_base == SOCK_DGRAM_LOCAL || s->type_base == SOCK_STREAM_LOCAL) && s->local_port) {
                sa.sin_port = be16(s->local_port);
            }

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 52: { /* getpeername */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!s->connected) return ret_err(ENOTCONN);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->unix_domain_stub) {
                /* Linux unix_getname: family + sun_path (pathname or abstract). */
                uint8_t sa[2 + 108];
                memset(sa, 0, sizeof(sa));
                uint16_t fam = AF_UNIX_LOCAL;
                memcpy(sa, &fam, sizeof(fam));
                int plen = s->unix_path_len;
                if (plen < 0) plen = 0;
                if (plen > 108) plen = 108;
                if (plen > 0)
                    memcpy(sa + 2, s->unix_path, (size_t)plen);
                uint32_t want = (uint32_t)(2 + plen);
                uint32_t copy_len = (ulen < want) ? ulen : want;
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = want;
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_peer_pid;
                sa.nl_groups = 0;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            if (s->ipv6_stub) {
                sockaddr_in6_k sa6;
                sockaddr_in6_v4mapped_fill(&sa6, s->peer_ip_be, s->peer_port);
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa6)) ? ulen : (uint32_t)sizeof(sa6);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa6, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa6);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_port = be16(s->peer_port);
            sa.sin_addr = be32(s->peer_ip_be);

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 54: { /* setsockopt */
            int fd = (int)a1;
            int level = (int)a2;
            int optname = (int)a3;
            const void *optval_u = (const void *)(uintptr_t)a4;
            size_t optlen = (size_t)a5;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            enum {
                SOL_SOCKET_LOCAL = 1,
                SO_REUSEADDR_LOCAL = 2,
                SO_REUSEPORT_LOCAL = 15,
                SOL_IPV6_LOCAL = 41,
                IPV6_V6ONLY_LOCAL = 26
            };
            if (level == SOL_SOCKET_LOCAL &&
                (optname == SO_REUSEADDR_LOCAL || optname == SO_REUSEPORT_LOCAL)) {
                int on = 1;
                if (optval_u && optlen >= sizeof(int) && user_range_ok(optval_u, sizeof(int))) {
                    if (copy_from_user_raw(&on, optval_u, sizeof(int)) != 0)
                        return ret_err(EFAULT);
                }
                s->reuseaddr = on ? 1 : 0;
                return 0;
            }
            if (level == SOL_IPV6_LOCAL && optname == IPV6_V6ONLY_LOCAL) {
                int on = 0;
                if (optval_u && optlen >= sizeof(int) && user_range_ok(optval_u, sizeof(int))) {
                    if (copy_from_user_raw(&on, optval_u, sizeof(int)) != 0)
                        return ret_err(EFAULT);
                }
                /* Meaningful on AF_INET6 stubs; harmless no-op storage on IPv4. */
                s->ipv6_only = on ? 1 : 0;
                return 0;
            }
            (void)level;
            (void)optname;
            (void)optval_u;
            (void)optlen;
            return 0;
        }
        case 55: { /* getsockopt */
            int fd = (int)a1;
            int level = (int)a2;
            int optname = (int)a3;
            void *optval_u = (void *)(uintptr_t)a4;
            void *optlen_u = (void *)(uintptr_t)a5;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!optlen_u || !user_range_ok(optlen_u, 4)) return ret_err(EFAULT);
            uint32_t olen = 0;
            if (copy_from_user_raw(&olen, optlen_u, 4) != 0) return ret_err(EFAULT);
            enum {
                SOL_SOCKET_LOCAL = 1,
                SO_ERROR_LOCAL = 4,
                SOL_IPV6_LOCAL = 41,
                IPV6_V6ONLY_LOCAL = 26
            };
            if (level == SOL_SOCKET_LOCAL && optname == SO_ERROR_LOCAL &&
                s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge &&
                optval_u && olen >= 4) {
                int soerr = 0;
                if (s->tcp.connect_pending) {
                    /* Still in progress: Linux reports 0 here; EINPROGRESS is only from connect(). */
                    soerr = 0;
                } else if (s->tcp.connect_refused) {
                    soerr = ECONNREFUSED;
                    s->tcp.connect_refused = 0; /* Linux: SO_ERROR clears on read */
                } else if (s->tcp.peer_rst) {
                    soerr = ECONNRESET;
                }
                if (copy_to_user_safe(optval_u, &soerr, 4) != 0) return ret_err(EFAULT);
                olen = 4;
                if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (level == SOL_IPV6_LOCAL && optname == IPV6_V6ONLY_LOCAL &&
                optval_u && olen >= 4) {
                int on = s->ipv6_only ? 1 : 0;
                if (copy_to_user_safe(optval_u, &on, 4) != 0) return ret_err(EFAULT);
                olen = 4;
                if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (optval_u && olen >= 4) {
                uint32_t zero = 0;
                if (copy_to_user_safe(optval_u, &zero, 4) != 0) return ret_err(EFAULT);
                olen = 4;
            } else {
                olen = 0;
            }
            if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 44: { /* sendto */
            int fd = (int)a1;
            const void *buf_u = (const void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            const void *to_u = (const void *)(uintptr_t)a5;
            size_t tolen = (size_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] &&
                           (strstr(t->name, "wget") || strstr(t->name, "curl"));
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!buf_u || len == 0) return ret_err(EINVAL);
                if (len < sizeof(nlmsghdr_k) || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                uint8_t pkt[256];
                size_t cp = (len > sizeof(pkt)) ? sizeof(pkt) : len;
                if (copy_from_user_raw(pkt, buf_u, cp) != 0) return ret_err(EFAULT);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > len) return ret_err(EINVAL);
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                if (netlink_apply_request(s, pkt, cp) != 0)
                    return ret_err(EINVAL);
                return (uint64_t)len;
            }
            if (s->sock_domain == AF_PACKET_LOCAL) {
                if (!buf_u || len == 0 || len > 2048) return ret_err(EINVAL);
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                uint8_t dst_mac[6];
                memset(dst_mac, 0xff, 6);
                if (to_u) {
                    if (tolen < sizeof(sockaddr_ll_k) || !user_range_ok(to_u, sizeof(sockaddr_ll_k)))
                        return ret_err(EFAULT);
                    sockaddr_ll_k sll;
                    if (copy_from_user_raw(&sll, to_u, sizeof(sll)) != 0) return ret_err(EFAULT);
                    if (sll.sll_family != AF_PACKET_LOCAL) return ret_err(EAFNOSUPPORT);
                    if (sll.sll_halen >= 6)
                        memcpy(dst_mac, sll.sll_addr, 6);
                    if (sll.sll_ifindex)
                        s->packet_ifindex = sll.sll_ifindex;
                }
                uint8_t *pkt = (uint8_t *)kmalloc(len);
                if (!pkt) return ret_err(ENOMEM);
                if (copy_from_user_raw(pkt, buf_u, len) != 0) { kfree(pkt); return ret_err(EFAULT); }
                int r = net_packet_send_frame(s, dst_mac, pkt, len);
                kfree(pkt);
                if (r != 0)
                    return ret_err((g_net.if_up && e1000_is_ready()) ?
                                   EIO : ENETDOWN);
                return (uint64_t)len;
            }
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                /* SOCK_DGRAM connect to /dev/log succeeds without a peer.
                 * Discard the datagram (vsyslog then falls through cleanly)
                 * instead of sleeping in the stream writer with unix_conn=NULL. */
                if (s->type_base != SOCK_STREAM_LOCAL || !s->unix_conn)
                    return (uint64_t)len;
                ssize_t wr = unix_stream_write_from_user(s, buf_u, len);
                if (wr < 0) return ret_err((int)(-wr));
                return (uint64_t)wr;
            }
            /* glibc send(2) -> sendto; OpenSSL wget uses this for TLS on :443. */
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (!buf_u || len == 0) return ret_err(EINVAL);
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->unix_conn) {
                    if (!s->connected) return ret_err(ENOTCONN);
                    ssize_t wr = net_sock_write_userspace(t, fd, s, buf_u, len);
                    if (wr < 0) return ret_err((int)-wr);
                    return (uint64_t)wr;
                }
                if (s->tcp.peer_rst) return ret_err(ECONNRESET);
                if (s->tcp.peer_fin) return ret_err(EPIPE);
                if (!s->connected || !s->tcp.established) return ret_err(ENOTCONN);
                ssize_t wr = net_sock_write_userspace(t, fd, s, buf_u, len);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }
            if (!buf_u || len == 0 || len > 2048) return ret_err(EINVAL);
            if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (to_u) {
                if (tolen < 2u || !user_range_ok(to_u, tolen)) return ret_err(EFAULT);
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(to_u, (size_t)tolen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr); /* user sockaddr stores network-order bytes */
                dst_port = be16(to.sin_port);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                    if (dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_ensure_ipv4() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) dst_ip_be = ns;
                    }
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                return ret_err(EDESTADDRREQ);
            }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto fd=%d len=%u dst=%u.%u.%u.%u:%u\n",
                    fd, (unsigned)len,
                    (unsigned)((dst_ip_be >> 24) & 0xFF), (unsigned)((dst_ip_be >> 16) & 0xFF),
                    (unsigned)((dst_ip_be >> 8) & 0xFF), (unsigned)(dst_ip_be & 0xFF),
                    (unsigned)dst_port);
            }
            uint8_t *icmp = (uint8_t *)kmalloc(len);
            if (!icmp) return ret_err(ENOMEM);
            if (copy_from_user_raw(icmp, buf_u, len) != 0) { kfree(icmp); return ret_err(EFAULT); }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u && len >= 12) {
                uint16_t id = (uint16_t)(((uint16_t)icmp[0] << 8) | (uint16_t)icmp[1]);
                uint16_t flags_d = (uint16_t)(((uint16_t)icmp[2] << 8) | (uint16_t)icmp[3]);
                uint16_t qd = (uint16_t)(((uint16_t)icmp[4] << 8) | (uint16_t)icmp[5]);
                uint16_t an = (uint16_t)(((uint16_t)icmp[6] << 8) | (uint16_t)icmp[7]);
                uint16_t ns = (uint16_t)(((uint16_t)icmp[8] << 8) | (uint16_t)icmp[9]);
                uint16_t ar = (uint16_t)(((uint16_t)icmp[10] << 8) | (uint16_t)icmp[11]);
                klogprintf("WGET-DNS: qhdr id=0x%04x flags=0x%04x qd=%u an=%u ns=%u ar=%u\n",
                    (unsigned)id, (unsigned)flags_d,
                    (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
            }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && len > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp + 8, len - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp, len);
                s->last_req_len = len;
                memcpy(s->last_req, icmp, len);
                r = net_send_icmp_echo(s, dst_ip_be, icmp, len);
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, icmp, len);
            }
            kfree(icmp);
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto result r=%d local_port=%u\n", r, (unsigned)s->local_port);
            }
            if (r != 0) return ret_err(net_l3_send_errno());
            return (uint64_t)len;
        }
        case 45: { /* recvfrom */
            int fd = (int)a1;
            void *buf_u = (void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            int flags = (int)a4;
            void *from_u = (void *)(uintptr_t)a5;
            void *fromlen_u = (void *)(uintptr_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (len == 0) return 0;
                if (!buf_u || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return 0;
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > len) ? len : avail;
                if (copy_to_user_safe(buf_u, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK=0x2 */
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_nl_k) && user_range_ok(from_u, sizeof(sockaddr_nl_k))) {
                        sockaddr_nl_k sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.nl_family = AF_NETLINK_LOCAL;
                        sa.nl_pid = 0; /* kernel */
                        sa.nl_groups = 0;
                        (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                        flen = sizeof(sa);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)ncopy;
            }
            if (s->sock_domain == AF_PACKET_LOCAL) {
                if (len == 0) return 0;
                if (!buf_u || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                enum { MSG_PEEK_PKT = 0x2 };
                int is_peek = (flags & MSG_PEEK_PKT) ? 1 : 0;
                uint32_t wait_ms = s->nonblock ? 0u : 5000u;
                uint8_t *tmp = (uint8_t *)kmalloc(len > 8192 ? 8192 : len);
                if (!tmp) return ret_err(ENOMEM);
                size_t cap = len > 8192 ? 8192 : len;
                int n = net_packet_sock_recv(s, tmp, cap, is_peek, wait_ms);
                if (n < 0) { kfree(tmp); return ret_err(-n); }
                if (n > 0 && copy_to_user_safe(buf_u, tmp, (size_t)n) != 0) {
                    kfree(tmp);
                    return ret_err(EFAULT);
                }
                kfree(tmp);
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 &&
                        flen >= sizeof(sockaddr_ll_k) && user_range_ok(from_u, sizeof(sockaddr_ll_k))) {
                        sockaddr_ll_k sll;
                        memset(&sll, 0, sizeof(sll));
                        sll.sll_family = AF_PACKET_LOCAL;
                        sll.sll_protocol = be16(s->packet_proto_host);
                        sll.sll_ifindex = s->packet_ifindex ? s->packet_ifindex : 2;
                        sll.sll_halen = 6;
                        (void)copy_to_user_safe(from_u, &sll, sizeof(sll));
                        flen = sizeof(sll);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)n;
            }
            /* Linux-compatible: zero-length recv is valid even with NULL buffer. */
            if (len == 0) return 0;
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                ssize_t rr = unix_stream_read_to_user(s, buf_u, len, (flags & 0x2) ? 1 : 0);
                if (rr < 0) return ret_err((int)(-rr));
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= 2 && user_range_ok(from_u, 2)) {
                        uint16_t fam = 1;
                        (void)copy_to_user_safe(from_u, &fam, sizeof(fam));
                        flen = 2;
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)rr;
            }
            if (!buf_u) {
                if (dbg_wget) qemu_debug_printf("RECVFROM-EFAULT: null buf with len=%llu\n", (unsigned long long)len);
                return ret_err(EFAULT);
            }
            /* glibc recv(2) -> recvfrom; OpenSSL wget uses this for TLS on :443. */
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->unix_conn) {
                    if (!s->connected) return ret_err(ENOTCONN);
                    ssize_t rr = net_sock_read_userspace(t, s, buf_u, len);
                    if (rr < 0) return ret_read_err(rr);
                    return (uint64_t)rr;
                }
                if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
                if ((!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) && s->tcp.rx_len == 0) return ret_err(ENOTCONN);
                ssize_t rr = net_sock_read_userspace(t, s, buf_u, len);
                if (rr < 0) return ret_read_err(rr);
                if (rr == 0) return 0;
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_in_k) && user_range_ok(from_u, sizeof(sockaddr_in_k))) {
                        sockaddr_in_k sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family = AF_INET_LOCAL;
                        sa.sin_port = be16(s->peer_port);
                        sa.sin_addr = be32(s->peer_ip_be);
                        (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                        flen = sizeof(sa);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)rr;
            }
            size_t cap = len;
            if (cap > 8192) cap = 8192; /* defensive cap to avoid huge temporary allocations */
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                    if (n >= 12) {
                        /* DNS header: id, flags, qd, an, ns, ar */
                        uint16_t id = (uint16_t)(((uint16_t)tmp[0] << 8) | (uint16_t)tmp[1]);
                        uint16_t flags_d = (uint16_t)(((uint16_t)tmp[2] << 8) | (uint16_t)tmp[3]);
                        uint8_t rcode = (uint8_t)(flags_d & 0x0Fu);
                        uint16_t qd = (uint16_t)(((uint16_t)tmp[4] << 8) | (uint16_t)tmp[5]);
                        uint16_t an = (uint16_t)(((uint16_t)tmp[6] << 8) | (uint16_t)tmp[7]);
                        uint16_t ns = (uint16_t)(((uint16_t)tmp[8] << 8) | (uint16_t)tmp[9]);
                        uint16_t ar = (uint16_t)(((uint16_t)tmp[10] << 8) | (uint16_t)tmp[11]);
                        klogprintf("WGET-DNS: hdr id=0x%04x flags=0x%04x rcode=%u qd=%u an=%u ns=%u ar=%u\n",
                            (unsigned)id, (unsigned)flags_d, (unsigned)rcode,
                            (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
                        int dump = (n < 32) ? n : 32;
                        klogprintf("WGET-DNS: hex0..%d:", dump - 1);
                        for (int i = 0; i < dump; i++) qemu_debug_printf(" %02x", (unsigned)tmp[i]);
                        qemu_debug_printf("\n");
                    }
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL)
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(buf_u, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)buf_u;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVFROM-EFAULT: copy buf=%p n=%d us=0x%llx ue=0x%llx\n",
                        buf_u, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                uint32_t flen = 0;
                if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_in_k) && user_range_ok(from_u, sizeof(sockaddr_in_k))) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(src_port);
                    sa.sin_addr = be32(src_ip); /* keep sockaddr in network byte order */
                    (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                    uint32_t out_len = sizeof(sa);
                    (void)copy_to_user_safe(fromlen_u, &out_len, 4);
                }
            }
            return (uint64_t)n;
        }
        case 46: { /* sendmsg -> map to sendto for first iov */
            int fd = (int)a1;
            const void *msg_u = (const void *)(uintptr_t)a2;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || m.msg_iovlen > 64 ||
                !user_range_ok(m.msg_iov, (size_t)m.msg_iovlen * 16u))
                return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov[64];
            if (copy_from_user_raw(iov, m.msg_iov, (size_t)m.msg_iovlen * sizeof(iov[0])) != 0)
                return ret_err(EFAULT);
            uint64_t sum64 = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++)
                sum64 += iov[i].len;
            if (sum64 == 0) return 0;
            if (sum64 > 65536u) return ret_err(EINVAL);
            size_t sum = (size_t)sum64;
            uint8_t *flat = (uint8_t *)kmalloc(sum);
            if (!flat) return ret_err(ENOMEM);
            size_t at = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                size_t ilen = (size_t)iov[i].len;
                if (ilen == 0) continue;
                if (!iov[i].base || !user_range_ok(iov[i].base, ilen)) {
                    kfree(flat);
                    return ret_err(EFAULT);
                }
                if (copy_from_user_raw(flat + at, iov[i].base, ilen) != 0) {
                    kfree(flat);
                    return ret_err(EFAULT);
                }
                at += ilen;
            }
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) {
                kfree(flat);
                return ret_err(EBADF);
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                uint8_t pkt[256];
                size_t cp = (sum > sizeof(pkt)) ? sizeof(pkt) : sum;
                memcpy(pkt, flat, cp);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > sum) {
                    kfree(flat);
                    return ret_err(EINVAL);
                }
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                if (netlink_apply_request(s, flat, sum) != 0) {
                    kfree(flat);
                    return ret_err(EINVAL);
                }
                kfree(flat);
                return (uint64_t)sum;
            }
            if (s->unix_domain_stub) {
                if (!s->connected) { kfree(flat); return ret_err(ENOTCONN); }
                if (s->type_base != SOCK_STREAM_LOCAL || !s->unix_conn) {
                    kfree(flat);
                    return (uint64_t)sum;
                }
                size_t written = 0;
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    ssize_t part = unix_stream_write_from_user(s, iov[i].base, ilen);
                    if (part < 0) {
                        kfree(flat);
                        return written ? (uint64_t)written : ret_err((int)(-part));
                    }
                    written += (size_t)part;
                    if ((size_t)part < ilen)
                        break;
                }
                kfree(flat);
                return (uint64_t)written;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (s->unix_conn) {
                    if (!s->connected) { kfree(flat); return ret_err(ENOTCONN); }
                    size_t written = 0;
                    for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                        size_t ilen = (size_t)iov[i].len;
                        if (ilen == 0) continue;
                        ssize_t part = unix_stream_write_from_user(s, iov[i].base, ilen);
                        if (part < 0) {
                            kfree(flat);
                            return written ? (uint64_t)written : ret_err((int)(-part));
                        }
                        written += (size_t)part;
                        if ((size_t)part < ilen) break;
                    }
                    kfree(flat);
                    return (uint64_t)written;
                }
                if (s->tcp.peer_rst) { kfree(flat); return ret_err(ECONNRESET); }
                if (s->tcp.peer_fin) { kfree(flat); return ret_err(EPIPE); }
                if (!s->connected || !s->tcp.established) { kfree(flat); return ret_err(ENOTCONN); }
                size_t total = 0;
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                while (total < sum) {
                    size_t chunk = sum - total;
                    if (chunk > 4096) chunk = 4096;
                    if (total == 0)
                        net_debug_log_tls443_tx(s, flat, chunk, "sendmsg");
                    int wr = net_tcp_send(&s->tcp, &ops, flat + total, chunk, 30000);
                    if (wr < 0) {
                        kfree(flat);
                        return total ? (uint64_t)total : ret_err(EIO);
                    }
                    total += (size_t)wr;
                    if ((size_t)wr < chunk)
                        break;
                }
                (void)net_tcp_flush_tx(&s->tcp, &ops, 250);
                for (int p = 0; p < 2; p++) {
                    e1000_poll();
                    (void)net_tcp_service(&s->tcp, &ops, 8);
                    if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst)
                        break;
                }
                kfree(flat);
                return (uint64_t)total;
            }
            if (sum > 2048) {
                kfree(flat);
                return ret_err(EINVAL);
            }
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (m.msg_name && m.msg_namelen >= 2u && user_range_ok(m.msg_name, (size_t)m.msg_namelen)) {
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(m.msg_name, (size_t)m.msg_namelen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr);
                dst_port = be16(to.sin_port);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) &&
                    dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_ensure_ipv4() == 0) {
                    uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                    if (ns) dst_ip_be = ns;
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                kfree(flat);
                return ret_err(EDESTADDRREQ);
            }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && sum > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(flat + 8, sum - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(flat, sum);
                s->last_req_len = sum;
                memcpy(s->last_req, flat, sum);
                r = net_send_icmp_echo(s, dst_ip_be, flat, sum);
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, flat, sum);
            }
            kfree(flat);
            if (r != 0) return ret_err(net_l3_send_errno());
            return (uint64_t)sum;
        }
        case 307: { /* sendmmsg: minimal, first message only */
            int fd = (int)a1;
            void *mmsg_u = (void *)(uintptr_t)a2;
            uint32_t vlen = (uint32_t)a3;
            int flags = (int)a4;
            if (!mmsg_u || vlen == 0) return ret_err(EFAULT);
            /* struct mmsghdr begins with struct msghdr, so first entry pointer is msg pointer. */
            uint64_t r = syscall_do_inner(46, (uint64_t)fd, (uint64_t)(uintptr_t)mmsg_u, (uint64_t)flags, 0, 0, 0);
            if ((int64_t)r < 0) return r;
            /* mmsghdr.msg_len sits right after msghdr (56 bytes on x86_64 ABI used above). */
            if (user_range_ok((uint8_t *)mmsg_u + 56, 4)) {
                uint32_t mlen = (uint32_t)r;
                (void)copy_to_user_safe((uint8_t *)mmsg_u + 56, &mlen, sizeof(mlen));
            }
            return 1;
        }
        case 47: { /* recvmsg */
            int fd = (int)a1;
            void *msg_u = (void *)(uintptr_t)a2;
            int flags = (int)a3;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || m.msg_iovlen > 64 ||
                !user_range_ok(m.msg_iov, (size_t)m.msg_iovlen * 16u))
                return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov[64];
            if (copy_from_user_raw(iov, m.msg_iov, (size_t)m.msg_iovlen * sizeof(iov[0])) != 0)
                return ret_err(EFAULT);
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] &&
                           (strstr(t->name, "wget") || strstr(t->name, "curl"));
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (iov[0].len == 0) return 0;
                if (!iov[0].base || !user_range_ok(iov[0].base, (size_t)iov[0].len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return 0;
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > (size_t)iov[0].len) ? (size_t)iov[0].len : avail;
                if (copy_to_user_safe(iov[0].base, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK */
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_nl_k) && user_range_ok(m.msg_name, sizeof(sockaddr_nl_k))) {
                    sockaddr_nl_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.nl_family = AF_NETLINK_LOCAL;
                    sa.nl_pid = 0; /* kernel */
                    (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
                }
                if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                    m.msg_namelen = sizeof(sockaddr_nl_k);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)ncopy;
            }
            if (s->sock_domain == AF_PACKET_LOCAL) {
                size_t cap = (size_t)iov[0].len;
                if (cap == 0) return 0;
                if (!iov[0].base || !user_range_ok(iov[0].base, cap)) return ret_err(EFAULT);
                if (cap > 8192) cap = 8192;
                enum { MSG_PEEK_PKT = 0x2 };
                int is_peek = (flags & MSG_PEEK_PKT) ? 1 : 0;
                uint32_t wait_ms = s->nonblock ? 0u : 5000u;
                uint8_t *tmp = (uint8_t *)kmalloc(cap);
                if (!tmp) return ret_err(ENOMEM);
                int n = net_packet_sock_recv(s, tmp, cap, is_peek, wait_ms);
                if (n < 0) { kfree(tmp); return ret_err(-n); }
                if (n > 0 && copy_to_user_safe(iov[0].base, tmp, (size_t)n) != 0) {
                    kfree(tmp);
                    return ret_err(EFAULT);
                }
                kfree(tmp);
                /* PACKET_AUXDATA optional — leave msg_control untouched / empty. */
                if (m.msg_control && m.msg_controllen && user_range_ok(m.msg_control, 4)) {
                    /* Report zero control data (udhcpc tolerates missing AUXDATA). */
                    m.msg_controllen = 0;
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_ll_k) &&
                    user_range_ok(m.msg_name, sizeof(sockaddr_ll_k))) {
                    sockaddr_ll_k sll;
                    memset(&sll, 0, sizeof(sll));
                    sll.sll_family = AF_PACKET_LOCAL;
                    sll.sll_protocol = be16(s->packet_proto_host);
                    sll.sll_ifindex = s->packet_ifindex ? s->packet_ifindex : 2;
                    sll.sll_halen = 6;
                    (void)copy_to_user_safe(m.msg_name, &sll, sizeof(sll));
                    m.msg_namelen = sizeof(sll);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)n;
            }
            /* Linux-compatible: zero-length recvmsg iov is valid. */
            uint64_t want64 = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++)
                want64 += iov[i].len;
            if (want64 == 0) return 0;
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    if (iov[i].len == 0) continue;
                    if (!iov[i].base || !user_range_ok(iov[i].base, (size_t)iov[i].len))
                        return ret_err(EFAULT);
                }
                size_t cap = (want64 > 65536u) ? 65536u : (size_t)want64;
                uint8_t *tmp = (uint8_t *)kmalloc(cap);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = unix_stream_read_to_user(s, tmp, cap, (flags & 0x2) ? 1 : 0);
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err((int)(-rr));
                }
                size_t left = (size_t)rr;
                size_t at = 0;
                for (uint64_t i = 0; i < m.msg_iovlen && left > 0; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    size_t cp = (ilen > left) ? left : ilen;
                    if (copy_to_user_safe(iov[i].base, tmp + at, cp) != 0) {
                        kfree(tmp);
                        return ret_err(EFAULT);
                    }
                    at += cp;
                    left -= cp;
                    if (cp < ilen)
                        break;
                }
                kfree(tmp);
                if (m.msg_name && m.msg_namelen >= 2 && user_range_ok(m.msg_name, 2)) {
                    uint16_t fam = 1;
                    (void)copy_to_user_safe(m.msg_name, &fam, sizeof(fam));
                    m.msg_namelen = 2;
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)rr;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
                if ((!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) && s->tcp.rx_len == 0) return ret_err(ENOTCONN);
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    if (iov[i].len == 0) continue;
                    if (!iov[i].base || !user_range_ok(iov[i].base, (size_t)iov[i].len))
                        return ret_err(EFAULT);
                }
                size_t cap = (want64 > 65536u) ? 65536u : (size_t)want64;
                uint8_t *tmp = (uint8_t *)kmalloc(cap);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = net_sock_read_userspace(t, s, tmp, cap);
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err((int)-rr);
                }
                if (rr == 0) {
                    kfree(tmp);
                    return 0;
                }
                size_t left = (size_t)rr;
                size_t at = 0;
                for (uint64_t i = 0; i < m.msg_iovlen && left > 0; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    size_t cp = (ilen > left) ? left : ilen;
                    if (copy_to_user_safe(iov[i].base, tmp + at, cp) != 0) {
                        kfree(tmp);
                        return ret_err(EFAULT);
                    }
                    at += cp;
                    left -= cp;
                    if (cp < ilen)
                        break;
                }
                kfree(tmp);
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_in_k) && user_range_ok(m.msg_name, sizeof(sockaddr_in_k))) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(s->peer_port);
                    sa.sin_addr = be32(s->peer_ip_be);
                    (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
                }
                if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                    m.msg_namelen = sizeof(sockaddr_in_k);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)rr;
            }
            if (!iov[0].base) {
                if (dbg_wget) qemu_debug_printf("RECVMSG-EFAULT: null base with len=%llu\n", (unsigned long long)iov[0].len);
                return ret_err(EFAULT);
            }
            size_t cap = (size_t)iov[0].len;
            if (cap > 8192) cap = 8192;
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)iov[0].len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (iov[0].len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (iov[0].len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                    (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge))
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(iov[0].base, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)iov[0].base;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVMSG-EFAULT: copy base=%p n=%d us=0x%llx ue=0x%llx\n",
                        iov[0].base, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            uint32_t fromlen = sizeof(sockaddr_in_k);
            if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_in_k) && user_range_ok(m.msg_name, sizeof(sockaddr_in_k))) {
                sockaddr_in_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET_LOCAL;
                sa.sin_port = be16(src_port);
                sa.sin_addr = be32(src_ip);
                (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
            }
            /* keep msg_namelen in sync */
            if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                m.msg_namelen = fromlen;
                (void)copy_to_user_safe(msg_u, &m, sizeof(m));
            }
            return (uint64_t)n;
        }
        case 299: { /* recvmmsg — Linux x86_64; glibc resolver may batch reads */
            int fd = (int)a1;
            void *mmsg_u = (void *)(uintptr_t)a2;
            unsigned int vlen = (unsigned int)a3;
            int flags = (int)a4;
            (void)a5;
            if (!mmsg_u || vlen == 0) return ret_err(EINVAL);
            /* One struct mmsghdr: msghdr (matches our msghdr_k) + msg_len */
            if (!user_range_ok(mmsg_u, 64)) return ret_err(EFAULT);
            uint64_t r = syscall_do_inner(47, (uint64_t)fd, (uint64_t)mmsg_u, (uint64_t)flags, 0, 0, 0);
            if ((int64_t)r < 0) return r;
            uint32_t mlen = (uint32_t)r;
            /* After Linux struct msghdr (56 bytes on x86_64) */
            if (copy_to_user_safe((uint8_t *)mmsg_u + 56, &mlen, sizeof(mlen)) != 0) return ret_err(EFAULT);
            return 1;
        }
        case SYS_sysinfo: { /* sysinfo(struct sysinfo *) - syscall 99; glibc allocatestack needs sane freeram */
            void *info_u = (void*)(uintptr_t)a1;
            if (!info_u || (uintptr_t)info_u + 112 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* Linux struct sysinfo x86_64: uptime(0), loads[3](8), totalram(32), freeram(40), sharedram(48),
               bufferram(56), totalswap(64), freeswap(72), procs(80), pad(82), totalhigh(84), freehigh(92),
               mem_unit(100). glibc advise_stack_range: freesize from freeram*mem_unit; must be >= stack size. */
            uint8_t buf[128];
            memset(buf, 0, sizeof(buf));
            int64_t uptime_sec = (int64_t)(pit_get_time_ms() / 1000);
            memcpy(buf + 0, &uptime_sec, 8);
            unsigned long loads[3];
            loadavg_get_user(loads);
            memcpy(buf + 8, loads, 24);
            int ram_mb = sysinfo_ram_mb();
            uint64_t totalram;
            if (ram_mb > 0)
                totalram = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            else
                totalram = heap_total_bytes() ? (uint64_t)heap_total_bytes() : (256ULL * 1024ULL * 1024ULL);
            uint64_t used = (uint64_t)heap_used_bytes();
            /* Rough free: physical minus kernel heap used; never claim less than
             * 64MiB free or pthread/cgo stack allocation aborts. */
            uint64_t freeram = totalram > used + (64ULL * 1024ULL * 1024ULL)
                ? totalram - used
                : (totalram > (64ULL * 1024ULL * 1024ULL)
                   ? totalram / 2
                   : (64ULL * 1024ULL * 1024ULL));
            if (freeram > totalram)
                freeram = totalram;
            memcpy(buf + 32, &totalram, 8);
            memcpy(buf + 40, &freeram, 8);
            /* sharedram, bufferram at 48,56 = 0 */
            /* totalswap, freeswap at 64,72 = 0 */
            uint16_t procs = (uint16_t)thread_get_count();
            memcpy(buf + 80, &procs, 2);
            /* totalhigh, freehigh at 84,92 = 0 */
            uint32_t mem_unit = 1;
            memcpy(buf + 100, &mem_unit, 4);
            if (copy_to_user_safe(info_u, buf, 112) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getrlimit: { /* getrlimit(resource, rlim) */
            int resource = (int)a1;
            void *rlim_u = (void*)(uintptr_t)a2;
            if (!rlim_u || (uintptr_t)rlim_u + 16 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint64_t cur_val = 0, max_val = 0;
            if (rlimit_get(cur, resource, &cur_val, &max_val) != 0)
                return ret_err(EINVAL);
            if (copy_to_user_safe(rlim_u, &cur_val, sizeof(cur_val)) != 0) return ret_err(EFAULT);
            if (copy_to_user_safe((char*)rlim_u + 8, &max_val, sizeof(max_val)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_sched_getaffinity: { /* sched_getaffinity(pid, len, user_mask) */
            int pid = (int)a1;
            size_t len = (size_t)a2;
            void *mask_u = (void*)(uintptr_t)a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            if (!mask_u || len < 8 || (uintptr_t)mask_u + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint64_t mask = smp_default_affinity_mask();
            size_t copy = len < 8 ? len : 8;
            if (copy_to_user_safe(mask_u, &mask, copy) != 0) return ret_err(EFAULT);
            for (size_t i = 8; i < len; i++) {
                char zero = 0;
                if (copy_to_user_safe((char*)mask_u + i, &zero, 1) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_sched_setaffinity: {
            /* sched_setaffinity(pid, len, user_mask) — accept and ignore mask. */
            int pid = (int)a1;
            size_t len = (size_t)a2;
            const void *mask_u = (const void *)(uintptr_t)a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            if (len == 0 || !mask_u || !user_range_ok(mask_u, len))
                return ret_err(EFAULT);
            return 0;
        }
        case SYS_sched_setscheduler: {
            /* sched_setscheduler(pid, policy, param) — accept SCHED_OTHER only. */
            int pid = (int)a1;
            int policy = (int)a2;
            const void *param_u = (const void *)(uintptr_t)a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            if (policy != 0) /* SCHED_OTHER */
                return ret_err(EINVAL);
            if (param_u && !user_range_ok(param_u, 4))
                return ret_err(EFAULT);
            return 0;
        }
        case SYS_sched_getscheduler: {
            int pid = (int)a1;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            return 0; /* SCHED_OTHER */
        }
#ifndef PRIO_PROCESS
#define PRIO_PROCESS 0
#endif
        case SYS_getpriority: { /* getpriority(which, who) */
            int which = (int)a1;
            int who = (int)a2;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            thread_t *t = (who == 0) ? cur : thread_get(who);
            if (!t) return ret_err(ESRCH);
            /* Linux's raw syscall returns 20 - nice (1..40), avoiding
             * ambiguity between nice 0 and an error return. libc converts
             * this back to the public -20..19 API. */
            return (uint64_t)(20 - t->nice);
        }
        case SYS_setpriority: { /* setpriority(which, who, prio) — Linux nice -20..19 */
            int which = (int)a1;
            int who = (int)a2;
            int nicev = (int)a3;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            if (thread_nice_set(who, nicev) != 0) return ret_err(ESRCH);
            return 0;
        }
        case 62: { /* kill(pid, sig) */
            int pid = (int)a1;
            int sig = (int)a2;
            if (sig < 0 || sig > 63) return ret_err(EINVAL);
            /*
             * BusyBox waitfor(): after waitpid ECHILD it does kill(spawn_pid,0).
             * If spawn_pid == self (vfork child wrongly took the parent path),
             * kill succeeds forever → spin. Break that by returning ESRCH.
             */
            if (sig == 0 && pid > 0 && cur->wait4_last_echild &&
                (uint64_t)(unsigned)pid == process_pid(cur)) {
                cur->wait4_last_echild = 0;
                devel_printf("kill-break-waitfor-self: tid=%llu pid=%d\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1), pid);
                return ret_err(ESRCH);
            }
            /* Adopt a live process that claims us as parent_tid but is not
             * linked under our process — next wait4 can then see it. */
            if (sig == 0 && pid > 0 && cur->process) {
                process_t *target = process_find((uint64_t)(unsigned)pid);
                if (target && target != cur->process && target->leader &&
                    target->leader->parent_tid == (int)(cur->tid ? cur->tid : 1) &&
                    target->parent != cur->process) {
                    if (process_adopt_child(cur->process, target) == 0)
                        devel_printf("kill-adopt: parent_tid=%llu got pid=%d\n",
                            (unsigned long long)(cur->tid ? cur->tid : 1), pid);
                }
            }
            if (sig == 0)
                cur->wait4_last_echild = 0;
            /*
             * SIGKILL must tear the group down from the killer's context.
             * Pending-only delivery never runs while the victim sits in
             * poll/thread_sleep (udhcpc survived kill -9).
             */
            if (sig == SIGKILL) {
                process_t *matched[256];
                int n = process_collect_signal_targets(cur->process, pid,
                                                      matched, 256);
                int killed = 0;
                for (int i = 0; i < n; i++) {
                    thread_t *lead = matched[i] ? matched[i]->leader : NULL;
                    if (lead && force_sigkill_thread_group(lead))
                        killed++;
                }
                if (killed == 0 && pid > 0) {
                    /* /proc may expose a tid; resolve to the live task / TGID. */
                    thread_t *t = thread_get(pid);
                    if (t && t->state != THREAD_TERMINATED) {
                        if (t->process && t->process->leader)
                            t = t->process->leader;
                        if (force_sigkill_thread_group(t))
                            killed = 1;
                    }
                }
                return killed > 0 ? 0 : ret_err(ESRCH);
            }
            if (cur->process) {
                if (sig == 21 && cur->name[0] && strstr(cur->name, "/bin/sh"))
                    devel_printf("ash-jobctl: kill pid=%d sig=SIGTTIN pgid=%d sid=%d\n",
                            pid, cur->process->pgid, cur->process->sid);
                int count = process_signal_targets(cur->process, pid, sig);
                if (count == 0 && pid > 0) {
                    /*
                     * Fallback: pid may be a tid advertised by /proc when the
                     * task has no process_t yet, or TGID lookup missed a live
                     * thread. Linux kill(2) is TGID-based; once we resolve a
                     * live task, signal its thread group.
                     */
                    thread_t *t = thread_get(pid);
                    if (t && t->ring == 3 && t->state != THREAD_TERMINATED) {
                        if (t->process) {
                            count = process_signal_targets(cur->process,
                                                           (int)t->process->pid,
                                                           sig);
                        } else if (sig == 0) {
                            count = 1;
                        } else {
                            t->pending_signals |= (1ULL << (sig - 1));
                            if (t->state == THREAD_BLOCKED ||
                                t->state == THREAD_SLEEPING)
                                thread_unblock((int)(t->tid ? t->tid : 1));
                            count = 1;
                        }
                    }
                }
                return count > 0 ? 0 : ret_err(ESRCH);
            }
            if (pid > 0) {
                process_t *target_process =
                    process_find((uint64_t)(unsigned)pid);
                thread_t *t = target_process ? target_process->leader : NULL;
                if (!t || t->state == THREAD_TERMINATED) return ret_err(ESRCH);
                /* sig==0 used for existence check */
                if (sig == 0)
                    return 0;
                thread_set_pending_signal(t, sig);
                return 0;
            } else if (pid == 0) {
                /* Send to every live member of the caller's process group. */
                for (int i = 0; i < thread_get_count(); i++) {
                    thread_t *t = thread_get_by_index(i);
                    if (t && t->state != THREAD_TERMINATED && t->pgid == cur->pgid && sig != 0)
                        thread_set_pending_signal(t, sig);
                }
                return 0;
            } else {
                /* kill(-pgrp, sig) */
                int pgrp = -pid;
                int found = 0;
                for (int i = 0; i < thread_get_count(); i++) {
                    thread_t *t = thread_get_by_index(i);
                    if (!t || t->state == THREAD_TERMINATED || t->pgid != pgrp) continue;
                    found = 1;
                    if (sig != 0) thread_set_pending_signal(t, sig);
                }
                return found ? 0 : ret_err(ESRCH);
            }
        }
        case 32: { /* dup(oldfd) */
            int oldfd = (int)a1;
            if (oldfd < 0 || oldfd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = syscall_fd_get(cur, oldfd);
            if (!f) return ret_err(EBADF);
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                if (syscall_fd_get(cur, i) == NULL) {
                    cur->fds[i] = f;
                    if (cur->process)
                        cur->process->fds[i] = f;
                    if (f->refcount <= 0) f->refcount = 1;
                    else f->refcount++;
                    return (uint64_t)i;
                }
            }
            return ret_err(EMFILE);
        }
        case SYS_dup2: { /* dup2(oldfd, newfd) — Linux 33; getty/nano need this to dup TTY to stdin/stdout/stderr */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
        }
        case 269: /* faccessat(dirfd, pathname, mode, flags) */
        case 439: /* faccessat2(dirfd, pathname, mode, flags, ...) */
        {
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int mode = (int)a3;
            int flags = (int)a4;
            (void)mode; (void)flags;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* Same dirfd join as openat: base + "/" + path (do NOT dirname-strip). */
            {
                char path[512];
                int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
                if (rc < 0) return ret_err(-rc);
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                    pid1_dl_log_stat("faccessat-req", path);
                    kprintf("dl-trace faccessat req path=%s mode=0%o dirfd=%d flags=0x%x\n",
                        path, (unsigned)mode, dirfd, (unsigned)flags);
                }
                struct stat st;
                if (vfs_stat(path, &st) != 0) {
                    if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                        kprintf("dl-trace faccessat ENOENT path=%s mode=0%o dirfd=%d\n",
                            path, (unsigned)mode, dirfd);
                    return ret_err(ENOENT);
                }
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                    pid1_dl_log_stat("faccessat-ok", path);
                    kprintf("dl-trace faccessat ok path=%s mode=0%o dirfd=%d flags=0x%x\n",
                        path, (unsigned)mode, dirfd, (unsigned)flags);
                }
                return 0;
            }
        }
        case 72: { /* fcntl(fd, cmd, arg) - minimal support */
            int fd = (int)a1;
            int cmd = (int)a2;
            int arg = (int)a3;
            enum {
                F_DUPFD = 0,
                F_GETFD = 1,
                F_SETFD = 2,
                F_GETFL = 3,
                F_SETFL = 4,
                F_GETLK = 5,
                F_SETLK = 6,
                F_SETLKW = 7,
                F_SETOWN = 8,  /* sockets: SIGIO/SIGURG owner (nginx worker channel) */
                F_GETOWN = 9,
                F_SETSIG = 10,
                F_GETSIG = 11,
                F_DUPFD_CLOEXEC = 1030,
            };
            int duplicate_cloexec = (cmd == F_DUPFD_CLOEXEC);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = syscall_fd_get(cur, fd);
            if (!f) return ret_err(EBADF);
            if (cmd == F_DUPFD_CLOEXEC) {
                cmd = F_DUPFD;
            }
            if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK) {
                /* File locking: stub as success (no-op). Busybox adduser uses flock on /etc/passwd;
                   without this it gets EINVAL and exits silently. */
                (void)arg;
                if (cmd == F_GETLK && arg) {
                    /* F_GETLK: write flock struct with l_type=F_UNLCK to indicate "not locked" */
                    if (user_range_ok((void*)(uintptr_t)arg, 32)) {
                        uint8_t zeros[32];
                        memset(zeros, 0, sizeof(zeros));
                        copy_to_user_safe((void*)(uintptr_t)arg, zeros, 32);
                    }
                }
                return 0;
            }
            if (cmd == F_GETFD) {
                return (cur->process && cur->process->fd_cloexec[fd]) ? 1 : 0;
            } else if (cmd == F_SETFD) {
                if (cur->process)
                    cur->process->fd_cloexec[fd] = (arg & 1) ? 1 : 0;
                return 0;
            } else if (cmd == F_GETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    int fl = O_RDWR_LINUX;
                    if (sk->nonblock) fl |= O_NONBLOCK_LINUX;
                    return (uint64_t)(unsigned)fl;
                }
                /* For regular files/dirs/pipes: we don't track flags yet; return accmode only so fdopen() works. */
                return (uint64_t)(unsigned)O_RDWR_LINUX;
            } else if (cmd == F_SETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    sk->nonblock = (arg & O_NONBLOCK_LINUX) ? 1 : 0;
                    if (arg & 0x2000) /* O_ASYNC on Linux x86_64 */
                        sk->async = 1;
                }
                return 0;
            } else if (cmd == F_SETOWN || cmd == F_GETOWN ||
                       cmd == F_SETSIG || cmd == F_GETSIG) {
                /* Linux f_setown / f_getown — required for nginx channel sockets.
                 * SIGIO delivery can remain stubbed; store owner for GETOWN. */
                ksock_net_t *sk = (f->type == SYSCALL_FTYPE_SOCKET) ?
                    (ksock_net_t *)f->driver_private : NULL;
                if (cmd == F_GETOWN)
                    return sk ? (uint64_t)(int64_t)sk->owner : 0;
                if (cmd == F_GETSIG)
                    return sk ? (uint64_t)(unsigned)sk->sigio_signum : 0;
                if (cmd == F_SETOWN) {
                    if (sk) sk->owner = arg;
                    return 0;
                }
                /* F_SETSIG */
                if (arg < 0 || arg > 64) return ret_err(EINVAL);
                if (sk) sk->sigio_signum = arg;
                return 0;
            } else if (cmd == F_DUPFD) {
                /* Linux: allocate lowest available fd >= arg */
                int minfd = arg;
                if (minfd < 0) minfd = 0;
                if (minfd >= THREAD_MAX_FD) return ret_err(EINVAL);
                for (int i = minfd; i < THREAD_MAX_FD; i++) {
                    if (syscall_fd_get(cur, i) == NULL) {
                        cur->fds[i] = f;
                        if (cur->process) {
                            cur->process->fds[i] = f;
                            cur->process->fd_cloexec[i] =
                                duplicate_cloexec ? 1 : 0;
                        }
                        if (f->refcount <= 0) f->refcount = 1;
                        else f->refcount++;
                        return (uint64_t)i;
                    }
                }
                return ret_err(EMFILE);
            }
            return ret_err(EINVAL);
        }
        case 73: { /* flock(fd, operation) - stub as success. Busybox adduser uses flock on /etc/passwd. */
            (void)a1; (void)a2;
            return 0;
        }
        case 74: /* fsync(fd) */
        case 75: { /* fdatasync(fd) - adduser syncs passwd before rename */
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!cur->fds[fd]) return ret_err(EBADF);
            return 0;
        }
        case 162: { /* sync() — drain async block I/O before reboot (BusyBox calls this without -f). */
            iothread_drain();
            return 0;
        }
        case 270: {
            /* pselect6 — musl implements select(2) via this. Sigmask ignored.
             * Timeout is still a user timespec*; select_common handles num==270. */
            (void)a6;
            goto select_common;
        }
        case 121: { /* getpgid(pid) */
            int pid = (int)a1;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid == 0) {
                return (uint64_t)user_pgrp;
            }
            if ((uint64_t)pid == self) return (uint64_t)user_pgrp;
            /* We only support querying current process for now */
            return ret_err(ESRCH);
        }
        case SYS_rt_sigaction: {
            /* rt_sigaction(int signum, const struct sigaction *act,
                            struct sigaction *oldact, size_t sigsetsize) */
            int signum = (int)a1;
            const void *act_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            int openrc_sa = (cur && cur->name[0] && strstr(cur->name, "openrc"));
            uint64_t sig_ra_va = 0, sig_ra_pa = 0, sig_ra_before = 0;
            int trace_ash_sa = cur && cur->name[0] &&
                (strstr(cur->name, "/bin/sh") || strstr(cur->name, "busybox"));
            if (trace_ash_sa && cur->mm && cur->saved_user_rsp) {
                sig_ra_va = cur->saved_user_rsp + 0x148ULL;
                uint64_t leaf = 0;
                if (mm_va_leaf_pa(cur->mm, sig_ra_va, &leaf) == 0) {
                    sig_ra_pa = (leaf & ~0xFFFULL) | (sig_ra_va & 0xFFFULL);
                    sig_ra_before = *(const uint64_t *)(uintptr_t)sig_ra_pa;
                }
            }
            if (openrc_sa) {
                static int openrc_sa_left = 32;
                if (openrc_sa_left-- > 0) {
                    devel_printf("openrc-sa: enter tid=%llu sig=%d act=0x%llx old=0x%llx ssz=%zu live_cr3=0x%llx mm_cr3=0x%llx child=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        signum,
                        (unsigned long long)(uintptr_t)act_u,
                        (unsigned long long)(uintptr_t)old_u,
                        sigsetsize,
                        (unsigned long long)(paging_read_cr3() & ~0xFFFULL),
                        (unsigned long long)(cur->mm ? (cur->mm->cr3 & ~0xFFFULL) : 0),
                        cur->fork_child_user_rip ? 1 : 0);
                    qemu_debug_printf("openrc-sa: enter tid=%llu sig=%d handler_pending child=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        signum,
                        cur->fork_child_user_rip ? 1 : 0);
                }
            }
            if (signum <= 0 || signum >= (int)(sizeof(user_sig_actions)/sizeof(user_sig_actions[0]))) return ret_err(EINVAL);
            /* Linux: SIGKILL and SIGSTOP cannot be caught or ignored. */
            if (signum == SIGKILL || signum == SIGSTOP) return ret_err(EINVAL);

            /* Linux kernel ABI for rt_sigaction on x86_64:
               struct {
                 void (*handler)(int);
                 unsigned long flags;
                 void (*restorer)(void);
                 sigset_t mask;   // size = sigsetsize (glibc usually passes 8)
               }
               Total size = 24 + sigsetsize.
               Important: do NOT over-copy here; glibc may pass a tiny 32-byte object. */
            if (sigsetsize == 0 || sigsetsize > 128) return ret_err(EINVAL);
            const size_t act_sz = 24 + sigsetsize;
            struct k_sa {
                uint64_t handler;
                uint64_t flags;
                uint64_t restorer;
                uint8_t  mask[128];
            } sa, old_sa;
            /*
             * Linux do_sigaction: copy_from_user(act) before copy_to_user(oldact).
             * Writing oldact first smashes act when they alias / overlap on stack
             * (seen as sa_mask in sa_handler after vfork; ash GPF at RIP=="ls").
             */
            int have_new = 0;
            if (act_u) {
                memset(&sa, 0, sizeof(sa));
                if (copy_from_user_raw(&sa, act_u, act_sz) != 0) {
                    if (openrc_sa)
                        devel_printf("openrc-sa: EFAULT act sig=%d\n", signum);
                    return ret_err(EFAULT);
                }
                have_new = 1;
            }
            if (old_u) {
                memset(&old_sa, 0, sizeof(old_sa));
                if (cur->process) {
                    old_sa.handler = cur->process->signal_handlers[signum];
                    old_sa.flags = cur->process->signal_flags[signum];
                    old_sa.restorer = cur->process->signal_restorer[signum];
                    memcpy(old_sa.mask, &cur->process->signal_masks[signum],
                           sizeof(uint64_t));
                } else {
                    old_sa.handler = (uint64_t)(uintptr_t)user_sig_actions[signum].handler;
                    old_sa.flags = user_sig_actions[signum].flags;
                    old_sa.restorer = user_sig_actions[signum].restorer;
                    memcpy(old_sa.mask, &user_sig_actions[signum].mask, sizeof(uint64_t));
                }
                if (copy_to_user_safe(old_u, &old_sa, act_sz) != 0) {
                    if (openrc_sa)
                        devel_printf("openrc-sa: EFAULT oldact sig=%d\n", signum);
                    return ret_err(EFAULT);
                }
            }
            if (trace_ash_sa && sig_ra_pa) {
                uint64_t sig_ra_after =
                    *(const uint64_t *)(uintptr_t)sig_ra_pa;
                if (sig_ra_after != sig_ra_before ||
                    (sig_ra_after >= MM_ASH_WATCH_LO &&
                     sig_ra_after < MM_ASH_WATCH_HI)) {
                    uint64_t heap_pa = 0;
                    (void)mm_va_leaf_pa(cur->mm, MM_ASH_WATCH_VA, &heap_pa);
                    devel_printf("ash-sa-trace: tid=%d sig=%d ursp=0x%llx act=0x%llx "
                            "old=0x%llx ra_va=0x%llx ra_pa=0x%llx "
                            "before=0x%llx after=0x%llx heap_pa=0x%llx alias=%d\n",
                            (int)(cur->tid ? cur->tid : 1), signum,
                            (unsigned long long)cur->saved_user_rsp,
                            (unsigned long long)(uintptr_t)act_u,
                            (unsigned long long)(uintptr_t)old_u,
                            (unsigned long long)sig_ra_va,
                            (unsigned long long)sig_ra_pa,
                            (unsigned long long)sig_ra_before,
                            (unsigned long long)sig_ra_after,
                            (unsigned long long)(heap_pa & ~0xFFFULL),
                            ((sig_ra_pa & ~0xFFFULL) ==
                             (heap_pa & ~0xFFFULL)) ? 1 : 0);
                }
            }
            if (have_new) {
                user_sig_actions[signum].handler = (user_sighandler_t)(uintptr_t)sa.handler;
                user_sig_actions[signum].flags = sa.flags;
                user_sig_actions[signum].restorer = sa.restorer;
                user_sig_actions[signum].mask = 0;
                if (sigsetsize >= sizeof(uint64_t))
                    memcpy(&user_sig_actions[signum].mask, sa.mask, sizeof(uint64_t));
                if (cur->process) {
                    cur->process->signal_handlers[signum] = sa.handler;
                    cur->process->signal_flags[signum] = sa.flags;
                    cur->process->signal_restorer[signum] = sa.restorer;
                    cur->process->signal_masks[signum] =
                        user_sig_actions[signum].mask;
                }
            }
            if (openrc_sa) {
                static int openrc_sa_done_left = 32;
                if (openrc_sa_done_left-- > 0) {
                    devel_printf("openrc-sa: ok tid=%llu sig=%d handler=0x%llx restorer=0x%llx child=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        signum,
                        (unsigned long long)(act_u ? sa.handler : 0),
                        (unsigned long long)(act_u ? sa.restorer : 0),
                        cur->fork_child_user_rip ? 1 : 0);
                    if (cur->fork_child_user_rip && act_u && sa.handler == 0)
                        debug_serial_marker("openrc-sa-child-DFL");
                    else if (cur->fork_child_user_rip)
                        debug_serial_marker("openrc-sa-child-ok");
                }
                /* Last reset in run_program is SIGWINCH(28); next is sigprocmask→execl.
                 * Only the fork child of openrc (parent must be openrc, not linuxrc's
                 * openrc child still carrying fork_child_user_rip). */
                if (signum == 28 && cur->fork_child_user_rip &&
                    cur->parent_tid > 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt && pt->name[0] && strstr(pt->name, "openrc")) {
                        int parent_waiting = (pt->state == THREAD_BLOCKED ||
                            pt->state == THREAD_SLEEPING);
                        devel_printf("openrc-sa: done-WINCH tid=%llu parent=%d pwait=%d mmcr3=0x%llx ret_rip=0x%llx handler=0x%llx\n",
                            (unsigned long long)(cur->tid ? cur->tid : 1),
                            cur->parent_tid,
                            parent_waiting,
                            (unsigned long long)(cur->mm ? cur->mm->cr3 : 0),
                            (unsigned long long)cur->saved_user_rip,
                            (unsigned long long)(act_u ? sa.handler : 0));
                        debug_serial_marker("openrc-sa-done-WINCH");
                    }
                }
            }
            return 0;
        }
        case SYS_rt_sigtimedwait: {
            /* rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
             *                 const struct timespec *timeout, size_t sigsetsize) */
            const void *timeout_u = (const void *)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            void *info_u = (void *)(uintptr_t)a2;
            if (!(sigsetsize == 0 || sigsetsize == 8 || sigsetsize == 128))
                return ret_err(EINVAL);
            uint64_t mask = 0;
            if (sigsetsize >= 8 && a1) {
                if (copy_from_user_raw(&mask, (const void *)(uintptr_t)a1,
                                       sizeof(mask)) != 0)
                    return ret_err(EFAULT);
            }
            thread_t *tcur = cur;
            uint64_t wait_mask = mask ? mask : ~0ULL;
            int wait_tid = (int)(tcur->tid ? tcur->tid : 1);
            uint32_t timeout_ms = 0;
            int has_timeout = 0;
            int waited_once = 0;

            if (tcur->name[0] && strstr(tcur->name, "linuxrc")) {
                int live_children = 0, zombie_children = 0;
                for (int i = 0; i < thread_get_count(); i++) {
                    thread_t *candidate = thread_get_by_index(i);
                    if (!candidate || candidate->parent_tid != wait_tid)
                        continue;
                    if (candidate->state == THREAD_TERMINATED)
                        zombie_children++;
                    else
                        live_children++;
                }
                devel_printf("sigtimedwait-enter: tid=%d pid=%llu mask=0x%llx "
                        "pending=0x%llx timeout=%s children=%d zombies=%d\n",
                    wait_tid,
                    (unsigned long long)process_pid(tcur),
                    (unsigned long long)mask,
                    (unsigned long long)tcur->pending_signals,
                    timeout_u ? "yes" : "NULL",
                    live_children, zombie_children);
            }

            if (timeout_u) {
                struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                if (copy_from_user_raw(&ts, timeout_u, sizeof(ts)) != 0)
                    return ret_err(EFAULT);
                if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL)
                    return ret_err(EINVAL);
                has_timeout = 1;
                uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL +
                    (uint64_t)(ts.tv_nsec / 1000000ULL);
                if (ms == 0 && (ts.tv_sec > 0 || ts.tv_nsec > 0))
                    ms = 1;
                if (ms > 0xFFFFFFFFull)
                    ms = 0xFFFFFFFFull;
                timeout_ms = (uint32_t)ms;
                if (tcur->name[0] && strstr(tcur->name, "linuxrc"))
                    devel_printf("sigtimedwait-timeout: tid=%d sec=%lld nsec=%lld ms=%u\n",
                        wait_tid, (long long)ts.tv_sec, (long long)ts.tv_nsec,
                        timeout_ms);
            }

            for (;;) {
                int sig = thread_fetch_pending_signal(tcur, wait_mask);
                if (!sig && (wait_mask & (1ULL << (SIGCHLD - 1))) &&
                    find_terminated_child(tcur))
                    sig = SIGCHLD;
                if (sig) {
                    if (info_u && sig == SIGCHLD) {
                        thread_t *c = find_terminated_child(tcur);
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        if (c) {
                            info.si_pid = (int)process_pid(c);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        }
                        if (copy_to_user_safe(info_u, &info, sizeof(info)) != 0)
                            return ret_err(EFAULT);
                    }
                    if (tcur->name[0] && strstr(tcur->name, "linuxrc"))
                        devel_printf("sigtimedwait-done: tid=%d sig=%d\n", wait_tid, sig);
                    return (uint64_t)sig;
                }

                if (has_timeout && (waited_once || timeout_ms == 0))
                    return ret_err(EAGAIN);

                /*
                 * Do not thread_sleep() from the live syscall stack. Sleep/yield
                 * without restoring the saved frame is what freezes BusyBox ash
                 * in rt_sigtimedwait after nested vfork (last log: nr=128).
                 * Match wait4: block, yield, then reload the snapshot.
                 */
                if (has_timeout)
                    thread_block_with_timeout(wait_tid, timeout_ms);
                else
                    thread_block(wait_tid);
                if (tcur->state == THREAD_BLOCKED)
                    thread_yield();
                syscall_restore_live_frame_from_snapshot(tcur, "rt_sigtimedwait");
                if (has_timeout)
                    waited_once = 1;
            }
        }
        case SYS_rt_sigsuspend: {
            /* rt_sigsuspend(const sigset_t *mask, size_t sigsetsize)
               Temporarily installs a signal mask and sleeps until an unblocked
               pending signal (or a waitable child/SIGCHLD event) exists. */
            const void *mask_u = (const void *)(uintptr_t)a1;
            size_t sigsetsize = (size_t)a2;
            if (!mask_u) return ret_err(EFAULT);
            if (!(sigsetsize == 8 || sigsetsize == 128)) return ret_err(EINVAL);
            uint64_t new_mask = 0;
            if (copy_from_user_raw(&new_mask, mask_u, sizeof(new_mask)) != 0)
                return ret_err(EFAULT);
            thread_t *tcur = cur;
            if (!tcur) return ret_err(EINVAL);
            uint64_t old_mask = tcur->saved_sig_mask;
            tcur->saved_sig_mask = new_mask;
            int wait_tid = (int)(tcur->tid ? tcur->tid : 1);
            for (;;) {
                uint64_t pending = tcur->pending_signals & ~new_mask;
                if (pending)
                    break;
                if (!(new_mask & (1ULL << (SIGCHLD - 1))) && find_terminated_child(tcur)) {
                    thread_set_pending_signal(tcur, SIGCHLD);
                    break;
                }
                thread_block(wait_tid);
                if (tcur->state == THREAD_BLOCKED)
                    thread_yield();
                syscall_restore_live_frame_from_snapshot(tcur, "rt_sigsuspend");
            }
            tcur->saved_sig_mask = old_mask;
            return ret_err(EINTR);
        }
        case SYS_execve: {
            /* copy path, argv, envp from user and call kernel_execve_from_path */
            if (cur->name[0] && (strstr(cur->name, "linuxrc") || strstr(cur->name, "openrc"))) {
                char peek[96];
                peek[0] = 0;
                if (a1 && user_range_ok((const void *)(uintptr_t)a1, 1)) {
                    size_t n = user_strnlen_bounded((const char *)(uintptr_t)a1, sizeof(peek) - 1);
                    if (n > 0 && n < sizeof(peek) &&
                        copy_from_user_raw(peek, (const void *)(uintptr_t)a1, n) == 0)
                        peek[n] = 0;
                }
                devel_printf("openrc-exec-enter: tid=%llu path=%s\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    peek[0] ? peek : "?");
            }
            const char *path_u = (const char*)(uintptr_t)a1;
            const char *const *argv_u = (const char *const*)(uintptr_t)a2;
            const char *const *envp_u = (const char *const*)(uintptr_t)a3;
            if (!path_u) return ret_err(EFAULT);
            if (!user_range_ok(path_u, 1)) return ret_err(EFAULT);
            /* Copy path */
            size_t plen = user_strnlen_bounded(path_u, 1024);
            if (plen == 0 || plen >= 1024) return ret_err(ENOENT);
            char *path = (char*)kmalloc(plen + 1);
            if (!path) { qemu_debug_printf("OOM execve: path plen=%llu\n", (unsigned long long)(plen+1)); return ret_err(ENOMEM); }
            if (!user_range_ok(path_u, plen + 1) || copy_from_user_raw(path, path_u, plen + 1) != 0) {
                kfree(path);
                return ret_err(EFAULT);
            }
            char resolved_path[512];
            resolve_kernel_path(cur, path, resolved_path, sizeof(resolved_path));
            if (!resolved_path[0]) {
                kfree(path);
                return ret_err(ENOENT);
            }
            /* Copy argv array (NULL-terminated) */
            int argc = 0;
            if (argv_u) {
                /* count args */
                while (argc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&argv_u[argc]), &p) != 0) {
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    argc++;
                }
            }
            const char **kargv = (const char**)kmalloc((size_t)(argc + 1) * sizeof(char*));
            if (!kargv) { qemu_debug_printf("OOM execve: kargv argc=%d\n", argc); kfree(path); return ret_err(ENOMEM); }
            for (int i = 0; i < argc; i++) {
                uint64_t a_up = 0;
                if (user_read_u64((const void*)(uintptr_t)(&argv_u[i]), &a_up) != 0) {
                    kfree((void*)kargv); kfree(path); return ret_err(EFAULT);
                }
                const char *a_u = (const char*)(uintptr_t)a_up;
                if (!a_u || !user_range_ok(a_u, 1)) { kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                size_t L = user_strnlen_bounded(a_u, (size_t)MAX_ARG_STRLEN + 1u);
                if (L > (size_t)MAX_ARG_STRLEN) {
                    for (int j = 0; j < i; j++) kfree((void *)kargv[j]);
                    kfree((void *)kargv);
                    kfree(path);
                    return ret_err(E2BIG);
                }
                char *ks = (char*)kmalloc(L + 1);
                if (!ks) { qemu_debug_printf("OOM execve: argv[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                if (L > 0 && (!user_range_ok(a_u, L) || copy_from_user_raw(ks, a_u, L) != 0)) {
                    kfree(ks);
                    for (int j=0;j<i;j++) kfree((void*)kargv[j]);
                    kfree((void*)kargv);
                    kfree(path);
                    return ret_err(EFAULT);
                }
                ks[L] = '\0';
                kargv[i] = ks;
            }
            kargv[argc] = NULL;
            /* Copy envp similarly (but allow NULL) */
            int envc = 0;
            const char **kenvp = NULL;
            if (envp_u) {
                while (envc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[envc]), &p) != 0) {
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    envc++;
                }
                kenvp = (const char**)kmalloc((size_t)(envc + 1) * sizeof(char*));
                if (!kenvp) { qemu_debug_printf("OOM execve: kenvp envc=%d\n", envc); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                for (int i = 0; i < envc; i++) {
                    uint64_t e_up = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[i]), &e_up) != 0) {
                        for (int j=0;j<i;j++) kfree((void*)kenvp[j]);
                        kfree(kenvp);
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    const char *e_u = (const char*)(uintptr_t)e_up;
                    if (!e_u || !user_range_ok(e_u, 1)) { for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                    size_t L = user_strnlen_bounded(e_u, (size_t)MAX_ARG_STRLEN + 1u);
                    if (L > (size_t)MAX_ARG_STRLEN) {
                        for (int j = 0; j < i; j++) kfree((void *)kenvp[j]);
                        kfree(kenvp);
                        for (int j = 0; j < argc; j++) kfree((void *)kargv[j]);
                        kfree((void *)kargv);
                        kfree(path);
                        return ret_err(E2BIG);
                    }
                    char *ks = (char*)kmalloc(L + 1);
                    if (!ks) { qemu_debug_printf("OOM execve: envp[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                    if (L > 0 && (!user_range_ok(e_u, L) || copy_from_user_raw(ks, e_u, L) != 0)) {
                        kfree(ks);
                        for (int j = 0; j < i; j++) kfree((void *)kenvp[j]);
                        kfree(kenvp);
                        for (int j = 0; j < argc; j++) kfree((void *)kargv[j]);
                        kfree((void *)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    ks[L] = '\0';
                    kenvp[i] = ks;
                }
                kenvp[envc] = NULL;
            }

            /* call kernel execve (does not return on success) */
            int rc = kernel_execve_from_path(resolved_path, (const char *const *)kargv, (const char *const *)kenvp);
            if (rc == -3) {
                /* One bounded retry for transient tid/layout race in exec path. */
                g_execve_retry_eagain++;
                rc = kernel_execve_from_path(resolved_path, (const char *const *)kargv, (const char *const *)kenvp);
                if (rc == 0) {
                    g_execve_retry_ok++;
                } else {
                    g_execve_retry_fail++;
                    uint64_t now_ms = pit_get_time_ms();
                    if (now_ms - g_execve_retry_last_log_ms >= 2000ULL) {
                        g_execve_retry_last_log_ms = now_ms;
                        klogprintf("execve: retry stats eagain=%llu ok=%llu fail=%llu last_rc=%d path=%s\n",
                                   (unsigned long long)g_execve_retry_eagain,
                                   (unsigned long long)g_execve_retry_ok,
                                   (unsigned long long)g_execve_retry_fail,
                                   rc, resolved_path);
                    }
                }
            }

            /* cleanup on failure */
            if (kenvp) { for (int i=0;i<envc;i++) if (kenvp[i]) kfree((void*)kenvp[i]); kfree(kenvp); }
            for (int i=0;i<argc;i++) if (kargv[i]) kfree((void*)kargv[i]);
            if (kargv) kfree((void*)kargv);
            if (cur && cur->name[0] &&
                (strstr(cur->name, "openrc") || strstr(cur->name, "linuxrc")))
                kprintf("execve-fail: tid=%llu path=%s rc=%d argc=%d envc=%d\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    path ? path : "?", rc, argc, envc);
            kfree(path);
            if (rc == 0) {
                sysv_shm_detach_all_for_tid((uint64_t)(cur && cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur && cur->tid ? cur->tid : 1));
                /* Success is noreturn via enter_user_mode. If we got here, jump. */
                if (cur && cur->user_rip && cur->user_stack) {
                    devel_printf("execve: fallthrough jump path=%s rip=0x%llx\n",
                        resolved_path, (unsigned long long)cur->user_rip);
                    cur->fork_child_user_rip = 0;
                    enter_user_mode(cur->user_rip, cur->user_stack);
                }
                return ret_err(EFAULT);
            }
            if (rc == -2) return ret_err(ENOEXEC);
            if (rc == -3) return ret_err(EAGAIN);
            if (rc == -EFAULT || rc == -14) return ret_err(EFAULT);
            if (rc == -ENOMEM || rc == -12) return ret_err(ENOMEM);
            return ret_err(ENOENT);
        }
        case SYS_rt_sigprocmask: {
            /* rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize)
               Per-thread signal mask; use cur->saved_sig_mask for user threads. */
            int how = (int)a1;
            const void *set_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            (void)a4;
            uint64_t *p_mask = (cur && cur->ring == 3) ? &cur->saved_sig_mask : &user_sig_mask;
            if (cur && cur->name[0] && strstr(cur->name, "openrc")) {
                static int openrc_pm_left = 24;
                if (openrc_pm_left-- > 0)
                    devel_printf("openrc-sigprocmask: tid=%llu how=%d set=0x%llx old=0x%llx child=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        how,
                        (unsigned long long)(uintptr_t)set_u,
                        (unsigned long long)(uintptr_t)old_u,
                        cur->fork_child_user_rip ? 1 : 0);
            }

            if (old_u) {
                uint64_t old = *p_mask;
                if (copy_to_user_safe(old_u, &old, sizeof(old)) != 0) return ret_err(EFAULT);
            }
            if (set_u) {
                uint64_t setv = 0;
                if (copy_from_user_raw(&setv, set_u, sizeof(setv)) != 0) return ret_err(EFAULT);
                if (how == 0 /* SIG_BLOCK */) *p_mask |= setv;
                else if (how == 1 /* SIG_UNBLOCK */) *p_mask &= ~setv;
                else if (how == 2 /* SIG_SETMASK */) *p_mask = setv;
                else return ret_err(EINVAL);
            }
            return 0;
        }
        case SYS_sigaltstack: {
            /* sigaltstack(const stack_t *ss, stack_t *old_ss) — Linux x86_64 nr 131.
             * Go runtime.minit queries then arms an alternate signal stack. */
            const void *ss_u = (const void *)(uintptr_t)a1;
            void *old_u = (void *)(uintptr_t)a2;
            if (!cur || cur->ring != 3) return ret_err(EINVAL);

            typedef struct {
                uint64_t ss_sp;
                int32_t ss_flags;
                int32_t __pad;
                uint64_t ss_size;
            } k_stack_t;

            k_stack_t old;
            old.ss_sp = cur->sas_ss_sp;
            old.ss_flags = cur->sas_ss_flags;
            old.__pad = 0;
            old.ss_size = cur->sas_ss_size;

            if (ss_u) {
                k_stack_t ss;
                if (!user_range_ok(ss_u, sizeof(ss)) ||
                    copy_from_user_raw(&ss, ss_u, sizeof(ss)) != 0)
                    return ret_err(EFAULT);
                int flags = ss.ss_flags;
                /* Input may only be 0 or SS_DISABLE (SS_ONSTACK is output-only). */
                if (flags & ~SS_DISABLE)
                    return ret_err(EINVAL);
                if (flags & SS_DISABLE) {
                    cur->sas_ss_sp = 0;
                    cur->sas_ss_size = 0;
                    cur->sas_ss_flags = SS_DISABLE;
                } else {
                    if (ss.ss_size < MINSIGSTKSZ_AXON)
                        return ret_err(ENOMEM);
                    if (!ss.ss_sp ||
                        ss.ss_sp < 0x200000ULL ||
                        ss.ss_sp + ss.ss_size < ss.ss_sp ||
                        ss.ss_sp + ss.ss_size > (uint64_t)MMIO_IDENTITY_LIMIT)
                        return ret_err(EFAULT);
                    cur->sas_ss_sp = ss.ss_sp;
                    cur->sas_ss_size = ss.ss_size;
                    cur->sas_ss_flags = 0;
                }
            }

            if (old_u) {
                if (!user_range_ok(old_u, sizeof(old)) ||
                    copy_to_user_safe(old_u, &old, sizeof(old)) != 0)
                    return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_fork: {
            struct kernel_clone_args args = {
                .exit_signal = SIGCHLD,
            };

            return kernel_clone(cur, &args);
        }

        case SYS_wait4: {
            /* waitpid(pid, status*, options, rusage*) minimal implementation
               - pid > 0: wait for specific child pid
               - pid == -1: wait for any child
               We only support blocking wait (options == 0) and ignore rusage.
               Use sc_a* (not a1/a2/a3 locals): another thread's syscall reuses the
               per-CPU syscall kernel stack and clobbers syscall_do_inner's C frame.

               CRITICAL: do not use thread_get_current_user() here. It is a global
               (not per-CPU); with SMP a child on another CPU overwrites it, so wait4
               can read the wrong sc_a1 (often 0 → waitpid(0)/pgrp) and return ECHILD
               while kill(child,0) still succeeds — BusyBox waitfor() spins forever. */
            (void)a4;
            /* Support WNOHANG (1), WUNTRACED (2), WCONTINUED (8) as no-ops. */
            enum { WNOHANG = 1, WUNTRACED = 2, WCONTINUED = 8 };

            /*
             * Process-based wait path.  A zombie remains linked in the
             * caller's child list until this exact operation reaps it; no
             * PID1 scans, kill(0) probes, or thread-slot identities are used.
             */
            if (cur->process) {
                for (;;) {
                    /* Pin waiter: after yield another syscall may reuse this
                     * CPU's syscall stack and clobber C locals. */
                    thread_t *waiter = cur;
                    int pid_arg = (int)waiter->sc_a1;
                    int options = (int)waiter->sc_a3;
                    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
                        return ret_err(ENOSYS);

                    int has_child = 0;
                    process_t *dead = process_find_child(waiter->process, pid_arg,
                        waiter->process->pgid, 1, &has_child);
                    if (dead) {
                        thread_t *dead_thread = dead->leader;
                        /* Process may be ZOMBIE while the leader is still in
                         * SYS_exit/exit_group. Reaping then frees process_t
                         * under a live exit path (linuxrc hang after first
                         * mount wait4). Wait until the leader is gone/TERMINATED. */
                        if (dead_thread && dead_thread->state != THREAD_TERMINATED) {
                            dead = NULL;
                        }
                    }
                    if (dead) {
                        int status = dead->exit_status;
                        int dead_pid = (int)dead->pid;
                        thread_t *dead_thread = dead->leader;
                        if (waiter->sc_a2 &&
                            copy_to_user_safe((void *)(uintptr_t)waiter->sc_a2,
                                              &status, sizeof(status)) != 0)
                            return ret_err(EFAULT);
                        if (dead_thread) {
                            int dead_tid = (int)(dead_thread->tid ?
                                                 dead_thread->tid : 1);
                            dead_thread->process = NULL;
                            dead->leader = NULL;
                            (void)thread_reap(dead_tid);
                        }
                        (void)process_reap(waiter->process, dead);
                        waiter->wait4_last_echild = 0;
                        if (waiter->name[0] && strstr(waiter->name, "linuxrc")) {
                            static int wait4_ok_left = 16;
                            if (wait4_ok_left-- > 0) {
                                uint32_t utmp_lock = 0;
                                int32_t utmp_fd = 0;
                                uint64_t act = 0, retaddr = 0;
                                if (waiter->mm)
                                    mm_switch(waiter->mm);
                                utmp_lock = *(volatile uint32_t *)(uintptr_t)0x63ea68ULL;
                                utmp_fd = *(volatile int32_t *)(uintptr_t)0x636eb4ULL;
                                act = *(volatile uint64_t *)(uintptr_t)0x63e2b8ULL;
                                if (waiter->saved_user_rsp >= 0x200000ULL &&
                                    waiter->saved_user_rsp + 8ULL < (uint64_t)MMIO_IDENTITY_LIMIT)
                                    retaddr = *(volatile uint64_t *)(uintptr_t)waiter->saved_user_rsp;
                                devel_printf("wait4-reap-pid: parent=%llu child_pid=%d status=0x%x rip=0x%llx rsp=0x%llx\n",
                                    (unsigned long long)(waiter->tid ? waiter->tid : 1),
                                    dead_pid, (unsigned)status,
                                    (unsigned long long)waiter->saved_user_rip,
                                    (unsigned long long)waiter->saved_user_rsp);
                                devel_printf("wait4-post: ret=[rsp]=0x%llx act=0x%llx utmp_fd=%d utmp_lock=%u\n",
                                    (unsigned long long)retaddr,
                                    (unsigned long long)act,
                                    (int)utmp_fd, (unsigned)utmp_lock);
                            }
                        }
                        return (uint64_t)(unsigned)dead_pid;
                    }
                    if (!has_child) {
                        /* Fallback: child threads by parent_tid (process link missing). */
                        int live_by_tid = 0;
                        thread_t *zombie_by_tid = NULL;
                        for (int i = 0; i < thread_get_count(); i++) {
                            thread_t *c = thread_get_by_index(i);
                            if (!c || c->ring != 3) continue;
                            if (c->parent_tid != (int)(waiter->tid ? waiter->tid : 1))
                                continue;
                            if (c->state == THREAD_TERMINATED) {
                                if (c->exit_status != 0x80000000 && !zombie_by_tid)
                                    zombie_by_tid = c;
                                continue;
                            }
                            live_by_tid = 1;
                            c->waiter_tid = (int)(waiter->tid ? waiter->tid : 1);
                        }
                        if (zombie_by_tid) {
                            int st = zombie_by_tid->exit_status;
                            int dead_pid = (int)process_pid(zombie_by_tid);
                            if (waiter->sc_a2 &&
                                copy_to_user_safe((void *)(uintptr_t)waiter->sc_a2,
                                                  &st, sizeof(st)) != 0)
                                return ret_err(EFAULT);
                            zombie_by_tid->exit_status = 0x80000000;
                            zombie_by_tid->waiter_tid = -1;
                            if (zombie_by_tid->process)
                                process_mark_zombie(zombie_by_tid->process, st);
                            (void)thread_reap((int)(zombie_by_tid->tid ?
                                                    zombie_by_tid->tid : 1));
                            devel_printf("wait4-reap-tid: parent=%llu child_pid=%d (via parent_tid)\n",
                                (unsigned long long)(waiter->tid ? waiter->tid : 1),
                                dead_pid);
                            return (uint64_t)(unsigned)dead_pid;
                        }
                        if (!live_by_tid) {
                            if (waiter->name[0] && strstr(waiter->name, "linuxrc")) {
                                static int wait4_echild_left = 12;
                                if (wait4_echild_left-- > 0) {
                                    uint64_t me = process_pid(waiter);
                                    devel_printf("wait4-ECHILD: tid=%llu me_pid=%llu pid_arg=%d opts=0x%x\n",
                                        (unsigned long long)(waiter->tid ? waiter->tid : 1),
                                        (unsigned long long)me, pid_arg, options);
                                    for (int i = 0; i < thread_get_count(); i++) {
                                        thread_t *c = thread_get_by_index(i);
                                        if (!c || c->ring != 3) continue;
                                        kprintf("  thr tid=%llu pid=%llu parent_tid=%d state=%d name=%s\n",
                                            (unsigned long long)(c->tid ? c->tid : 1),
                                            (unsigned long long)process_pid(c),
                                            c->parent_tid, (int)c->state,
                                            c->name[0] ? c->name : "?");
                                    }
                                }
                            }
                            waiter->wait4_last_echild = 1;
                            return ret_err(ECHILD);
                        }
                        has_child = 1;
                        if (waiter->name[0] && strstr(waiter->name, "linuxrc")) {
                            static int wait4_repair_left = 8;
                            if (wait4_repair_left-- > 0)
                                devel_printf("wait4-repair: tid=%llu blocking on parent_tid children\n",
                                    (unsigned long long)(waiter->tid ? waiter->tid : 1));
                        }
                    }
                    if (options & WNOHANG)
                        return 0;
                    if (thread_has_interrupt_signal(waiter))
                        return ret_err(EINTR);

                    process_t *live = process_find_child(waiter->process, pid_arg,
                        waiter->process->pgid, 0, NULL);
                    if (live && live->leader)
                        live->leader->waiter_tid =
                            (int)(waiter->tid ? waiter->tid : 1);
                    thread_block((int)(waiter->tid ? waiter->tid : 1));
                    thread_yield();
                    syscall_restore_live_frame_from_snapshot(waiter, "wait4-process");
                    cur = waiter;
                }
            }

            for (;;) {
                /*
                 * thread_block_current_atomic() can schedule another task on this
                 * CPU.  Its syscall reuses the CPU syscall stack, so automatic
                 * locals from the prior iteration cannot be trusted after wakeup.
                 * Reacquire the running parent each time.  current_user is now
                 * per-CPU, unlike the old global pointer.
                 */
                thread_t *tcur = cur;
                if (!tcur || tcur->ring != 3 || tcur->state == THREAD_TERMINATED)
                    tcur = thread_get_current_user();
                if (!tcur) return ret_err(EINVAL);
                if (((int)tcur->sc_a3) & ~(WNOHANG | WUNTRACED | WCONTINUED))
                    return ret_err(ENOSYS);
                thread_t *found = NULL;
                int has_waitable_child = 0;
                int w4_pid = (int)tcur->sc_a1;
                if (w4_pid > 0) {
                    thread_t *c = thread_get(w4_pid);
                    if (c && c->parent_tid == (int)tcur->tid) {
                        found = c;
                        has_waitable_child = 1;
                    }
                } else if (w4_pid == 0) {
                    /* waitpid(0): any child in the caller's process group. */
                    for (int i = 0; i < thread_get_count(); i++) {
                        thread_t *c = thread_get_by_index(i);
                        if (!c) continue;
                        if (c->parent_tid != (int)tcur->tid) continue;
                        if (c->pgid != tcur->pgid) continue;
                        if (c->state == THREAD_TERMINATED && c->exit_status == 0x80000000) continue;
                        has_waitable_child = 1;
                        if (c->state != THREAD_TERMINATED) continue;
                        if (c->exit_status == 0x80000000) continue;
                        found = c;
                        break;
                    }
                } else if (w4_pid == -1) {
                    /* waitpid(-1) waits for any child. Do not bind the wait to the
                       first live child: init may have multiple gettys and must wake
                       for whichever one exits first. */
                    for (int i = 0; i < thread_get_count(); i++) {
                        thread_t *c = thread_get_by_index(i);
                        if (!c) continue;
                        if (c->parent_tid != (int)tcur->tid) continue;
                        if (c->state == THREAD_TERMINATED && c->exit_status == 0x80000000) continue; /* already reaped */
                        has_waitable_child = 1;
                        if (c->state != THREAD_TERMINATED) continue;
                        if (c->exit_status == 0x80000000) continue; /* already reaped */
                        found = c;
                        break;
                    }
                } else {
                    return ret_err(EINVAL);
                }
                if (!found) {
                    if (!found && !has_waitable_child) {
                        if ((int)tcur->sc_a3 & WNOHANG) {
                            thread_sleep(1);
                            return 0;
                        }
                        if (is_init_user(tcur) || (tcur->name[0] && strstr(tcur->name, "linuxrc"))) {
                            static int wait4_echild_dbg_left = 8;
                            if (wait4_echild_dbg_left-- > 0) {
                                devel_printf("wait4-ECHILD: parent_tid=%llu name=%s w4_pid=%d sc_a1=%lld\n",
                                    (unsigned long long)(tcur->tid ? tcur->tid : 1),
                                    tcur->name[0] ? tcur->name : "(noname)",
                                    w4_pid, (long long)tcur->sc_a1);
                                for (int i = 0; i < thread_get_count(); i++) {
                                    thread_t *c = thread_get_by_index(i);
                                    if (!c || c->ring != 3 || c->state == THREAD_TERMINATED)
                                        continue;
                                    kprintf("  live user tid=%llu parent=%d pgid=%d name=%s\n",
                                        (unsigned long long)(c->tid ? c->tid : 1),
                                        c->parent_tid, c->pgid,
                                        c->name[0] ? c->name : "(noname)");
                                }
                            }
                        }
                        return ret_err(ECHILD);
                    }
                    if (!found) {
                        if ((int)tcur->sc_a3 & WNOHANG) {
                            thread_sleep(1);
                            return 0;
                        }
                        /* Block until a child exits (futex-style: safe inside syscall). */
                        if (w4_pid > 0) {
                            for (int i = 0; i < thread_get_count(); i++) {
                                thread_t *c = thread_get_by_index(i);
                                if (!c) continue;
                                if (c->parent_tid != (int)tcur->tid) continue;
                                if ((int)c->tid == w4_pid)
                                    c->waiter_tid = (int)(tcur->tid ? tcur->tid : 1);
                            }
                        } else if (w4_pid == 0) {
                            for (int i = 0; i < thread_get_count(); i++) {
                                thread_t *c = thread_get_by_index(i);
                                if (!c) continue;
                                if (c->parent_tid != (int)tcur->tid) continue;
                                if (c->pgid != tcur->pgid) continue;
                                if (c->state == THREAD_TERMINATED) continue;
                                c->waiter_tid = (int)(tcur->tid ? tcur->tid : 1);
                            }
                        } else if (w4_pid == -1) {
                            for (int i = 0; i < thread_get_count(); i++) {
                                thread_t *c = thread_get_by_index(i);
                                if (!c) continue;
                                if (c->parent_tid != (int)tcur->tid) continue;
                                if (c->state == THREAD_TERMINATED) continue;
                                c->waiter_tid = (int)(tcur->tid ? tcur->tid : 1);
                            }
                        }
                        if (tcur->name[0] && (strstr(tcur->name, "busybox") || strstr(tcur->name, "/sh") ||
                                              strstr(tcur->name, "openrc"))) {
                            static int wait4_block_dbg_left = 24;
                            if (wait4_block_dbg_left-- > 0) {
                                devel_printf("wait4-block: parent=%llu name=%s pid_arg=%d opts=0x%llx\n",
                                    (unsigned long long)(tcur->tid ? tcur->tid : 1),
                                    tcur->name,
                                    w4_pid,
                                    (unsigned long long)tcur->sc_a3);
                            }
                        }
                        /*
                         * Do not block thread_current(): during a handoff it can
                         * still name the fork child.  The syscall issuer is the
                         * stable tcur captured at entry.
                         */
                        thread_block((int)(tcur->tid ? tcur->tid : 1));
                        if (tcur->state == THREAD_BLOCKED) {
                            thread_yield();
                            syscall_restore_live_frame_from_snapshot(tcur, "wait4-any");
                        }
                        continue;
                    }
                }
                /* Trace selection for debugging hangs (limited by global trace budget anyway). */
                if (g_syscall_trace_on && g_syscall_trace_budget > 0 && is_watch_proc(tcur)) {
                    qemu_debug_printf("wait4: parent=%llu name=%s pid_arg=%d -> child=%llu state=%d exit_status=0x%x reaped=%d\n",
                        (unsigned long long)(tcur->tid ? tcur->tid : 1),
                        (tcur->name[0] ? tcur->name : "(noname)"),
                        w4_pid,
                        (unsigned long long)(found->tid ? found->tid : 1),
                        (int)found->state,
                        (unsigned)found->exit_status,
                        (found->exit_status == 0x80000000));
                }
                /* If child was already reaped, behave like Linux: ECHILD */
                if (found->state == THREAD_TERMINATED && found->exit_status == 0x80000000) {
                    if ((int)tcur->sc_a3 & WNOHANG) {
                        thread_sleep(1);
                        return 0;
                    }
                    return ret_err(ECHILD);
                }
                /* If already terminated -> return immediately */
                if (found->state == THREAD_TERMINATED && found->exit_status != 0x80000000) {
                    int st = found->exit_status;
                    int dead_pid = (int)process_pid(found);
                    if (tcur->name[0] && (strstr(tcur->name, "busybox") || strstr(tcur->name, "/sh") ||
                                          strstr(tcur->name, "openrc"))) {
                        static int wait4_reap_dbg_left = 24;
                        if (wait4_reap_dbg_left-- > 0) {
                            uint64_t frame_rip = 0;
                            if (tcur->saved_syscall_frame)
                                frame_rip = tcur->saved_syscall_frame[13];
                            devel_printf("wait4-reap: parent=%llu name=%s child=%d status=0x%x status_u=0x%llx\n",
                                (unsigned long long)(tcur->tid ? tcur->tid : 1),
                                tcur->name,
                                dead_pid,
                                (unsigned)st,
                                (unsigned long long)tcur->sc_a2);
                            devel_printf("wait4-reap-frame: parent=%llu rcx_slot=0x%llx saved_rip=0x%llx rsp=0x%llx\n",
                                (unsigned long long)(tcur->tid ? tcur->tid : 1),
                                (unsigned long long)frame_rip,
                                (unsigned long long)tcur->saved_user_rip,
                                (unsigned long long)tcur->saved_user_rsp);
                        }
                    }
                    if (tcur->sc_a2) {
                        int *status_u = (int *)(uintptr_t)tcur->sc_a2;
                        if (copy_to_user_safe(status_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
                    }
                    found->waiter_tid = -1;
                    /* mark reaped */
                    found->exit_status = 0x80000000;
                    /* free slot/resources so fork doesn't hit MAX_THREADS */
                    {
                        extern int thread_reap(int pid);
                        (void)thread_reap(dead_pid);
                    }
                    if (!find_terminated_child(tcur))
                        tcur->pending_signals &= ~(1ULL << (SIGCHLD - 1));
                    return (uint64_t)dead_pid;
                }
                /* not terminated -> WNOHANG returns immediately */
                if ((int)tcur->sc_a3 & WNOHANG) {
                    thread_sleep(1);
                    return 0;
                }
                /* waitpid(pid>0): wait for that specific child. */
                found->waiter_tid = (int)(tcur->tid ? tcur->tid : 1);
                /* See the live-child wait path above: block the syscall owner,
                   not a possibly stale scheduler current thread. */
                thread_block((int)(tcur->tid ? tcur->tid : 1));
                if (tcur->state == THREAD_BLOCKED) {
                    thread_yield();
                    syscall_restore_live_frame_from_snapshot(tcur, "wait4-pid");
                }
                /* when child exits, loop to check again */
            }
            return ret_err(EINVAL);
        }
        case SYS_ioctl: {
            int fd = (int)a1;
            uint64_t req = a2;
            void *argp = (void*)(uintptr_t)a3;
            if (cur && cur->name[0] && strstr(cur->name, "openrc") &&
                cur->fork_child_user_rip) {
                static int openrc_ioctl_left = 16;
                if (openrc_ioctl_left-- > 0)
                    devel_printf("openrc-ioctl: tid=%llu fd=%d req=0x%llx arg=0x%llx\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        fd, (unsigned long long)req,
                        (unsigned long long)(uintptr_t)argp);
            }
            if (fd < 0 || fd >= THREAD_MAX_FD) {
                if (cur && cur->name[0] && (strstr(cur->name, "/sh") || strstr(cur->name, "busybox")))
                    kprintf("shell-ioctl-EBADF: fd=%d req=0x%llx (range) fds=[%s,%s,%s]\n",
                        fd, (unsigned long long)req,
                        thread_fd_path(cur, 0) ? thread_fd_path(cur, 0) : "-",
                        thread_fd_path(cur, 1) ? thread_fd_path(cur, 1) : "-",
                        thread_fd_path(cur, 2) ? thread_fd_path(cur, 2) : "-");
                return ret_err(EBADF);
            }
            struct fs_file *f = cur->fds[fd];
            if (!f) {
                if (cur && cur->name[0] && (strstr(cur->name, "/sh") || strstr(cur->name, "busybox")))
                    kprintf("shell-ioctl-EBADF: fd=%d req=0x%llx (nil) fds=[%s,%s,%s]\n",
                        fd, (unsigned long long)req,
                        thread_fd_path(cur, 0) ? thread_fd_path(cur, 0) : "-",
                        thread_fd_path(cur, 1) ? thread_fd_path(cur, 1) : "-",
                        thread_fd_path(cur, 2) ? thread_fd_path(cur, 2) : "-");
                return ret_err(EBADF);
            }

            /* Common ioctl numbers on Linux x86_64 */
            enum {
                TCGETS    = 0x5401,
                TCSETS    = 0x5402,
                TCSETSW   = 0x5403,
                TCSETSF   = 0x5404,
                TCFLSH    = 0x540B, /* tcflush(3): arg is TCIFLUSH/TCOFLUSH/TCIOFLUSH */
                TIOCSTI   = 0x5412, /* inject byte into tty input queue (terminal ioctls) */
                TIOCGSID  = 0x5429, /* tcgetsid(3) */
                TIOCNOTTY = 0x5423, /* drop controlling tty (getty after setsid) */
                TIOCSCTTY = 0x540E,
                TIOCGPGRP = 0x540F,
                TIOCSPGRP = 0x5410,
                TIOCGWINSZ= 0x5413,
                TIOCSWINSZ= 0x5414,
                TIOCMGET  = 0x5415,
                TIOCMBIS  = 0x5416,
                TIOCMBIC  = 0x5417,
                /* Linux block ioctls commonly used by mkfs/mount utilities */
                BLKGETSIZE   = 0x1260,       /* get device size in 512-byte sectors (unsigned long*) */
                BLKSSZGET    = 0x1268,       /* get logical sector size (int*) */
                BLKBSZGET    = 0x80081270,   /* get block size (int*) */
                BLKGETSIZE64 = 0x80081272,   /* get device size in bytes (uint64_t*) */
                FIONREAD  = 0x541B,
                FIONBIO   = 0x5421,
                FIOASYNC  = 0x5452, /* set/clear O_ASYNC (nginx worker channel) */
            };

            /* no ioctl tracing in release builds */

            /* Kernel ABI structs (minimal) */
            struct winsize { uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel; };
            typedef uint32_t tcflag_t;
            typedef uint8_t  cc_t;
            typedef uint32_t speed_t;
            struct termios_k {
                tcflag_t c_iflag;
                tcflag_t c_oflag;
                tcflag_t c_cflag;
                tcflag_t c_lflag;
                cc_t c_line;
                cc_t c_cc[19];
                speed_t c_ispeed;
                speed_t c_ospeed;
            };

            /* usbdevfs subset for /dev/bus/usb/BBB/DDD */
            if (usb_is_devfs_file(f)) {
                const usb_device_t *cd = usb_device_from_file(f);
                usb_device_t *dev = (usb_device_t *)cd;
                if (!dev) return ret_err(ENOENT);

                if (req == USBDEVFS_CLAIMINTERFACE || req == USBDEVFS_RELEASEINTERFACE) {
                    if (!argp) return ret_err(EFAULT);
                    int ifnum = 0;
                    if (copy_from_user_raw(&ifnum, argp, sizeof(ifnum)) != 0) return ret_err(EFAULT);
                    int rc = (req == USBDEVFS_CLAIMINTERFACE) ? usb_claim_interface(dev, ifnum)
                                                               : usb_release_interface(dev, ifnum);
                    return (rc == 0) ? 0 : ret_err(EINVAL);
                }
                if (req == USBDEVFS_RESET) {
                    return (usb_reset_device(dev) == 0) ? 0 : ret_err(EIO);
                }
                if (req == USBDEVFS_CONTROL) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_ctrltransfer_t))) return ret_err(EFAULT);
                    usbdevfs_ctrltransfer_t ctl;
                    if (copy_from_user_raw(&ctl, argp, sizeof(ctl)) != 0) return ret_err(EFAULT);
                    if (ctl.wLength > 4096) return ret_err(EINVAL);
                    void *kbuf = NULL;
                    if (ctl.wLength > 0) {
                        if (!ctl.data || !user_range_ok(ctl.data, ctl.wLength)) return ret_err(EFAULT);
                        kbuf = kmalloc(ctl.wLength);
                        if (!kbuf) return ret_err(ENOMEM);
                        if ((ctl.bRequestType & 0x80) == 0) {
                            if (copy_from_user_raw(kbuf, ctl.data, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                        } else {
                            memset(kbuf, 0, ctl.wLength);
                        }
                    }
                    usb_setup_packet_t s;
                    s.bmRequestType = ctl.bRequestType;
                    s.bRequest = ctl.bRequest;
                    s.wValue = ctl.wValue;
                    s.wIndex = ctl.wIndex;
                    s.wLength = ctl.wLength;
                    int rc = usb_control_transfer(dev, &s, kbuf, ctl.wLength, ctl.timeout ? ctl.timeout : 1000);
                    if (rc >= 0 && (ctl.bRequestType & 0x80) && ctl.wLength > 0) {
                        if (copy_to_user_safe(ctl.data, kbuf, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                if (req == USBDEVFS_BULK) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_bulktransfer_t))) return ret_err(EFAULT);
                    usbdevfs_bulktransfer_t b;
                    if (copy_from_user_raw(&b, argp, sizeof(b)) != 0) return ret_err(EFAULT);
                    if (b.len > 65536u) return ret_err(EINVAL);
                    if (b.len > 0 && (!b.data || !user_range_ok(b.data, b.len))) return ret_err(EFAULT);
                    void *kbuf = NULL;
                    if (b.len > 0) {
                        kbuf = kmalloc(b.len);
                        if (!kbuf) return ret_err(ENOMEM);
                    }
                    int is_in = (b.ep & 0x80u) ? 1 : 0;
                    if (!is_in && b.len > 0) {
                        if (copy_from_user_raw(kbuf, b.data, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    int rc = usb_bulk_transfer(dev, (uint8_t)(b.ep & 0x0Fu), is_in, kbuf, b.len, b.timeout ? b.timeout : 1000);
                    if (rc >= 0 && is_in && b.len > 0) {
                        if (copy_to_user_safe(b.data, kbuf, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                return ret_err(ENOTTY);
            }

            /* Linux fbdev ioctls on /dev/fb0 (Xorg Driver "fbdev"). */
            if (fbdev_is_fb0_file(f)) {
                if (req == FBIOGET_VSCREENINFO) {
                    struct fb_var_screeninfo v;
                    if (!argp) return ret_err(EFAULT);
                    if (!fbdev_is_active()) return ret_err(ENODEV);
                    fbdev_get_var(&v);
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                if (req == FBIOPUT_VSCREENINFO) {
                    struct fb_var_screeninfo v;
                    if (!argp) return ret_err(EFAULT);
                    if (copy_from_user_raw(&v, argp, sizeof(v)) != 0) return ret_err(EFAULT);
                    int rc = fbdev_check_var(&v);
                    return rc < 0 ? ret_err(-rc) : 0;
                }
                if (req == FBIOGET_FSCREENINFO) {
                    struct fb_fix_screeninfo fi;
                    if (!argp) return ret_err(EFAULT);
                    if (!fbdev_is_active()) return ret_err(ENODEV);
                    fbdev_get_fix(&fi);
                    if (copy_to_user_safe(argp, &fi, sizeof(fi)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                if (req == FBIOPAN_DISPLAY) {
                    struct fb_var_screeninfo v;
                    if (!argp) return ret_err(EFAULT);
                    if (copy_from_user_raw(&v, argp, sizeof(v)) != 0) return ret_err(EFAULT);
                    int rc = fbdev_check_var(&v);
                    if (rc < 0) return ret_err(-rc);
                    fbdev_flush_display();
                    return 0;
                }
                if (req == FBIOBLANK)
                    return 0;
                if (req == FBIO_WAITFORVSYNC) {
                    fbdev_flush_display();
                    return 0;
                }
                return ret_err(ENOTTY);
            }

            /* Block-device ioctls for /dev/sdX,/dev/hdX (needed by mkfs.vfat and friends). */
            if (req == BLKSSZGET || req == BLKBSZGET || req == BLKGETSIZE || req == BLKGETSIZE64) {
                if (!argp) return ret_err(EFAULT);
                if (!f->path || devfs_get_device_id(f->path) < 0) return ret_err(ENOTTY);
                uint64_t bytes = (uint64_t)f->size;
                if (req == BLKSSZGET || req == BLKBSZGET) {
                    int v = 512;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                if (req == BLKGETSIZE64) {
                    uint64_t v = bytes;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* BLKGETSIZE -> number of 512-byte sectors (unsigned long on x86_64) */
                {
                    uint64_t sectors = bytes / 512u;
                    if (copy_to_user_safe(argp, &sectors, sizeof(sectors)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* Window-size query: succeed on real ttys; ENOTTY elsewhere so isatty()-like
               probes on /dev/null do not pretend to be interactive. */
            if (req == TIOCGWINSZ) {
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                uint16_t rows = (uint16_t)console_max_rows();
                uint16_t cols = (uint16_t)console_max_cols();
                if (rows == 0) rows = 25;
                if (cols == 0) cols = 80;
                struct winsize ws = { .ws_row = rows,
                                      .ws_col = cols,
                                      .ws_xpixel = 0, 
                                      .ws_ypixel = 0 };
                if (copy_to_user_safe(argp, &ws, sizeof(ws)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSWINSZ) {
                if (!argp)  return ret_err(EFAULT); /* accept setting window size silently */
                /* optionally we could copy_from_user and store winsize, but accept for now */
                return 0;
            }
            if (req == TIOCSCTTY) {
                /* Always succeed: EPERM here poisons errno and breaks ld.so
                   open_path() with "Operation not permitted" on libraries. */
                thread_t *curth = cur;
                if (!curth) return 0;
                int ctty_sid = curth->process ? curth->process->sid : curth->sid;
                int ctty_pgid = curth->process ? (int)curth->process->pgid : curth->pgid;
                if (ctty_pgid <= 0)
                    ctty_pgid = curth->pgid;
                if (pid1_dl_trace_thread(curth)) {
                    kprintf("dl-trace ioctl TIOCSCTTY ok fd=%d tty_sid=%d th_sid=%d th_tid=%d euid=%u\n",
                        fd, devfs_get_tty_controlling_sid(f), ctty_sid,
                        (int)(curth->tid ? curth->tid : 1), (unsigned)curth->euid);
                }
                devfs_tty_attach_thread(f, curth);
                if (ctty_sid > 0)
                    devfs_set_tty_controlling_sid(f, ctty_sid);
                {
                    int tty_idx = devfs_get_tty_index_from_file(f);
                    if (tty_idx >= 0 && ctty_pgid > 0)
                        devfs_set_tty_fg_pgrp(tty_idx, ctty_pgid);
                }
                return 0;
            }
            if (req == TIOCGPGRP) {
                if (!argp) return ret_err(EFAULT);
                /*
                 * BusyBox ash setjobctl spins:
                 *   while (tcgetpgrp(tty) != getpgrp())
                 *       kill(-getpgrp(), SIGTTIN);
                 * Falling back to the global user_pgrp (often still 1 from
                 * boot) when fg_pgrp is unset made login shells loop forever
                 * on getpgrp/kill/ioctl — SIGTTIN is not a stop here, so the
                 * mismatch never clears. Prefer the caller's pgid and publish
                 * it when this session owns the tty (or fg is dead/unset).
                 */
                int pgrp = devfs_tty_get_fg_pgrp(f);
                int my_pgid = 0;
                int my_sid = -1;
                if (cur && cur->process) {
                    my_pgid = (int)cur->process->pgid;
                    my_sid = cur->process->sid;
                } else if (cur) {
                    my_pgid = cur->pgid;
                    my_sid = cur->sid;
                }
                int tty_sid = devfs_get_tty_controlling_sid(f);
                int fg_live = 0;
                if (pgrp > 0) {
                    if (cur && cur->process)
                        fg_live = process_signal_targets(cur->process, -pgrp, 0) > 0;
                    else {
                        for (int i = 0; i < thread_get_count(); i++) {
                            thread_t *t = thread_get_by_index(i);
                            if (t && t->state != THREAD_TERMINATED && t->pgid == pgrp) {
                                fg_live = 1;
                                break;
                            }
                        }
                    }
                }
                if (pgrp < 0 || !fg_live) {
                    if (my_pgid > 0) {
                        pgrp = my_pgid;
                        if (tty_sid < 0 || tty_sid == my_sid)
                            (void)devfs_tty_set_fg_pgrp(f, pgrp);
                    } else {
                        pgrp = (int)user_pgrp;
                    }
                }
                if (cur && cur->name[0] && strstr(cur->name, "/bin/sh")) {
                    static int ash_jobctl_left = 8;
                    if (ash_jobctl_left-- > 0)
                        devel_printf("ash-jobctl: tcgetpgrp fd=%d fg=%d live=%d "
                                "my_pgid=%d my_sid=%d tty_sid=%d\n",
                                fd, pgrp, fg_live, my_pgid, my_sid, tty_sid);
                }
                uint32_t pu = (uint32_t)pgrp;
                if (copy_to_user_safe(argp, &pu, sizeof(pu)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSPGRP) {
                /* Linux tcsetpgrp: set tty foreground process group. */
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                uint32_t p = 0;
                if (copy_from_user_raw(&p, argp, sizeof(p)) != 0) return ret_err(EFAULT);
                if (p == 0) return ret_err(EINVAL);
                if (devfs_tty_set_fg_pgrp(f, (int)p) != 0)
                    return ret_err(ENOTTY);
                return 0;
            }
            if (req == TCFLSH) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                /* Linux: arg is TCIFLUSH=0, TCOFLUSH=1, TCIOFLUSH=2.
                 * We only buffer input; output flush is a no-op. */
                unsigned long which = (unsigned long)argp;
                if (which == 0 || which == 2) /* TCIFLUSH | TCIOFLUSH */
                    devfs_tty_flush_input(tty_idx);
                return 0;
            }
            if (req == TIOCNOTTY) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                thread_t *ct = cur;
                if (ct) {
                    int tty_idx = devfs_get_tty_index_from_file(f);
                    if (tty_idx >= 0 && ct->attached_tty == tty_idx)
                        ct->attached_tty = -1;
                    if (tty_idx >= 0 && devfs_get_tty_by_index(tty_idx) &&
                        devfs_get_tty_by_index(tty_idx)->controlling_sid == ct->sid)
                        devfs_get_tty_by_index(tty_idx)->controlling_sid = -1;
                }
                return 0;
            }
            if (req == TIOCGSID) {
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                thread_t *ct = cur;
                int sid = (ct && ct->sid >= 0) ? ct->sid : 0;
                if (copy_to_user_safe(argp, &sid, sizeof(sid)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCMGET) {
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                /* Virtual consoles: report carrier present so getty proceeds without -L. */
                int bits = (int)(0x40u | 0x100u | 0x04u); /* CAR|DSR|LE */
                if (copy_to_user_safe(argp, &bits, sizeof(bits)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCMBIS || req == TIOCMBIC) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                return 0;
            }
            if (req == TCGETS) {
                if (!argp) return ret_err(EFAULT);
                /* isatty(3) is TCGETS success. Lying here for /dev/null made ash
                 * think stdin was interactive, read EOF, exit, and respawn-loop. */
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                struct termios_k tio;
                memset(&tio, 0, sizeof(tio));
                tio.c_iflag = 0x00000100u /* ICRNL */;
                tio.c_oflag = 0x00000001u /* OPOST */;
                tio.c_cflag = 0x00000CB7u; /* CS8|CREAD|CLOCAL */
                tio.c_lflag = 0x00000002u /* ICANON */ | 0x00000008u /* ECHO */ | 0x00000001u /* ISIG */;
                {
                    struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_tty_index_from_file(f));
                    if (tty) {
                        tio.c_lflag = tty->term_lflag;
                        tio.c_cc[5] = tty->term_vtime;
                        tio.c_cc[6] = tty->term_vmin;
                    }
                }
                tio.c_ispeed = 9600;
                tio.c_ospeed = 9600;
                /* Never copy full struct termios to userspace: NCCS differs (BusyBox vs glibc)
                 * and a 60-byte write clobbers the stack canary -> "stack smashing detected". */
                size_t safe_sz = 32;
                if (safe_sz > sizeof(tio)) safe_sz = sizeof(tio);
                if (copy_to_user_safe(argp, &tio, safe_sz) != 0) return ret_err(EFAULT);
                return 0;
            }

            /* Socket ioctls often used by wget/getaddrinfo paths. */
            if (f->type == SYSCALL_FTYPE_SOCKET) {
                if (req == FIONBIO) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    uint32_t on = 0;
                    if (copy_from_user_raw(&on, argp, sizeof(on)) != 0) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    if (s) s->nonblock = on ? 1 : 0;
                    return 0;
                }
                if (req == FIOASYNC) {
                    /* Linux sock_ioctl(FIOASYNC): toggle O_ASYNC / fasync.
                     * nginx master requires success when spawning workers
                     * (channel socketpair); SIGIO delivery can come later. */
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    uint32_t on = 0;
                    if (copy_from_user_raw(&on, argp, sizeof(on)) != 0) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    if (s) s->async = on ? 1 : 0;
                    return 0;
                }
                if (req == FIONREAD) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    uint32_t nb = 0;
                    if (s) {
                        if (s->sock_domain == AF_NETLINK_LOCAL) {
                            if (s->nl_rx_off < s->nl_rx_len)
                                nb = (uint32_t)(s->nl_rx_len - s->nl_rx_off);
                        } else if (s->unix_domain_stub && s->connected) {
                            size_t a = unix_stream_avail_to_read(s);
                            if (a > 0xFFFFFFFFu) a = 0xFFFFFFFFu;
                            nb = (uint32_t)a;
                        } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL &&
                                   s->dns_tcp_udp_bridge) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                            nb = (s->tcp.rx_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)s->tcp.rx_len;
                        }
                    }
                    if (copy_to_user_safe(argp, &nb, sizeof(nb)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* Network interface ioctls (SIOCxxx) - used by ip, ifconfig, etc. */
                enum {
                    SIOCGIFNAME    = 0x8910,
                    SIOCGIFCONF    = 0x8912,
                    SIOCGIFFLAGS   = 0x8913,
                    SIOCSIFFLAGS   = 0x8914,
                    SIOCGIFADDR    = 0x8915,
                    SIOCSIFADDR    = 0x8916,
                    SIOCGIFDSTADDR = 0x8917,
                    SIOCSIFDSTADDR = 0x8918,
                    SIOCGIFBRDADDR = 0x8919,
                    SIOCSIFBRDADDR = 0x891A,
                    SIOCGIFNETMASK = 0x891B,
                    SIOCSIFNETMASK = 0x891C,
                    SIOCGIFMETRIC  = 0x891D,
                    SIOCSIFMETRIC  = 0x891E,
                    SIOCGIFMTU     = 0x8921,
                    SIOCSIFMTU     = 0x8922,
                    SIOCGIFHWADDR  = 0x8927,
                    SIOCSIFHWADDR  = 0x8928,
                    SIOCGIFINDEX   = 0x8933,
                    SIOCGIFTXQLEN  = 0x8942,
                    SIOCSIFTXQLEN  = 0x8943,
                };
                /* struct ifreq layout (Linux x86_64):
                   char ifr_name[16];
                   union { sockaddr, int, ... } ifr_ifru; (16 bytes typically)
                   Total: 32-40 bytes depending on union member */
                struct ifreq_k {
                    char ifr_name[16];
                    union {
                        struct { uint16_t sa_family; char sa_data[14]; } ifr_addr;
                        struct { uint16_t sa_family; uint8_t sa_data[14]; } ifr_hwaddr;
                        int16_t ifr_flags;
                        int32_t ifr_ifindex;
                        int32_t ifr_metric;
                        int32_t ifr_mtu;
                        int32_t ifr_qlen;
                    };
                };
                /* Check if this is a network interface ioctl */
                enum {
                    SIOCADDRT_LOCAL = 0x890B,
                    SIOCDELRT_LOCAL = 0x890C,
                };
                if (req == SIOCADDRT_LOCAL || req == SIOCDELRT_LOCAL) {
                    /* struct rtentry (x86_64): pad1 + 3x sockaddr + flags ... */
                    struct rtentry_k {
                        uint64_t rt_pad1;
                        struct { uint16_t sa_family; char sa_data[14]; } rt_dst;
                        struct { uint16_t sa_family; char sa_data[14]; } rt_gateway;
                        struct { uint16_t sa_family; char sa_data[14]; } rt_genmask;
                        uint16_t rt_flags;
                    } rt;
                    if (!argp || !user_range_ok(argp, sizeof(rt))) return ret_err(EFAULT);
                    memset(&rt, 0, sizeof(rt));
                    if (copy_from_user_raw(&rt, argp, sizeof(rt)) != 0) return ret_err(EFAULT);
                    if (net_stack_init() != 0) return ret_err(ENETDOWN);
                    if (req == SIOCDELRT_LOCAL) {
                        g_net.gw_be = 0;
                        g_net.gw_mac_valid = 0;
                        return 0;
                    }
                    if (rt.rt_gateway.sa_family == AF_INET_LOCAL) {
                        uint32_t wire = 0;
                        memcpy(&wire, rt.rt_gateway.sa_data + 2, 4);
                        g_net.gw_be = be32(wire);
                        g_net.gw_mac_valid = 0;
                        if (!g_net.dns_be)
                            g_net.dns_be = g_net.gw_be;
                        if (g_net.ip_be && g_net.if_up) {
                            g_net.ready = 1;
                            net_write_resolv_from_dns(g_net.dns_be ? g_net.dns_be : g_net.gw_be);
                            net_announce_ipv4("route");
                        }
                    }
                    return 0;
                }
                if (req == SIOCGIFNAME || req == SIOCGIFINDEX || req == SIOCGIFFLAGS ||
                    req == SIOCGIFADDR || req == SIOCGIFNETMASK || req == SIOCGIFBRDADDR ||
                    req == SIOCGIFHWADDR || req == SIOCGIFMTU || req == SIOCGIFTXQLEN ||
                    req == SIOCGIFMETRIC || req == SIOCGIFDSTADDR ||
                    req == SIOCSIFFLAGS || req == SIOCSIFADDR || req == SIOCSIFNETMASK ||
                    req == SIOCSIFMTU || req == SIOCSIFTXQLEN) {
                    if (!argp || !user_range_ok(argp, sizeof(struct ifreq_k))) return ret_err(EFAULT);
                    struct ifreq_k ifr;
                    memset(&ifr, 0, sizeof(ifr));
                    if (copy_from_user_raw(&ifr, argp, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    /* Determine which interface: lo (index 1) or eth0 (index 2) */
                    int is_lo = 0, is_eth0 = 0;
                    if (strcmp(ifr.ifr_name, "lo") == 0) is_lo = 1;
                    else if (strcmp(ifr.ifr_name, "eth0") == 0 || ifr.ifr_name[0] == '\0') is_eth0 = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 1) is_lo = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 2) is_eth0 = 1;
                    if (!is_lo && !is_eth0) return ret_err(ENODEV);
                    /* Set interface name */
                    if (is_lo) strncpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name));
                    else strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name));
                    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
                    /* Handle specific requests */
                    if (req == SIOCGIFINDEX) {
                        ifr.ifr_ifindex = is_lo ? 1 : 2;
                    } else if (req == SIOCGIFNAME) {
                        /* ifr_name already set above */
                    } else if (req == SIOCGIFFLAGS) {
                        if (is_lo) {
                            /* IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP */
                            ifr.ifr_flags = (int16_t)(0x1 | 0x8 | 0x40);
                        } else {
                            (void)net_stack_init();
                            ifr.ifr_flags = (int16_t)(0x2 | 0x1000);
                            if (g_net.if_up)
                                ifr.ifr_flags |= (int16_t)0x1;
                            if (g_net.if_up && e1000_link_is_up())
                                ifr.ifr_flags |= (int16_t)0x40;
                        }
                    } else if (req == SIOCSIFFLAGS) {
                        if (is_eth0 && net_set_if_up(!!(ifr.ifr_flags & 0x1)) != 0)
                            return ret_err(EIO);
                    } else if (req == SIOCGIFADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t ip = is_lo ? 0x0100007Fu : be32(g_net.ip_be);
                        memcpy(ifr.ifr_addr.sa_data + 2, &ip, 4);
                    } else if (req == SIOCGIFNETMASK) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t mask = is_lo ? 0x000000FFu : be32(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
                        memcpy(ifr.ifr_addr.sa_data + 2, &mask, 4);
                    } else if (req == SIOCGIFBRDADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        if (is_lo) {
                            /* lo has no broadcast */
                            return ret_err(ENODEV);
                        }
                        uint32_t mask = g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u;
                        uint32_t brd = be32((g_net.ip_be & mask) | ~mask);
                        memcpy(ifr.ifr_addr.sa_data + 2, &brd, 4);
                    } else if (req == SIOCGIFDSTADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t dst = is_lo ? 0x0100007Fu : be32(g_net.gw_be);
                        memcpy(ifr.ifr_addr.sa_data + 2, &dst, 4);
                    } else if (req == SIOCGIFHWADDR) {
                        if (is_lo) {
                            ifr.ifr_hwaddr.sa_family = 772; /* ARPHRD_LOOPBACK */
                            memset(ifr.ifr_hwaddr.sa_data, 0, 6);
                        } else {
                            (void)net_stack_init();
                            ifr.ifr_hwaddr.sa_family = 1; /* ARPHRD_ETHER */
                            memcpy(ifr.ifr_hwaddr.sa_data, g_net.mac, 6);
                        }
                    } else if (req == SIOCGIFMTU) {
                        ifr.ifr_mtu = is_lo ? 65536 : 1500;
                    } else if (req == SIOCSIFMTU) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFTXQLEN) {
                        ifr.ifr_qlen = is_lo ? 1000 : 1000; /* typical default */
                    } else if (req == SIOCSIFTXQLEN) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFMETRIC) {
                        ifr.ifr_metric = 0;
                    } else if (req == SIOCSIFADDR) {
                        if (is_lo) {
                            /* ignore static lo config */
                        } else {
                            uint32_t wire = 0;
                            memcpy(&wire, ifr.ifr_addr.sa_data + 2, 4);
                            uint32_t ip_be = be32(wire);
                            uint32_t mask = g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u;
                            if (net_apply_ipv4(ip_be, mask, g_net.gw_be, g_net.dns_be, 0) != 0)
                                return ret_err(EIO);
                        }
                    } else if (req == SIOCSIFNETMASK) {
                        if (is_eth0) {
                            uint32_t wire = 0;
                            memcpy(&wire, ifr.ifr_addr.sa_data + 2, 4);
                            g_net.mask_be = be32(wire);
                            if (g_net.ip_be && g_net.if_up)
                                g_net.ready = 1;
                        }
                    }
                    if (copy_to_user_safe(argp, &ifr, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* SIOCGIFCONF - list all interfaces */
                if (req == SIOCGIFCONF) {
                    if (!argp) return ret_err(EFAULT);
                    struct ifconf_k {
                        int32_t ifc_len;
                        int32_t __pad;
                        void *ifc_buf;
                    } ifc;
                    if (copy_from_user_raw(&ifc, argp, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    /* We have 2 interfaces: lo and eth0 */
                    struct ifreq_k entries[2];
                    memset(entries, 0, sizeof(entries));
                    /* lo */
                    strncpy(entries[0].ifr_name, "lo", sizeof(entries[0].ifr_name));
                    entries[0].ifr_addr.sa_family = AF_INET_LOCAL;
                    uint32_t lo_ip = 0x0100007Fu; /* 127.0.0.1 in big-endian */
                    memcpy(entries[0].ifr_addr.sa_data + 2, &lo_ip, 4);
                    /* eth0 */
                    strncpy(entries[1].ifr_name, "eth0", sizeof(entries[1].ifr_name));
                    entries[1].ifr_addr.sa_family = AF_INET_LOCAL;
                    {
                        uint32_t wire = be32(g_net.ip_be);
                        memcpy(entries[1].ifr_addr.sa_data + 2, &wire, 4);
                    }
                    int32_t needed = (int32_t)(2 * sizeof(struct ifreq_k));
                    if (ifc.ifc_buf && ifc.ifc_len > 0) {
                        int32_t copy_len = (ifc.ifc_len < needed) ? ifc.ifc_len : needed;
                        if (user_range_ok(ifc.ifc_buf, (size_t)copy_len)) {
                            copy_to_user_safe(ifc.ifc_buf, entries, (size_t)copy_len);
                        }
                        ifc.ifc_len = copy_len;
                    } else {
                        ifc.ifc_len = needed;
                    }
                    if (copy_to_user_safe(argp, &ifc, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* KDGKBTYPE (0x4B33): get keyboard type. BusyBox chvt uses this to validate console fd. */
            if (req == 0x4B33) {
                if (argp && user_range_ok(argp, 1)) {
                    char kbd_type = 0x02; /* KB_101 — Linux always answers this */
                    if (copy_to_user_safe(argp, &kbd_type, 1) == 0 && devfs_is_tty_file(f))
                        return 0;
                }
                return ret_err(ENOTTY);
            }

            /* For the remaining tty-specific ioctls, require a real tty file. */
            if (!devfs_is_tty_file(f)) {
                return ret_err(ENOTTY);
            }

            /*
             * Linux console font ioctls (include/uapi/linux/kd.h).
             * BusyBox loadfont/setfont use KDFONTOP; older tools use PIO_FONT*.
             * Font payload is PSF-decoded in userspace — NOT GRUB .pf2.
             */
            {
                enum {
                    GIO_FONT_I = 0x4B60,
                    PIO_FONT_I = 0x4B61,
                    GIO_UNIMAP_I = 0x4B66,
                    PIO_UNIMAP_I = 0x4B67,
                    PIO_UNIMAPCLR_I = 0x4B68,
                    GIO_FONTX_I = 0x4B6B,
                    PIO_FONTX_I = 0x4B6C,
                    PIO_FONTRESET_I = 0x4B6D,
                    KDFONTOP_I = 0x4B72,
                    KD_FONT_OP_SET = 0,
                    KD_FONT_OP_GET = 1,
                    KD_FONT_OP_SET_DEFAULT = 2,
                    KD_FONT_OP_SET_TALL = 4,
                    KD_FONT_OP_GET_TALL = 5
                };
                if (req == PIO_FONTRESET_I) {
                    font_init_default();
                    con_unimap_clear();
                    font_notify_changed();
                    return 0;
                }
                /* Unicode → glyph map (BusyBox setfont after KDFONTOP). */
                if (req == PIO_UNIMAPCLR_I) {
                    /* struct unimapinit advice — optional; Linux ignores contents. */
                    (void)argp;
                    con_unimap_clear();
                    return 0;
                }
                if (req == PIO_UNIMAP_I) {
                    struct unimapdesc_k {
                        uint16_t entry_ct;
                        uint16_t _pad0;
                        uint32_t _pad1;
                        uint64_t entries;
                    } ud;
                    if (!argp || copy_from_user_raw(&ud, argp, sizeof(ud)) != 0)
                        return ret_err(EFAULT);
                    if (ud.entry_ct == 0) {
                        con_unimap_clear();
                        return 0;
                    }
                    if (ud.entry_ct > 8192 || !ud.entries)
                        return ret_err(EINVAL);
                    size_t need = (size_t)ud.entry_ct * 4u; /* struct unipair */
                    void *pairs = kmalloc(need);
                    if (!pairs) return ret_err(ENOMEM);
                    if (copy_from_user_raw(pairs, (const void *)(uintptr_t)ud.entries, need) != 0) {
                        kfree(pairs);
                        return ret_err(EFAULT);
                    }
                    int rc = con_unimap_set(ud.entry_ct, pairs);
                    kfree(pairs);
                    return rc < 0 ? ret_err(-rc) : 0;
                }
                if (req == GIO_UNIMAP_I) {
                    struct unimapdesc_k {
                        uint16_t entry_ct;
                        uint16_t _pad0;
                        uint32_t _pad1;
                        uint64_t entries;
                    } ud;
                    if (!argp || copy_from_user_raw(&ud, argp, sizeof(ud)) != 0)
                        return ret_err(EFAULT);
                    unsigned have = 0;
                    int rc = con_unimap_get(&have, NULL, 0);
                    if (rc < 0) return ret_err(-rc);
                    if (!ud.entries) {
                        ud.entry_ct = (uint16_t)(have > 0xFFFFu ? 0xFFFFu : have);
                        if (copy_to_user_safe(argp, &ud, sizeof(ud)) != 0)
                            return ret_err(EFAULT);
                        return 0;
                    }
                    if (ud.entry_ct < have)
                        return ret_err(ENOMEM); /* Linux: ENOSPC-ish via ENOMEM for small buf */
                    size_t need = (size_t)have * 4u;
                    void *pairs = kmalloc(need ? need : 1);
                    if (!pairs) return ret_err(ENOMEM);
                    rc = con_unimap_get(&have, pairs, have);
                    if (rc == 0 &&
                        copy_to_user_safe((void *)(uintptr_t)ud.entries, pairs, need) != 0)
                        rc = -EFAULT;
                    kfree(pairs);
                    if (rc < 0) return ret_err(-rc);
                    ud.entry_ct = (uint16_t)have;
                    if (copy_to_user_safe(argp, &ud, sizeof(ud)) != 0)
                        return ret_err(EFAULT);
                    return 0;
                }
                if (req == PIO_FONT_I) {
                    /* Expanded form: 256 glyphs × 32 bytes, width=8. */
                    if (!argp) return ret_err(EFAULT);
                    size_t need = 256u * 32u;
                    uint8_t *buf = (uint8_t *)kmalloc(need);
                    if (!buf) return ret_err(ENOMEM);
                    if (copy_from_user_raw(buf, argp, need) != 0) {
                        kfree(buf);
                        return ret_err(EFAULT);
                    }
                    int rc = font_load_kd(8, 32, 256, buf, 32);
                    kfree(buf);
                    return rc < 0 ? ret_err(-rc) : 0;
                }
                if (req == GIO_FONT_I) {
                    if (!argp) return ret_err(EFAULT);
                    size_t need = 256u * 32u;
                    uint8_t *buf = (uint8_t *)kmalloc(need);
                    if (!buf) return ret_err(ENOMEM);
                    uint32_t w = 0, h = 0, cc = 0;
                    int rc = font_export_kd(&w, &h, &cc, buf, need, 32);
                    if (rc == 0 && copy_to_user_safe(argp, buf, need) != 0)
                        rc = -EFAULT;
                    kfree(buf);
                    return rc < 0 ? ret_err(-rc) : 0;
                }
                if (req == PIO_FONTX_I || req == GIO_FONTX_I) {
                    struct consolefontdesc_k {
                        uint16_t charcount;
                        uint16_t charheight;
                        uint32_t _pad;
                        uint64_t chardata;
                    } cfd;
                    if (!argp || copy_from_user_raw(&cfd, argp, sizeof(cfd)) != 0)
                        return ret_err(EFAULT);
                    if (cfd.charcount == 0 || cfd.charcount > 512 ||
                        cfd.charheight == 0 || cfd.charheight > 32)
                        return ret_err(EINVAL);
                    size_t need = (size_t)cfd.charcount * (size_t)cfd.charheight;
                    if (req == PIO_FONTX_I) {
                        if (!cfd.chardata) return ret_err(EFAULT);
                        uint8_t *buf = (uint8_t *)kmalloc(need);
                        if (!buf) return ret_err(ENOMEM);
                        if (copy_from_user_raw(buf, (const void *)(uintptr_t)cfd.chardata, need) != 0) {
                            kfree(buf);
                            return ret_err(EFAULT);
                        }
                        /* PIO_FONTX: width fixed to 8, rows = charheight (tall). */
                        int rc = font_load_kd(8, cfd.charheight, cfd.charcount, buf, cfd.charheight);
                        kfree(buf);
                        return rc < 0 ? ret_err(-rc) : 0;
                    }
                    /* GIO_FONTX — width 8 only (classic VGA cell). */
                    uint32_t w = 0, h = 0, cc = 0;
                    int rc = font_export_kd(&w, &h, &cc, NULL, 0, 0);
                    if (rc < 0) return ret_err(-rc);
                    if (w != 8) return ret_err(EINVAL);
                    cfd.charcount = (uint16_t)(cc > 512 ? 512 : cc);
                    cfd.charheight = (uint16_t)h;
                    if (cfd.chardata) {
                        size_t out_need = (size_t)cfd.charcount * (size_t)cfd.charheight;
                        uint8_t *buf = (uint8_t *)kmalloc(out_need);
                        if (!buf) return ret_err(ENOMEM);
                        rc = font_export_kd(&w, &h, &cc, buf, out_need, h);
                        if (rc == 0 &&
                            copy_to_user_safe((void *)(uintptr_t)cfd.chardata, buf, out_need) != 0)
                            rc = -EFAULT;
                        kfree(buf);
                    }
                    if (rc < 0) return ret_err(-rc);
                    if (copy_to_user_safe(argp, &cfd, sizeof(cfd)) != 0)
                        return ret_err(EFAULT);
                    return 0;
                }
                if (req == KDFONTOP_I) {
                    struct console_font_op_k {
                        uint32_t op;
                        uint32_t flags;
                        uint32_t width;
                        uint32_t height;
                        uint32_t charcount;
                        uint32_t _pad;
                        uint64_t data;
                    } cfo;
                    if (!argp || copy_from_user_raw(&cfo, argp, sizeof(cfo)) != 0)
                        return ret_err(EFAULT);
                    if (cfo.op == KD_FONT_OP_SET_DEFAULT) {
                        font_init_default();
                        font_notify_changed();
                        return 0;
                    }
                    if (cfo.op == KD_FONT_OP_SET || cfo.op == KD_FONT_OP_SET_TALL) {
                        if (cfo.width == 0 || cfo.height == 0 || cfo.charcount == 0 ||
                            cfo.width > FONT_MAX_CELL_W || cfo.height > FONT_MAX_CELL_H ||
                            cfo.charcount > 512)
                            return ret_err(EINVAL);
                        if (!cfo.data) return ret_err(EFAULT);
                        uint32_t vpitch = (cfo.op == KD_FONT_OP_SET_TALL) ? cfo.height : 32u;
                        uint32_t bpr = (cfo.width + 7u) / 8u;
                        size_t need = (size_t)cfo.charcount * (size_t)vpitch * bpr;
                        if (need == 0 || need > (4u * 1024u * 1024u))
                            return ret_err(EINVAL);
                        uint8_t *buf = (uint8_t *)kmalloc(need);
                        if (!buf) return ret_err(ENOMEM);
                        if (copy_from_user_raw(buf, (const void *)(uintptr_t)cfo.data, need) != 0) {
                            kfree(buf);
                            return ret_err(EFAULT);
                        }
                        int rc = font_load_kd(cfo.width, cfo.height, cfo.charcount, buf, vpitch);
                        kfree(buf);
                        return rc < 0 ? ret_err(-rc) : 0;
                    }
                    if (cfo.op == KD_FONT_OP_GET || cfo.op == KD_FONT_OP_GET_TALL) {
                        uint32_t w = 0, h = 0, cc = 0;
                        uint32_t vpitch = (cfo.op == KD_FONT_OP_GET_TALL) ? 0 : 32u;
                        int rc = font_export_kd(&w, &h, &cc, NULL, 0, 16);
                        if (rc < 0) return ret_err(-rc);
                        if (cfo.op == KD_FONT_OP_GET_TALL)
                            vpitch = h;
                        cfo.width = w;
                        cfo.height = h;
                        cfo.charcount = cc;
                        if (cfo.data) {
                            uint32_t bpr = (w + 7u) / 8u;
                            size_t need = (size_t)cc * (size_t)vpitch * bpr;
                            uint8_t *buf = (uint8_t *)kmalloc(need);
                            if (!buf) return ret_err(ENOMEM);
                            rc = font_export_kd(&w, &h, &cc, buf, need, vpitch);
                            if (rc == 0 &&
                                copy_to_user_safe((void *)(uintptr_t)cfo.data, buf, need) != 0)
                                rc = -EFAULT;
                            kfree(buf);
                            if (rc < 0) return ret_err(-rc);
                        }
                        if (copy_to_user_safe(argp, &cfo, sizeof(cfo)) != 0)
                            return ret_err(EFAULT);
                        return 0;
                    }
                    return ret_err(EINVAL);
                }
            }
            if (req == 0x5606) { /* VT_ACTIVATE: BusyBox passes vt as value; glibc may pass int* */
                int vt = -1;
                uintptr_t ua = (uintptr_t)argp;
                if (ua >= 1 && ua <= (uintptr_t)DEVFS_TTY_COUNT)
                    vt = (int)ua;
                else if (argp && user_range_ok(argp, sizeof(int))) {
                    if (copy_from_user_raw(&vt, argp, sizeof(vt)) != 0)
                        return ret_err(EFAULT);
                } else
                    return ret_err(EFAULT);
                if (vt >= 1 && vt <= DEVFS_TTY_COUNT) {
                    devfs_switch_tty(vt - 1);
                    return 0;
                }
                return ret_err(ENOTTY);
            }
            if (req == 0x5607) { /* VT_WAITACTIVE: VT_ACTIVATE is synchronous */
                (void)argp;
                return 0;
            }
            if (req == TCSETS || req == TCSETSW || req == TCSETSF) {
                if (!argp) return ret_err(EFAULT);
                struct termios_k tio;
                size_t need = 24; /* through c_cc[6] (VMIN); avoids libc-specific full struct sizes */
                if (copy_from_user_raw(&tio, argp, need) != 0) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                struct devfs_tty *tty = devfs_get_tty_by_index(tty_idx);
                if (!tty) return ret_err(ENOTTY);
                tty->term_lflag = tio.c_lflag;
                tty->term_vtime = tio.c_cc[5];
                tty->term_vmin = tio.c_cc[6];
                /* TCSETSF: set attrs then flush pending input (Linux termios). */
                if (req == TCSETSF)
                    devfs_tty_flush_input(tty_idx);
                return 0;
            }
            if (req == TIOCSTI) {
                /* Push one byte as if typed on the tty (used by some tools; input path is unchanged). */
                if (!argp) return ret_err(EFAULT);
                unsigned char cbyte;
                if (copy_from_user_raw(&cbyte, argp, 1) != 0) return ret_err(EFAULT);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                devfs_tty_push_input(tty_idx, (char)cbyte);
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_write: {
            int fd = (int)a1;
            const void *bufp = (const void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            /* Prefer process fd table (CLONE_FILES / CLONE_THREAD). */
            struct fs_file *f = syscall_fd_get(cur, fd);
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                ssize_t wr = net_sock_write_userspace(cur, fd, s, bufp, cnt);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }
            if (f->type == FS_TYPE_PIPE && fs_pipe_is_write_end(f)) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                size_t copied = 0;
                void *tmp = copy_from_user_safe(bufp, cnt, PIPE_RW_CHUNK, &copied);
                if (!tmp) return ret_err(EFAULT);
                ssize_t wr = pipe_write_bytes(p, tmp, copied, cur);
                kfree(tmp);
                return (wr >= 0) ? (uint64_t)wr : ret_err((int)-wr);
            }
            if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
                eventfd_t *e = (eventfd_t *)f->driver_private;
                if (cnt < 8) return ret_err(EINVAL);
                uint64_t v = 0;
                if (copy_from_user_raw(&v, bufp, 8) != 0) return ret_err(EFAULT);
                ssize_t wr = eventfd_write_bytes(e, &v, 8, cur);
                return (wr >= 0) ? (uint64_t)wr : ret_err((int)-wr);
            }
            size_t total = 0;
            while (total < cnt) {
                size_t chunk = cnt - total;
                if (chunk > 4096) chunk = 4096;
                size_t copied = 0;
                void *tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 4096, &copied);
                if (!tmp && chunk > 512) {
                    chunk = 512;
                    tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 512, &copied);
                }
                if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                ssize_t wr = fs_write(f, tmp, copied, f->pos);
                kfree(tmp);
                if (wr <= 0) return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                f->pos += (size_t)wr;
                total += (size_t)wr;
                if ((size_t)wr < copied) break;
            }
            return (uint64_t)total;
        }
        case SYS_readv: {
            /* readv(fd, const struct iovec *iov, int iovcnt) - scatter read */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            struct fs_file *f = syscall_fd_get(cur, fd);
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t total = 0;
                for (int i = 0; i < iovcnt; i++) {
                    void *base = (void *)(uintptr_t)iov[i].base;
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                    size_t pos = 0;
                    while (pos < len) {
                        size_t chunk = len - pos;
                        if (chunk > 4096) chunk = 4096;
                        ssize_t rr = net_sock_read_userspace(cur, s, (uint8_t *)base + pos, chunk);
                        if (rr < 0) return (total > 0) ? total : ret_read_err(rr);
                        if (rr == 0) return total;
                        total += (uint64_t)rr;
                        pos += (size_t)rr;
                    }
                }
                return total;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr;
                    if (f->type == FS_TYPE_PIPE && fs_pipe_is_read_end(f) && f->driver_private) {
                        rr = pipe_read_bytes((pipe_t *)f->driver_private, tmp, chunk, cur);
                    } else if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
                        if (chunk < 8) {
                            kfree(tmp);
                            return (total > 0) ? total : ret_err(EINVAL);
                        }
                        rr = eventfd_read_bytes((eventfd_t *)f->driver_private, tmp, 8, cur);
                    } else {
                        rr = fs_read(f, tmp, chunk, f->pos);
                    }
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_read_err(rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (rr > (ssize_t)chunk) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err(EIO);
                    }
                    if (copy_to_user_safe((uint8_t*)base + off, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)rr;
                    total += (uint64_t)rr;
                    off += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case SYS_preadv: {
            /* preadv(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 295 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t pos = 0;
                while (pos < len) {
                    size_t chunk = len - pos;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr = fs_read(f, tmp, chunk, cur_off);
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_read_err(rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (rr > (ssize_t)chunk) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err(EIO);
                    }
                    if (copy_to_user_safe((uint8_t*)base + pos, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    cur_off += (size_t)rr;
                    total += (uint64_t)rr;
                    pos += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case 17: { /* pread64(fd, buf, count, offset) */
            int fd = (int)a1;
            void *bufp = (void *)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            int64_t off_in = (int64_t)a4;
            if (fd == g_dl_libeinfo_fd)
                devel_printf("dl-watch: pread64 libeinfo fd=%d off=%lld cnt=0x%zx\n",
                    fd, (long long)off_in, cnt);
            boot_io_log(cur, "pread64", fd, (uint64_t)off_in);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (off_in < 0) return ret_err(EINVAL);
            if (cnt == 0) return 0;
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            /* pread on pipes/sockets is invalid (doesn't use/advance file position). */
            if (f->type == SYSCALL_FTYPE_SOCKET || f->type == FS_TYPE_PIPE ||
                f->type == FS_TYPE_EVENTFD || f->type == FS_TYPE_EPOLL)
                return ret_err(ESPIPE);
            if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            while ((size_t)total < cnt) {
                size_t chunk = cnt - (size_t)total;
                if (chunk > 4096) chunk = 4096;
                void *tmp = kmalloc(chunk);
                if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                ssize_t rr = fs_read(f, tmp, chunk, cur_off);
                if (rr < 0) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_read_err(rr);
                }
                if (rr == 0) {
                    kfree(tmp);
                    return total;
                }
                if ((size_t)rr > chunk) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_err(EIO);
                }
                if (copy_to_user_safe((uint8_t *)bufp + total, tmp, (size_t)rr) != 0) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_err(EFAULT);
                }
                kfree(tmp);
                total += (uint64_t)rr;
                cur_off += (size_t)rr;
                if ((size_t)rr < chunk) return total;
            }
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_fd(cur, fd)) {
                const char *dp = thread_fd_path(cur, fd);
                kprintf("dl-trace pread64 fd=%d path=%s off=%lld cnt=0x%zx ret=%llu\n",
                    fd, dp ? dp : "?", (long long)off_in, cnt, (unsigned long long)total);
            }
            return total;
        }
        case 18: { /* pwrite64(fd, buf, count, offset) */
            int fd = (int)a1;
            const void *bufp = (const void *)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (off_in < 0) return ret_err(EINVAL);
            if (cnt == 0) return 0;
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET || f->type == FS_TYPE_PIPE) return ret_err(ESPIPE);
            if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            while ((size_t)total < cnt) {
                size_t chunk = cnt - (size_t)total;
                if (chunk > 4096) chunk = 4096;
                size_t copied = 0;
                void *tmp = copy_from_user_safe((const uint8_t *)bufp + total, chunk, 4096, &copied);
                if (!tmp) return (total > 0) ? total : ret_err(EFAULT);
                ssize_t wr = fs_write(f, tmp, copied, cur_off);
                kfree(tmp);
                if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                total += (uint64_t)wr;
                cur_off += (size_t)wr;
                if ((size_t)wr < copied) return total;
            }
            return total;
        }
        case SYS_read: {
            int fd = (int)a1;
            void *bufp = (void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd == g_dl_libeinfo_fd)
                devel_printf("dl-watch: read libeinfo fd=%d cnt=0x%zx\n", fd, cnt);
            boot_io_log(cur, "read", fd, (uint64_t)cnt);
            if (is_init_user(cur))
                g_dl_read_seen++;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = syscall_fd_get(cur, fd);
            if (!f) return ret_err(EBADF);
            if (cur && cur->name[0] && strstr(cur->name, "openrc")) {
                static int openrc_read_dbg_left = 24;
                if (openrc_read_dbg_left-- > 0) {
                    const char *rp = thread_fd_path(cur, fd);
                    devel_printf("openrc-read: tid=%llu fd=%d path=%s buf=0x%llx cnt=0x%zx type=%u\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        fd, rp ? rp : "?",
                        (unsigned long long)(uintptr_t)bufp, cnt,
                        (unsigned)f->type);
                }
            }
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ssize_t r = net_sock_read_userspace(cur, (ksock_net_t *)f->driver_private, bufp, cnt);
                if (r < 0) return ret_err((int)-r);
                return (uint64_t)r;
            }
            if (f->type == FS_TYPE_PIPE && fs_pipe_is_read_end(f)) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);
                size_t to_read = cnt < (size_t)PIPE_RW_CHUNK ? cnt : (size_t)PIPE_RW_CHUNK;
                void *tmp = kmalloc(to_read);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = pipe_read_bytes(p, tmp, to_read, cur);
                if (rr > 0) {
                    if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) { kfree(tmp); return ret_err(EFAULT); }
                }
                kfree(tmp);
                return (rr >= 0) ? (uint64_t)rr : ret_read_err(rr);
            }
            if (f->type == FS_TYPE_EVENTFD && f->driver_private) {
                eventfd_t *e = (eventfd_t *)f->driver_private;
                if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);
                if (cnt < 8) return ret_err(EINVAL);
                uint64_t v = 0;
                ssize_t rr = eventfd_read_bytes(e, &v, 8, cur);
                if (rr > 0 && copy_to_user_safe(bufp, &v, 8) != 0)
                    return ret_err(EFAULT);
                return (rr >= 0) ? (uint64_t)rr : ret_read_err(rr);
            }
            if (!bufp || !user_range_ok(bufp, cnt)) {
                if (is_init_user(cur))
                    devel_printf("boot-io: read EFAULT fd=%d buf=0x%llx cnt=0x%zx path=%s\n",
                        fd, (unsigned long long)(uintptr_t)bufp, cnt,
                        thread_fd_path(cur, fd) ? thread_fd_path(cur, fd) : "?");
                return ret_err(EFAULT);
            }
            size_t to_read = cnt < 4096 ? cnt : 4096;
            void *tmp = kmalloc(to_read);
            if (!tmp) return ret_err(ENOMEM);
            off_t read_pos = f->pos;
            ssize_t rr = fs_read(f, tmp, to_read, f->pos);

            if (rr > 0) {
                if (rr > (ssize_t)to_read) { kfree(tmp); return ret_err(EIO); }
                if (f->path && strcmp(f->path, "/etc/inittab") == 0) {
                    /* Normalize CRLF -> LF for busybox init parser. */
                    for (ssize_t i = 0; i < rr; i++) {
                        if (((char*)tmp)[i] == '\r') ((char*)tmp)[i] = '\n';
                    }
                    /* Some development initfs archives accidentally captured a secret-looking
                       one-line token in /etc/inittab. BusyBox init treats it as a bad entry,
                       then takes an early malloc/abort path that hides kernel diagnostics. */
                    for (ssize_t i = 0; i + 9 <= rr; i++) {
                        int at_line_start = (i == 0) || (((char*)tmp)[i - 1] == '\n');
                        if (at_line_start && memcmp((char*)tmp + i, "sk-or-v1-", 9) == 0) {
                            ((char*)tmp)[i] = '#';
                            for (ssize_t j = i + 1; j < rr && ((char*)tmp)[j] != '\n'; j++)
                                ((char*)tmp)[j] = ' ';
                        }
                    }
                    if (f->pos == 0) {
                        char preview[129];
                        size_t plen = (rr < 128) ? (size_t)rr : 128;
                        int has_nul = 0;
                        int has_respawn = 0;
                        int has_askfirst = 0;
                        int lines = 0;
                        for (size_t i = 0; i < plen; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\0') has_nul = 1;
                            if (c < 32 || c > 126) c = '.';
                            preview[i] = c;
                        }
                        preview[plen] = '\0';
                        for (ssize_t i = 0; i < rr; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\n') lines++;
                        }
                        if (rr >= 7) {
                            for (ssize_t i = 0; i + 7 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "respawn", 7) == 0) { has_respawn = 1; break; }
                            }
                        }
                        if (rr >= 8) {
                            for (ssize_t i = 0; i + 8 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "askfirst", 8) == 0) { has_askfirst = 1; break; }
                            }
                        }
                        {
                            char hex[3 * 32 + 1];
                            size_t hlen = (rr < 32) ? (size_t)rr : 32;
                            size_t w = 0;
                            for (size_t i = 0; i < hlen && w + 3 < sizeof(hex); i++) {
                                static const char *hx = "0123456789abcdef";
                                unsigned char b = (unsigned char)((char*)tmp)[i];
                                hex[w++] = hx[(b >> 4) & 0xF];
                                hex[w++] = hx[b & 0xF];
                                hex[w++] = ' ';
                            }
                            hex[w] = '\0';
                        }
                    }
                }
                if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) { kfree(tmp); return ret_err(EFAULT); }
                f->pos += (size_t)rr;
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_fd(cur, fd)) {
                    const char *dp = thread_fd_path(cur, fd);
                    kprintf("dl-trace read fd=%d path=%s off=%lld cnt=0x%zx ret=%zd\n",
                        fd, dp ? dp : "?", (long long)read_pos, cnt, rr);
                    if (rr > 0) {
                        const uint8_t *b = (const uint8_t *)tmp;
                        kprintf("dl-trace read data %02x%02x%02x%02x%02x%02x%02x%02x\n",
                            b[0], rr > 1 ? b[1] : 0, rr > 2 ? b[2] : 0, rr > 3 ? b[3] : 0,
                            rr > 4 ? b[4] : 0, rr > 5 ? b[5] : 0, rr > 6 ? b[6] : 0, rr > 7 ? b[7] : 0);
                    }
                }
                kfree(tmp);
                return (uint64_t)rr;
            }
            if (f->path && strcmp(f->path, "/etc/inittab") == 0 && f->pos == 0) {
            }
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_fd(cur, fd)) {
                const char *dp = thread_fd_path(cur, fd);
                kprintf("dl-trace read fd=%d path=%s off=%lld cnt=0x%zx ret=%zd\n",
                    fd, dp ? dp : "?", (long long)read_pos, cnt, rr);
                if (rr > 0) {
                    const uint8_t *b = (const uint8_t *)tmp;
                    kprintf("dl-trace read data %02x%02x%02x%02x%02x%02x%02x%02x\n",
                        b[0], rr > 1 ? b[1] : 0, rr > 2 ? b[2] : 0, rr > 3 ? b[3] : 0,
                        rr > 4 ? b[4] : 0, rr > 5 ? b[5] : 0, rr > 6 ? b[6] : 0, rr > 7 ? b[7] : 0);
                }
            }
            kfree(tmp);
            return (rr >= 0) ? (uint64_t)rr : ret_read_err(rr);
        }
        case SYS_sendfile: {
            /* ssize_t sendfile(out_fd, in_fd, off_t *offset, size_t count) */
            int out_fd = (int)a1;
            int in_fd = (int)a2;
            off_t *offp = (off_t*)(uintptr_t)a3;
            size_t count = (size_t)a4;
            if (out_fd < 0 || out_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            if (in_fd < 0 || in_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            struct fs_file *fout = cur->fds[out_fd];
            struct fs_file *fin = cur->fds[in_fd];
            if (!fout || !fin) {
                return ret_err(EBADF);
            }
            /* Keep sendfile conservative: tty output is handled better via read/write fallback. */
            if (devfs_is_tty_file(fout)) {
                return ret_err(ENOSYS);
            }
            size_t total = 0;
            size_t tocopy = count;
            size_t bufcap = tocopy < 4096 ? tocopy : 4096;
            if (bufcap == 0) return 0;
            uint8_t *tmp = (uint8_t*)kmalloc(bufcap);
            if (!tmp) {
                return ret_err(ENOMEM);
            }
            off_t use_pos = -1;
            if (offp) {
                if (copy_from_user_raw(&use_pos, offp, sizeof(use_pos)) != 0) {
                    kfree(tmp);
                    return ret_err(EFAULT);
                }
            }
            int out_is_sock = (fout->type == SYSCALL_FTYPE_SOCKET && fout->driver_private);
            ksock_net_t *outs = out_is_sock ? (ksock_net_t *)fout->driver_private : NULL;
            while (tocopy > 0) {
                size_t chunk = tocopy < bufcap ? tocopy : bufcap;
                ssize_t rr;
                if (use_pos >= 0) {
                    rr = fs_read(fin, tmp, chunk, (size_t)use_pos);
                } else {
                    rr = fs_read(fin, tmp, chunk, fin->pos);
                }
                if (rr < 0) {
                    kfree(tmp);
                    return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                }
                if (rr == 0) break;
                if (rr > (ssize_t)chunk) {
                    kfree(tmp);
                    return (total > 0) ? (uint64_t)total : ret_err(EIO);
                }
                ssize_t wr;
                if (outs) {
                    /* nginx body: sendfile(socket, file). fs_write() cannot TX TCP. */
                    wr = net_sock_write_kbuf(outs, tmp, (size_t)rr);
                } else {
                    wr = fs_write(fout, tmp, (size_t)rr, fout->pos);
                }
                if (wr <= 0) {
                    kfree(tmp);
                    if (total > 0) return (uint64_t)total;
                    if (wr < 0) return ret_err((int)(-wr));
                    return ret_err(EINVAL);
                }
                if (use_pos >= 0) use_pos += (off_t)rr; else fin->pos += (size_t)rr;
                if (!outs) fout->pos += (size_t)wr;
                total += (size_t)wr;
                tocopy -= (size_t)rr;
                if ((size_t)wr < (size_t)rr) break;
                if ((size_t)rr < chunk) break;
            }
            kfree(tmp);
            if (offp) {
                if (copy_to_user_safe(offp, &use_pos, sizeof(use_pos)) != 0) return ret_err(EFAULT);
            }
            return (uint64_t)total;
        }
        case 271: /* ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask, size_t sigsetsize) */
        case SYS_poll: {
            /* int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) */
            const void *ufds = (const void*)(uintptr_t)a1;
            int nfds = (int)a2;
            int timeout;
            /* Pin the syscall task across sleep/yield. Re-resolving via
             * thread_get_current_user() can point at another process's fd
             * table and spuriously return POLLNVAL (OpenSSH: invalid rfd). */
            thread_t *poll_thr = cur;
            int is_udhcpc_proc = (poll_thr && poll_thr->name[0] && strstr(poll_thr->name, "udhcpc")) ? 1 : 0;
            if (num == 271) {
                /* Minimal ppoll: ignore sigmask/sigsetsize, translate timespec->ms for poll(). */
                const void *tmo_u = (const void*)(uintptr_t)a3;
                timeout = -1; /* NULL timeout => infinite */
                if (tmo_u) {
                    struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                    if (copy_from_user_raw(&ts, tmo_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                    if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                    uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                    if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                    if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                    timeout = (int)ms;
                }
                /* Do NOT cap infinite poll for wget/git — that truncated HTTPS bodies. */
            } else {
                timeout = (int)a3; /* milliseconds, -1 means infinite */
            }
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);
            volatile int elapsed = 0;
            uint64_t poll_t_start = 0;
            int poll_first_entry = 1;
            if (nfds == 0) {
                /* just wait for timeout */
                if (timeout <= 0) return 0;
                if (timeout < 0) {
                    /* block indefinitely but yield */
                    for (;;) { thread_sleep(10); }
                } else {
                    int waited = 0;
                    while (waited < timeout) { thread_sleep(10); waited += 10; }
                    return 0;
                }
            }
            size_t entry_size = 8; /* struct { int fd; short events; short revents; } */
            size_t bytes = (size_t)nfds * entry_size;
            void *kbuf = kmalloc(bytes);
            if (!kbuf) return ret_err(ENOMEM);
            if (copy_from_user_raw(kbuf, ufds, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }

            auto_check:
            {
                /* htop refresh loops live inside one poll/getdents window on SMP
                 * (timer only sets need_resched in kernel). Yield so a woken tty
                 * reader on another VC can run. */
                thread_cond_resched();
                thread_t *pt_sig = poll_thr ? poll_thr : thread_current();
                if (thread_has_interrupt_signal(pt_sig)) {
                    kfree(kbuf);
                    return ret_err(EINTR);
                }
                int ready = 0;
                for (int i = 0; i < nfds; i++) {
                    int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                    short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                    short revents = fd_poll_revents(poll_thr, fd, events);
                    *(short*)((uint8_t*)kbuf + i * entry_size + 6) = revents; /* revents slot at offset 6 */
                    if (revents) ready++;
                }
                if (ready > 0) {
                    if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    kfree(kbuf);
                    return (uint64_t)ready;
                }
            }

            /* Detect if poll set includes network sockets (TCP/UDP) - need e1000_poll */
            int has_net_socket = 0;
            for (int i = 0; i < nfds && !has_net_socket; i++) {
                int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                if (fd < 0 || fd >= THREAD_MAX_FD) continue;
                struct fs_file *f = syscall_fd_get(poll_thr, fd);
                if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                    (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                    s->sock_domain == AF_PACKET_LOCAL)
                    has_net_socket = 1;
            }
            if (timeout == 0) {
                /* Non-blocking poll: must return immediately (POSIX). Sleeping
                 * here made ncurses/htop feel laggy — every idle poll cost 10ms. */
                if (has_net_socket)
                    net_pump_all_tcp(poll_thr);
                kfree(kbuf);
                return 0;
            }
            int step = 2; /* ms — keep net+tty poll snappy (was 10ms) */
            int cur_tid = poll_thr ? (int)poll_thr->tid : -1;
            int tty_waiting[16];
            int n_tty_waiting;
            if (timeout < 0) {
                /* block indefinitely: add self as TTY waiter so we wake on keypress.
                   When has_net_socket: must use bounded sleep so we periodically poll e1000 and re-check. */
                for (;;) {
                    if (has_net_socket)
                        net_pump_all_tcp(poll_thr);
                    else
                        e1000_poll();
                    n_tty_waiting = 0;
                    if (cur_tid >= 0) {
                        for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                            int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                            short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                            if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN_K)) continue;
                            struct fs_file *f = syscall_fd_get(poll_thr, fd);
                            if (!f || !devfs_is_tty_file(f)) continue;
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                        }
                    }
                    if (n_tty_waiting > 0 && !has_net_socket) {
                        /*
                         * A tty waiter is event driven.  Never reuse the
                         * process interval timer as a redraw/poll timeout:
                         * user_itimer_interval_ms is still global, so Xvfb's
                         * 500ms setitimer made every shell tty wake in 500ms
                         * batches. Keyboard input and signals unblock this
                         * waiter directly.
                         */
                        thread_block(cur_tid);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_check;
                    }
                    if (n_tty_waiting > 0 && has_net_socket) {
                        thread_block_with_timeout(cur_tid, (uint32_t)step);
                        thread_yield();
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_check;
                    }
                    thread_sleep(step);
                    goto auto_check;
                }
            } else {
                /* timeout > 0: use TTY waiters + block_with_timeout to wake on keypress
                   (Escape) immediately instead of sleeping full timeout */
                n_tty_waiting = 0;
                if (cur_tid >= 0) {
                    for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                        int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                        short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                        if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN_K)) continue;
                        struct fs_file *f = syscall_fd_get(poll_thr, fd);
                        if (!f || !devfs_is_tty_file(f)) continue;
                        int tidx = devfs_get_tty_index_from_file(f);
                        if (tidx < 0) tidx = devfs_get_active();
                        if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                    }
                }
                if (n_tty_waiting > 0) {
                    int remain = timeout - elapsed;
                    if (remain > 0) {
                        uint64_t t0 = pit_get_time_ms();
                        thread_block_with_timeout(cur_tid, (uint32_t)remain);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        elapsed += (int)(pit_get_time_ms() - t0);
                        if (elapsed >= timeout) {
                            for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                            kfree(kbuf);
                            return 0; /* timeout expired */
                        }
                    }
                    for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    goto auto_check;
                }
                int step_ms = has_net_socket ? 10 : 2;
                if (poll_first_entry) { poll_t_start = pit_get_time_ms(); poll_first_entry = 0; }
                while (elapsed < timeout) {
                    thread_t *pt = poll_thr ? poll_thr : thread_current();
                    if (thread_has_interrupt_signal(pt)) {
                        kfree(kbuf);
                        return ret_err(EINTR);
                    }
                    if (has_net_socket) {
                        net_packet_pump_rx(16);
                        net_pump_all_tcp(poll_thr);
                    } else {
                        e1000_poll();
                    }
                    /*
                     * Must leave RUNNING: a yield-only spin monopolizes the BSP
                     * (timer does not preempt kernel syscalls), so Ctrl+C never
                     * runs and the machine looks hard-frozen after udhcpc discover.
                     */
                    uint32_t sleep_ms = (uint32_t)(timeout - elapsed);
                    if (sleep_ms > (uint32_t)step_ms) sleep_ms = (uint32_t)step_ms;
                    if (sleep_ms < 1u) sleep_ms = 1u;
                    thread_sleep(sleep_ms);
                    elapsed = (int)(pit_get_time_ms() - poll_t_start);
                    goto auto_check;
                }
            }
            /* timeout expired */
            if (is_udhcpc_proc) {
                static int dhcp_timeout_logs = 4;

                if (dhcp_timeout_logs-- > 0) {
                    e1000_stats_t stats;

                    if (e1000_get_stats(&stats) == 0)
                        klogprintf("udhcpc: RX timeout tx=%llu rx=%llu txerr=%llu rxerr=%llu\n",
                                   (unsigned long long)stats.tx_packets,
                                   (unsigned long long)stats.rx_packets,
                                   (unsigned long long)stats.tx_errors,
                                   (unsigned long long)stats.rx_errors);
                    e1000_debug_rx();
                }
            }
            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
            kfree(kbuf);
            return 0;
        }
        case SYS_open: {
            const char *path_u = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            (void)a3;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char *path = kmalloc(256);
            if (!path) return ret_err(ENOMEM);
            /* path is a heap buffer; sizeof(path) would be sizeof(char*) (8) and truncate paths */
            resolve_user_path(cur, path_u, path, 256);
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
                else if (strncmp(path, "/tty", 4) == 0 &&
                         path[4] >= '1' && path[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
                         path[5] == '\0') {
                    char dev_tty_path[16];
                    snprintf(dev_tty_path, sizeof(dev_tty_path), "/dev/tty%c", path[4]);
                    f = fs_open(dev_tty_path);
                }
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) { kfree(path); return ret_err(ENOENT); }
                } else {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    kfree(path);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); kfree(path); return ret_err(EBADF); }
            (void)fs_file_set_user_path(f, path);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                if (strstr(path, "libeinfo")) {
                    dl_watch_start();
                    g_dl_libeinfo_fd = fd;
                }
                pid1_dl_log_fd(cur, "open-ok", fd);
                pid1_dl_verify_file_id(cur, fd);
                kprintf("dl-trace open-chain done fd=%d path=%s\n", fd, path);
            }
            if (is_init_user(cur) && strstr(path, ".so") != NULL) {
                dl_fd_note(fd, path);
                kprintf("boot: open ok fd=%d path=%s\n", fd, path);
                g_dl_post_open_left = 32;
            }
            kfree(path);
            return (uint64_t)(unsigned)fd;
        }
        case SYS_openat: {
            /* openat(dirfd, pathname, flags, mode) - dirfd=AT_FDCWD(-100) uses cwd */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)a4;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[4096];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                pid1_dl_log_stat("openat-req", path);
            {
                static int pid1_openat_trace_left = 80;
                int trace_all_so = (is_init_user(cur) ||
                    (cur && cur->name[0] && strstr(cur->name, "openrc"))) &&
                    strstr(path, ".so") != NULL;
                if (trace_all_so || (pid1_openat_trace_left > 0 && (is_init_user(cur) ||
                    (cur && cur->name[0] && strstr(cur->name, "openrc"))))) {
                    if (!trace_all_so)
                        pid1_openat_trace_left--;
                    devel_printf("pid1 openat path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                }
            }
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                /* chvt: "console"->/console, "tty"->/tty, "tty0"->/tty0, "vc/0"->/dev/vc/0 (handled by devfs) */
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
                else if (strncmp(path, "/tty", 4) == 0 &&
                         path[4] >= '1' && path[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
                         path[5] == '\0') {
                    char dev_tty_path[16];
                    snprintf(dev_tty_path, sizeof(dev_tty_path), "/dev/tty%c", path[4]);
                    f = fs_open(dev_tty_path);
                }
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) {
                        if (is_init_user(cur) || (cur && cur->name[0] && strstr(cur->name, "openrc")))
                            devel_printf("pid1 openat ENOENT create path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                        return ret_err(ENOENT);
                    }
                } else {
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    if (is_init_user(cur) || (cur && cur->name[0] &&
                        (strstr(cur->name, "openrc") || strstr(cur->name, "busybox") ||
                         strstr(cur->name, "/sh") || strstr(cur->name, "linuxrc"))))
                        devel_printf("pid1 openat ENOENT path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                    if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                        kprintf("dl-trace openat ENOENT path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            if (cur->process)
                cur->process->fd_cloexec[fd] =
                    (flags & 02000000) ? 1 : 0;
            (void)fs_file_set_user_path(f, path);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path)) {
                if (strstr(path, "libeinfo"))
                    dl_watch_start();
                if (strstr(path, "libeinfo"))
                    g_dl_libeinfo_fd = fd;
                pid1_dl_log_fd(cur, "openat-ok", fd);
                pid1_dl_verify_file_id(cur, fd);
                kprintf("dl-trace openat-chain done fd=%d path=%s\n", fd, path);
                if (f) {
                    unsigned char hdr[16];
                    memset(hdr, 0, sizeof(hdr));
                    ssize_t hr = fs_read(f, hdr, sizeof(hdr), 0);
                    f->pos = 0;
                    kprintf(" -------------------------------- dl-trace openat hdr fd=%d path=%s got=%zd "
                        "%02x%02x%02x%02x %02x%02x%02x%02x flags=0x%x dirfd=%d\n",
                        fd, path, hr,
                        hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
                        flags, dirfd);
                }
            }
            if (is_init_user(cur) && strstr(path, ".so") != NULL) {
                dl_fd_note(fd, path);
                pid1_dl_verify_file_id(cur, fd);
                kprintf("boot: openat ok fd=%d path=%s flags=0x%x\n", fd, path, flags);
                g_dl_post_open_left = 32;
                if (f) {
                    unsigned char hdr[4];
                    ssize_t hr = fs_read(f, hdr, sizeof(hdr), 0);
                    f->pos = 0;
                    kprintf("boot: openat verify-read fd=%d got=%zd magic=%02x%02x%02x%02x\n",
                        fd, hr, hdr[0], hdr[1], hdr[2], hdr[3]);
                }
            } else if (is_init_user(cur) || (cur && cur->name[0] && strstr(cur->name, "openrc"))) {
                if (strstr(path, ".so") != NULL) {
                    struct stat st;
                    if (vfs_fstat(f, &st) == 0) {
                        unsigned char magic[4] = {0};
                        ssize_t mr = fs_read(f, magic, sizeof(magic), 0);
                        if (mr > 0) f->pos = 0;
                        devel_printf("pid1 openat ok path=%s fd=%d size=%lld mode=0%o magic=%02x%02x%02x%02x\n",
                            path, fd, (long long)st.st_size, (unsigned)(st.st_mode & 0777777),
                            magic[0], magic[1], magic[2], magic[3]);
                    }
                }
            }
            return (uint64_t)(unsigned)fd;
        }
        case 53: { /* socketpair(domain, type, protocol, sv[2]) */
            int domain = (int)a1;
            int type = (int)a2;
            int protocol = (int)a3;
            void *sv_u = (void*)(uintptr_t)a4;
            int type_base = type & ~(O_NONBLOCK_LINUX | SOCK_CLOEXEC_LINUX);
            if (domain != AF_UNIX_LOCAL || !sv_u || (uintptr_t)sv_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EAFNOSUPPORT);
            if (type_base != SOCK_STREAM_LOCAL || protocol != 0)
                return ret_err(EOPNOTSUPP);
            unix_stream_conn_t *conn = (unix_stream_conn_t *)kmalloc(sizeof(*conn));
            ksock_net_t *s0 = (ksock_net_t *)kmalloc(sizeof(*s0));
            ksock_net_t *s1 = (ksock_net_t *)kmalloc(sizeof(*s1));
            struct fs_file *f0 = (struct fs_file *)kmalloc(sizeof(*f0));
            struct fs_file *f1 = (struct fs_file *)kmalloc(sizeof(*f1));
            char *p0 = (char *)kmalloc(24);
            char *p1 = (char *)kmalloc(24);
            if (!conn || !s0 || !s1 || !f0 || !f1 || !p0 || !p1) {
                if (conn) kfree(conn);
                if (s0) kfree(s0);
                if (s1) kfree(s1);
                if (f0) kfree(f0);
                if (f1) kfree(f1);
                if (p0) kfree(p0);
                if (p1) kfree(p1);
                return ret_err(ENOMEM);
            }
            memset(conn, 0, sizeof(*conn));
            conn->refs = 2;
            conn->lock.lock = 0;
            memset(s0, 0, sizeof(*s0));
            memset(s1, 0, sizeof(*s1));
            memset(f0, 0, sizeof(*f0));
            memset(f1, 0, sizeof(*f1));
            snprintf(p0, 24, "socket:[unix]");
            snprintf(p1, 24, "socket:[unix]");
            s0->sock_domain = AF_UNIX_LOCAL;
            s1->sock_domain = AF_UNIX_LOCAL;
            s0->unix_domain_stub = 1;
            s1->unix_domain_stub = 1;
            s0->type_base = SOCK_STREAM_LOCAL;
            s1->type_base = SOCK_STREAM_LOCAL;
            s0->connected = 1;
            s1->connected = 1;
            s0->nonblock = (type & O_NONBLOCK_LINUX) ? 1 : 0;
            s1->nonblock = s0->nonblock;
            s0->unix_conn = conn;
            s1->unix_conn = conn;
            s0->unix_end = 0;
            s1->unix_end = 1;
            s0->kref = 1;
            s1->kref = 1;
            f0->path = p0;
            f1->path = p1;
            f0->type = SYSCALL_FTYPE_SOCKET;
            f1->type = SYSCALL_FTYPE_SOCKET;
            f0->driver_private = s0;
            f1->driver_private = s1;
            f0->refcount = 1;
            f1->refcount = 1;
            int fd0 = thread_fd_alloc(f0);
            int fd1 = thread_fd_alloc(f1);
            if (fd0 < 0 || fd1 < 0) {
                if (fd0 >= 0) thread_fd_close(fd0); else net_fs_file_destroy(f0);
                if (fd1 >= 0) thread_fd_close(fd1); else net_fs_file_destroy(f1);
                return ret_err(EMFILE);
            }
            if (ksock_register(s0) != 0 || ksock_register(s1) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EMFILE);
            }
            int fds[2] = { fd0, fd1 };
            if (copy_to_user_safe(sv_u, fds, sizeof(fds)) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_pipe:
        case SYS_pipe2: {
            /* pipe(int pipefd[2]); pipe2(int pipefd[2], int flags). */
            void *pipefd_u = (void*)(uintptr_t)a1;
            int flags = (num == SYS_pipe2) ? (int)a2 : 0;
            const int O_CLOEXEC = 02000000;
            const int O_NONBLOCK = 00004000;
            if (flags & ~(O_CLOEXEC | O_NONBLOCK)) return ret_err(EINVAL);
            if (!pipefd_u || (uintptr_t)pipefd_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            pipe_t *p = (pipe_t *)kmalloc(sizeof(pipe_t));
            if (!p) { qemu_debug_printf("OOM: pipe pipe_t alloc\n"); return ret_err(ENOMEM); }
            /* The ring uses one sentinel byte to distinguish full from empty. */
            p->buf = (uint8_t *)kmalloc(PIPE_CAPACITY + 1u);
            if (!p->buf) { qemu_debug_printf("OOM: pipe buf alloc %u\n", (unsigned)(PIPE_CAPACITY + 1u)); kfree(p); return ret_err(ENOMEM); }
            p->size = PIPE_CAPACITY + 1u;
            p->id = ++pipe_next_id;
            p->head = p->tail = 0;
            p->refcount = 2;
            p->reader_waiter_tid = p->writer_waiter_tid = -1;
            p->lock.lock = 0;

            struct fs_file *r = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            struct fs_file *w = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            if (!r || !w) { kfree(p->buf); kfree(p); if (r) kfree(r); if (w) kfree(w); return ret_err(ENOMEM); }
            memset(r, 0, sizeof(*r)); memset(w, 0, sizeof(*w));
            r->type = w->type = FS_TYPE_PIPE;
            r->driver_private = w->driver_private = p;
            /* End markers must not collide with VFS driver_data (NULL) or
             * small integers that a buggy matcher could treat as mounts. */
            r->fs_private = PIPE_END_READ;
            w->fs_private = PIPE_END_WRITE;
            r->refcount = w->refcount = 1;

            int fd0 = thread_fd_alloc(r);
            int fd1 = thread_fd_alloc(w);
            if (fd0 < 0 || fd1 < 0) {
                if (fd0 >= 0) thread_fd_close(fd0);
                if (fd1 >= 0) thread_fd_close(fd1);
                if (fd0 < 0) fs_file_free(r);
                if (fd1 < 0) fs_file_free(w);
                return ret_err(EMFILE);
            }
            if (cur->process && (flags & O_CLOEXEC)) {
                cur->process->fd_cloexec[fd0] = 1;
                cur->process->fd_cloexec[fd1] = 1;
            }
            int fds[2] = { fd0, fd1 };
#if DEVEL_DEBUG
            syscall_pipe_watch_active = 1;
            syscall_pipe_watch_owner_tid = (int)(cur->tid ? cur->tid : 1);
            if (pipe_trace_left-- > 0)
                devel_printf("pipe: create id=%llu tid=%d rfd=%d wfd=%d r=%p w=%p\n",
                        (unsigned long long)p->id,
                        (int)(cur->tid ? cur->tid : 1),
                        fd0, fd1, (void *)r, (void *)w);
#endif
            if (copy_to_user_safe(pipefd_u, fds, 8) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_eventfd:
        case SYS_eventfd2: {
            /* int eventfd(unsigned int initval, int flags) / eventfd2 */
            unsigned int initval = (unsigned int)a1;
            int flags = (num == SYS_eventfd2) ? (int)a2 : 0;
            if (flags & ~(EFD_CLOEXEC_K | EFD_NONBLOCK_K | EFD_SEMAPHORE_K))
                return ret_err(EINVAL);
            eventfd_t *e = (eventfd_t *)kmalloc(sizeof(*e));
            struct fs_file *f = (struct fs_file *)kmalloc(sizeof(*f));
            char *path = (char *)kmalloc(16);
            if (!e || !f || !path) {
                if (e) kfree(e);
                if (f) kfree(f);
                if (path) kfree(path);
                return ret_err(ENOMEM);
            }
            memset(e, 0, sizeof(*e));
            memset(f, 0, sizeof(*f));
            e->count = (uint64_t)initval;
            e->nonblock = (flags & EFD_NONBLOCK_K) ? 1 : 0;
            e->semaphore = (flags & EFD_SEMAPHORE_K) ? 1 : 0;
            e->reader_waiter_tid = e->writer_waiter_tid = -1;
            e->lock.lock = 0;
            snprintf(path, 16, "anon_inode:[eventfd]");
            f->path = path;
            f->type = FS_TYPE_EVENTFD;
            f->driver_private = e;
            f->refcount = 1;
            int fd = thread_fd_alloc(f);
            if (fd < 0) {
                kfree(e);
                kfree(path);
                kfree(f);
                return ret_err(EMFILE);
            }
            if (cur->process && (flags & EFD_CLOEXEC_K))
                cur->process->fd_cloexec[fd] = 1;
            return (uint64_t)fd;
        }
        case SYS_close: {
            int fd = (int)a1;
            boot_io_log(cur, "close", fd, 0);
            if (fd == g_dl_libeinfo_fd) {
                devel_printf("dl-watch: close libeinfo fd=%d\n", fd);
                g_dl_libeinfo_fd = -1;
            }
            dl_fd_clear(fd);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_fd(cur, fd))
                pid1_dl_log_fd(cur, "close", fd);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            int r = thread_fd_close(fd);
            return (r == 0) ? 0ULL : ret_err(EBADF);
        }
        case SYS_stat:
        case SYS_lstat: {
            const char *path_u = (const char*)(uintptr_t)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (!path_u || !st_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                pid1_dl_log_stat(num == SYS_lstat ? "lstat-req" : "stat-req", path);
            struct stat st;
            int rc_st = (num == SYS_lstat) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
            if (rc_st != 0) {
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                    kprintf("dl-trace stat ENOENT path=%s\n", path);
                return ret_err(ENOENT);
            }
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                pid1_dl_log_stat(num == SYS_lstat ? "lstat-ok" : "stat-ok", path);
            /* build Linux x86_64 ABI struct stat and copy full layout so vi/busybox S_ISREG works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = (uint64_t)st.st_dev;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = (uint64_t)st.st_rdev;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 4096;
                cs.st_blocks = (st.st_size + 511) / 512;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_fstat: {
            int fd = (int)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            struct stat st;
            if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
            if (pid1_dl_trace_thread(cur) && pid1_dl_trace_fd(cur, fd)) {
                kprintf("dl-trace fstat fd=%d path=%s dev=%llu ino=%llu mode=0%o size=%lld\n",
                    fd, thread_fd_path(cur, fd) ? thread_fd_path(cur, fd) : "?",
                    (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
                    (unsigned)(st.st_mode & 0777777), (long long)st.st_size);
            }
            /* build Linux x86_64 ABI struct stat so vi/busybox S_ISREG(st.st_mode) works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = (uint64_t)st.st_dev;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = (uint64_t)st.st_rdev;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 4096;
                cs.st_blocks = (st.st_size + 511) / 512;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_newfstatat: {
            /* newfstatat(dirfd, pathname, statbuf, flags) - use same Linux ABI layout as stat/fstat */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            void *st_u = (void*)(uintptr_t)a3;
            int flags = (int)a4;
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct stat st;
            enum { AT_FDCWD = -100 };
            /* Linux AT_* flags */
            enum { AT_SYMLINK_NOFOLLOW = 0x100 };
            int st_ready = 0;
            /* AT_EMPTY_PATH (0x1000): stat the file given by dirfd when path is empty (or NULL). */
            char first = '\0';
            int empty_path = 0;
            if ((flags & 0x1000) != 0) {
                if (!path_u) {
                    empty_path = 1;
                } else {
                    if (copy_from_user_raw(&first, path_u, 1) != 0) return ret_err(EFAULT);
                    if (first == '\0') empty_path = 1;
                }
            }
            if (empty_path) {
                if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[dirfd];
                if (!f) return ret_err(EBADF);
                if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
                st_ready = 1;
            } else {
                if (!path_u) return ret_err(EFAULT);
                char *kpath = copy_user_cstr(path_u, 256);
                if (!kpath) return ret_err(EFAULT);
                char path[256];
                int rc_resolve = 0;
                if (kpath[0] == '/') {
                    resolve_kernel_path(cur, kpath, path, sizeof(path));
                } else if (dirfd == AT_FDCWD) {
                    resolve_kernel_path(cur, kpath, path, sizeof(path));
                } else {
                    if (dirfd < 0 || dirfd >= THREAD_MAX_FD) rc_resolve = -EBADF;
                    else {
                        struct fs_file *df = cur->fds[dirfd];
                        if (!df) rc_resolve = -EBADF;
                        else if (df->type != FS_TYPE_DIR) rc_resolve = -ENOTDIR;
                        else {
                            const char *base = df->path ? df->path : "/";
                            if (strcmp(base, "/") == 0) snprintf(path, sizeof(path), "/%s", kpath);
                            else snprintf(path, sizeof(path), "%s/%s", base, kpath);
                            path[sizeof(path) - 1] = '\0';
                            if (path_needs_normalize(path)) normalize_path(path, sizeof(path));
                        }
                    }
                }
                kfree(kpath);
                if (rc_resolve != 0) {
                    if (rc_resolve == -EBADF) return ret_err(EBADF);
                    if (rc_resolve == -ENOTDIR) return ret_err(ENOTDIR);
                    if (rc_resolve == -ENOENT) return ret_err(ENOENT);
                    return ret_err(EFAULT);
                }
                {
                    static int pid1_fstatat_trace_left = 80;
                    if (pid1_fstatat_trace_left > 0 && (is_init_user(cur) ||
                        (cur && cur->name[0] && strstr(cur->name, "openrc")))) {
                        pid1_fstatat_trace_left--;
                        devel_printf("pid1 newfstatat path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                    }
                    if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                        pid1_dl_log_stat("newfstatat-req", path);
                }
                /* Respect AT_SYMLINK_NOFOLLOW: behave like lstat() when requested.
                   ld.so may stat a symlink path after open(); following keeps
                   st_dev/st_ino consistent with fstat(fd) on the resolved object. */
                if (cur && cur->ring == 3 && strstr(path, ".so") != NULL)
                    flags &= ~AT_SYMLINK_NOFOLLOW;
                int sr = (flags & AT_SYMLINK_NOFOLLOW) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
                if (sr != 0) {
                    if (is_init_user(cur) || (cur && cur->name[0] && strstr(cur->name, "openrc")))
                        devel_printf("pid1 newfstatat ENOENT path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                    if (pid1_dl_trace_thread(cur))
                        kprintf("dl-trace newfstatat ENOENT path=%s flags=0x%x dirfd=%d\n", path, flags, dirfd);
                    return ret_err(ENOENT);
                }
                if (pid1_dl_trace_thread(cur) && pid1_dl_trace_path(path))
                    pid1_dl_log_stat("newfstatat-ok", path);
                st_ready = 1;
            }
            if (!st_ready) return ret_err(EFAULT);

            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = (uint64_t)st.st_dev;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = (uint64_t)st.st_rdev;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 4096;
                cs.st_blocks = (st.st_size + 511) / 512;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_statx: {
            /* statx(dirfd, pathname, flags, mask, statxbuf) — Linux x86_64 #332.
             * coreutils ls uses this; ENOSYS became "Function not implemented". */
            int dirfd = (int)a1;
            const char *path_u = (const char *)(uintptr_t)a2;
            int flags = (int)a3;
            unsigned int req_mask = (unsigned int)a4;
            void *buf_u = (void *)(uintptr_t)a5;
            (void)req_mask;
            if (!buf_u) return ret_err(EFAULT);
            enum { AT_FDCWD_X = -100, AT_SYMLINK_NOFOLLOW_X = 0x100, AT_EMPTY_PATH_X = 0x1000 };
            struct stat st;
            int st_ready = 0;
            char first = '\0';
            int empty_path = 0;
            if ((flags & AT_EMPTY_PATH_X) != 0) {
                if (!path_u) empty_path = 1;
                else {
                    if (copy_from_user_raw(&first, path_u, 1) != 0) return ret_err(EFAULT);
                    if (first == '\0') empty_path = 1;
                }
            }
            if (empty_path) {
                if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[dirfd];
                if (!f) return ret_err(EBADF);
                if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
                st_ready = 1;
            } else {
                if (!path_u) return ret_err(EFAULT);
                char *kpath = copy_user_cstr(path_u, 256);
                if (!kpath) return ret_err(EFAULT);
                char path[256];
                int rc_resolve = 0;
                if (kpath[0] == '/' || dirfd == AT_FDCWD_X) {
                    resolve_kernel_path(cur, kpath, path, sizeof(path));
                } else if (dirfd < 0 || dirfd >= THREAD_MAX_FD) {
                    rc_resolve = -EBADF;
                } else {
                    struct fs_file *df = cur->fds[dirfd];
                    if (!df) rc_resolve = -EBADF;
                    else if (df->type != FS_TYPE_DIR) rc_resolve = -ENOTDIR;
                    else {
                        const char *base = df->path ? df->path : "/";
                        if (strcmp(base, "/") == 0) snprintf(path, sizeof(path), "/%s", kpath);
                        else snprintf(path, sizeof(path), "%s/%s", base, kpath);
                        path[sizeof(path) - 1] = '\0';
                        if (path_needs_normalize(path)) normalize_path(path, sizeof(path));
                    }
                }
                kfree(kpath);
                if (rc_resolve == -EBADF) return ret_err(EBADF);
                if (rc_resolve == -ENOTDIR) return ret_err(ENOTDIR);
                if (rc_resolve != 0) return ret_err(EFAULT);
                int sr = (flags & AT_SYMLINK_NOFOLLOW_X) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
                if (sr != 0) return ret_err(ENOENT);
                st_ready = 1;
            }
            if (!st_ready) return ret_err(EFAULT);

            struct statx_ts { int64_t tv_sec; uint32_t tv_nsec; int32_t __reserved; };
            struct statx_k {
                uint32_t stx_mask;
                uint32_t stx_blksize;
                uint64_t stx_attributes;
                uint32_t stx_nlink;
                uint32_t stx_uid;
                uint32_t stx_gid;
                uint16_t stx_mode;
                uint16_t __spare0[1];
                uint64_t stx_ino;
                uint64_t stx_size;
                uint64_t stx_blocks;
                uint64_t stx_attributes_mask;
                struct statx_ts stx_atime;
                struct statx_ts stx_btime;
                struct statx_ts stx_ctime;
                struct statx_ts stx_mtime;
                uint32_t stx_rdev_major;
                uint32_t stx_rdev_minor;
                uint32_t stx_dev_major;
                uint32_t stx_dev_minor;
                uint64_t stx_mnt_id;
                uint64_t __spare2[13];
            } sx;
            memset(&sx, 0, sizeof(sx));
            /* STATX_BASIC_STATS */
            sx.stx_mask = 0x000007ffu;
            sx.stx_blksize = 4096;
            sx.stx_nlink = (uint32_t)st.st_nlink;
            sx.stx_uid = (uint32_t)st.st_uid;
            sx.stx_gid = (uint32_t)st.st_gid;
            sx.stx_mode = (uint16_t)st.st_mode;
            sx.stx_ino = (uint64_t)st.st_ino;
            sx.stx_size = (uint64_t)st.st_size;
            sx.stx_blocks = (uint64_t)((st.st_size + 511) / 512);
            sx.stx_atime.tv_sec = (int64_t)st.st_atime;
            sx.stx_mtime.tv_sec = (int64_t)st.st_mtime;
            sx.stx_ctime.tv_sec = (int64_t)st.st_ctime;
            sx.stx_dev_major = (uint32_t)(((uint64_t)st.st_dev >> 8) & 0xfffu);
            sx.stx_dev_minor = (uint32_t)((uint64_t)st.st_dev & 0xffu);
            sx.stx_rdev_major = (uint32_t)(((uint64_t)st.st_rdev >> 8) & 0xfffu);
            sx.stx_rdev_minor = (uint32_t)((uint64_t)st.st_rdev & 0xffu);
            /* Linux userspace expects a 256-byte statx buffer. */
            uint8_t out[256];
            memset(out, 0, sizeof(out));
            size_t n = sizeof(sx) < sizeof(out) ? sizeof(sx) : sizeof(out);
            memcpy(out, &sx, n);
            if (copy_to_user_safe(buf_u, out, sizeof(out)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_lseek: {
            int fd = (int)a1;
            int64_t off = (int64_t)a2;
            int whence = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            off_t newpos = 0;
            /* 0=SET 1=CUR 2=END; 3=SEEK_DATA 4=SEEK_HOLE (Linux) — glibc/wget use 3/4 on regular files */
            if (whence == 0)
                newpos = (off_t)off;
            else if (whence == 1)
                newpos = (off_t)((int64_t)f->pos + off);
            else if (whence == 2)
                newpos = (off_t)((int64_t)f->size + off);
            else if (whence == 3)
                newpos = (off_t)off;
            else if (whence == 4) { /* SEEK_HOLE: no sparse files; hole begins at EOF */
                if ((off_t)off >= (off_t)f->size)
                    newpos = (off_t)off;
                else
                    newpos = (off_t)f->size;
            } else
                return ret_err(EINVAL);
            if (newpos < 0) return ret_err(EINVAL);
            f->pos = newpos;
            return (uint64_t)(uint64_t)f->pos;
        }
        case SYS_ftruncate: {
            int fd = (int)a1;
            int64_t len64 = (int64_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET) return ret_err(EINVAL);
            if (len64 < 0) return ret_err(EINVAL);
            int r = vfs_ftruncate(f, (off_t)len64);
            if (r == 0) return 0;
            if (r < 0) return ret_err(-r);
            return ret_err(EINVAL);
        }
        case SYS_getdents: /* historic getdents syscall (78) */
        case SYS_getdents64: {
            int fd = (int)a1;
            void *dirp_u = (void*)(uintptr_t)a2;
            size_t count = (size_t)a3;
            int want64 = (num == SYS_getdents64);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!dirp_u) return ret_err(EFAULT);
            if (count < 32) return ret_err(EINVAL);
            if ((uintptr_t)dirp_u + count > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type != FS_TYPE_DIR) return ret_err(EINVAL);

            /* Synthesize linux_dirent64 records into a kernel buffer, then copy to userspace.
               This avoids exposing malformed driver records directly to libc. */
            uint8_t kbuf[1024];
            ssize_t rr = fs_readdir_next(f, kbuf, sizeof(kbuf));
            if (rr < 0) return ret_err(rr == -1 ? EIO : (int)(-rr));
            if (rr == 0) return 0;

            /* Directory stream offset at the start of this batch (Linux d_off cookie). */
            off_t batch_start = f->pos - (off_t)rr;
            if (batch_start < 0) batch_start = 0;

            size_t in_off = 0;
            size_t out_off = 0;
            size_t out_cap = count < 4096 ? count : 4096;
            uint8_t *outbuf = (uint8_t*)kmalloc(out_cap);
            if (!outbuf) return ret_err(ENOMEM);

            int dent_iters = 0;
            while (in_off + 8 <= (size_t)rr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)(kbuf + in_off);
                if (de->rec_len < 8) break;
                size_t rem = (size_t)rr - in_off;
                size_t entry_rec = (size_t)de->rec_len;
                if (entry_rec == 0) break;
                /* Do not parse a partial entry at buffer end — would corrupt next name */
                if (entry_rec > rem) break;
                size_t max_name = (entry_rec > 8) ? entry_rec - 8 : 0;
                size_t name_len_use = (size_t)de->name_len;
                if (name_len_use > max_name) name_len_use = max_name;
                /* Never read past this record — avoids "+" or garbage from next entry. */
                if (name_len_use > 255) name_len_use = 255;

                const char *nm_raw = (const char*)(kbuf + in_off + 8);
                char namebuf_local[256];
                size_t copy_n = (name_len_use < sizeof(namebuf_local)-1) ? name_len_use : (sizeof(namebuf_local)-1);
                if (copy_n > 0) memcpy(namebuf_local, nm_raw, copy_n);
                namebuf_local[copy_n] = '\0';
                for (size_t _i = 0; _i < copy_n; _i++) {
                    unsigned char ch = (unsigned char)namebuf_local[_i];
                    if (ch < 32 || ch > 126) namebuf_local[_i] = '?';
                }
                const char *nm = namebuf_local;
                size_t nlen = copy_n;

                /* Determine inode/type by stat'ing the full path if possible.
                   IMPORTANT: some virtual filesystems don't provide st_ino (0).
                   Userspace tools often treat d_ino==0 as "absent" and skip it,
                   which makes mountpoints like /dev invisible.
                   Skip open+stat when the driver already filled inode — htop's
                   /proc refresh otherwise opens every pid entry twice per tick. */
                uint64_t out_ino = (uint64_t)de->inode;
                uint8_t out_type = (uint8_t)de->file_type;
                if (out_ino == 0 && f->path && nlen > 0) {
                    char fullpath[512];
                    size_t plen = strlen(f->path);
                    if (plen + 1 + nlen + 1 < sizeof(fullpath)) {
                        memcpy(fullpath, f->path, plen);
                        if (plen == 0 || fullpath[plen-1] != '/') fullpath[plen++] = '/';
                        memcpy(fullpath + plen, nm, nlen);
                        fullpath[plen + nlen] = '\0';
                        struct fs_file *ef = fs_open(fullpath);
                        if (ef) {
                            struct stat st;
                            if (vfs_fstat(ef, &st) == 0) {
                                if ((uint64_t)st.st_ino != 0) {
                                    out_ino = (uint64_t)st.st_ino;
                                }
                                if ((st.st_mode & S_IFDIR) == S_IFDIR) out_type = EXT2_FT_DIR;
                                else out_type = EXT2_FT_REG_FILE;
                            }
                            fs_file_free(ef);
                        }
                    }
                }
                /* Yield / honor Ctrl+C during long /proc scans (htop). */
                if ((++dent_iters & 3) == 0) {
                    thread_cond_resched();
                    if (thread_has_interrupt_signal(cur)) {
                        kfree(outbuf);
                        return ret_err(EINTR);
                    }
                }

                uint8_t dtype = 0; /* DT_UNKNOWN */
                if (out_type == EXT2_FT_DIR) dtype = 4;       /* DT_DIR */
                else if (out_type == EXT2_FT_REG_FILE) dtype = 8; /* DT_REG */
                else if (out_type == EXT2_FT_SYMLINK) dtype = 10; /* DT_LNK */

                size_t reclen;
                if (want64) {
                    /* linux_dirent64: ino(8), off(8), reclen(2), type(1), name[] */
                    reclen = 19 + nlen + 1;
                } else {
                    /* linux_dirent: ino(8), off(8), reclen(2), name[], ..., type at last byte */
                    reclen = 18 + nlen + 1 + 1;
                }
                reclen = (reclen + 7) & ~7u;
                if (out_off + reclen > out_cap) break;

                /* Linux d_off: seek cookie for the next directory entry. */
                int64_t dent_off = (int64_t)batch_start + (int64_t)in_off + (int64_t)entry_rec;

                uint8_t *outp = outbuf + out_off;
                *(uint64_t*)(outp + 0) = (uint64_t)out_ino;
                *(int64_t*)(outp + 8) = dent_off;
                *(uint16_t*)(outp + 16) = (uint16_t)reclen;
                if (want64) {
                    outp[18] = dtype;
                    memcpy(outp + 19, nm, nlen);
                    outp[19 + nlen] = '\0';
                    for (size_t z = 19 + nlen + 1; z < reclen; z++) outp[z] = 0;
                } else {
                    memcpy(outp + 18, nm, nlen);
                    outp[18 + nlen] = '\0';
                    for (size_t z = 19 + nlen; z + 1 < reclen; z++) outp[z] = 0;
                    outp[reclen - 1] = dtype;
                }

                out_off += reclen;
                in_off += entry_rec;
            }

            /* Rewind directory position so next getdents64 re-reads the partial entry */
            if (in_off < (size_t)rr)
                f->pos -= (rr - (off_t)in_off);

            /* copy synthesized data to user buffer per-record (safer) */
            size_t wrote = 0;
            size_t scan = 0;
            while (scan + 18 < out_off) {
                uint16_t recl = *(uint16_t*)(outbuf + scan + 16);
                if (recl == 0) break;
                if (scan + recl > out_off) break;
                /* bounds check user destination */
                if ((uintptr_t)dirp_u + wrote + recl > (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    break;
                }
                int rc = copy_to_user_safe((uint8_t*)dirp_u + wrote, outbuf + scan, recl);
                if (rc != 0) {
                    kfree(outbuf);
                    return ret_err(EFAULT);
                }
                wrote += recl;
                scan += recl;
            }
            kfree(outbuf);
            return (uint64_t)wrote;
        }
        case SYS_prctl: {
            /* prctl(option, arg2, arg3, arg4, arg5) — Linux x86_64 #157 */
            int option = (int)a1;
            unsigned long arg2 = (unsigned long)a2;
            (void)a3; (void)a4; (void)a5;
            enum {
                PR_SET_PDEATHSIG = 1,
                PR_GET_PDEATHSIG = 2,
                PR_GET_DUMPABLE = 3,
                PR_SET_DUMPABLE = 4,
                PR_SET_NAME = 15,
                PR_GET_NAME = 16,
                PR_SET_SECCOMP = 22,
                PR_GET_SECCOMP = 21,
                PR_SET_NO_NEW_PRIVS = 38,
                PR_GET_NO_NEW_PRIVS = 39,
                PR_SET_THP_DISABLE = 41,
                PR_GET_THP_DISABLE = 42,
            };
            process_t *p = cur->process;
            if (option == PR_SET_DUMPABLE) {
                /* Linux: 0, 1, or 2 (SUID_DUMP_ROOT). nginx worker spawn. */
                if (arg2 > 2) return ret_err(EINVAL);
                if (p) p->dumpable = (int)arg2;
                return 0;
            }
            if (option == PR_GET_DUMPABLE) {
                return p ? (uint64_t)(unsigned)p->dumpable : 1;
            }
            if (option == PR_SET_NAME) {
                /* arg2 = user pointer to ≤16-byte name (not NUL-padded required). */
                char name[16];
                memset(name, 0, sizeof(name));
                if (!arg2 || !user_range_ok((const void *)arg2, 1))
                    return ret_err(EFAULT);
                size_t n = user_strnlen_bounded((const char *)arg2, sizeof(name));
                if (n > sizeof(name)) n = sizeof(name);
                if (n && copy_from_user_raw(name, (const void *)arg2, n) != 0)
                    return ret_err(EFAULT);
                name[sizeof(name) - 1] = '\0';
                strncpy(cur->name, name, sizeof(cur->name) - 1);
                cur->name[sizeof(cur->name) - 1] = '\0';
                return 0;
            }
            if (option == PR_GET_NAME) {
                if (!arg2 || !user_range_ok((void *)arg2, 16))
                    return ret_err(EFAULT);
                char name[16];
                memset(name, 0, sizeof(name));
                strncpy(name, cur->name, sizeof(name) - 1);
                if (copy_to_user_safe((void *)arg2, name, sizeof(name)) != 0)
                    return ret_err(EFAULT);
                return 0;
            }
            if (option == PR_SET_PDEATHSIG || option == PR_GET_PDEATHSIG ||
                option == PR_SET_SECCOMP || option == PR_GET_SECCOMP ||
                option == PR_SET_NO_NEW_PRIVS || option == PR_GET_NO_NEW_PRIVS ||
                option == PR_SET_THP_DISABLE || option == PR_GET_THP_DISABLE) {
                /* Accepted stubs — enough for nginx/glibc spawn paths. */
                if (option == PR_GET_PDEATHSIG || option == PR_GET_SECCOMP ||
                    option == PR_GET_NO_NEW_PRIVS || option == PR_GET_THP_DISABLE)
                    return 0;
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_iopl: {
            /* Linux: iopl(level) — set I/O privilege level 0..3. Needs CAP_SYS_RAWIO. */
            unsigned long level = (unsigned long)a1;
            if (level > 3)
                return ret_err(EINVAL);
            if (!cur || cur->euid != 0)
                return ret_err(EPERM);
            /* IOPL is recorded; port I/O still goes through kernel PCI helpers.
             * Returning success matches Linux CAP_SYS_RAWIO for privileged tasks. */
            cur->iopl = (uint8_t)level;
            return 0;
        }
        case SYS_ioperm: {
            /* Linux: ioperm(from, num, turn_on) — I/O bitmap for ports < 0x10000. */
            unsigned long from = (unsigned long)a1;
            unsigned long num = (unsigned long)a2;
            int turn_on = (int)a3;
            if (from >= 0x10000UL || num > 0x10000UL || from + num > 0x10000UL)
                return ret_err(EINVAL);
            if (!cur || cur->euid != 0)
                return ret_err(EPERM);
            (void)turn_on;
            /* Full TSS I/O bitmap not wired; privilege check + success is the Linux ABI
             * Xorg expects before probing VGA ports / PCI. */
            return 0;
        }
        case SYS_arch_prctl: {
            /* Linux x86_64 arch_prctl(code, addr) — rdi=code, rsi=addr */
            enum { ARCH_SET_GS = 0x1001, ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ARCH_GET_GS = 0x1004 };
            uint64_t code = a1;
            uint64_t addr = a2;
            /* Defensive: some callers have been seen with code/addr swapped. */
            if (code >= 0x200000ULL && code < (uint64_t)USER_STACK_TOP &&
                (addr == ARCH_SET_FS || addr == ARCH_SET_GS || addr == ARCH_GET_FS || addr == ARCH_GET_GS)) {
                uint64_t t = code;
                code = addr;
                addr = t;
            }
            if (code == ARCH_SET_FS || code == ARCH_SET_GS) {
                if (code == ARCH_SET_GS)
                    code = ARCH_SET_FS;
                if (addr < 0x200000ULL || addr >= (uint64_t)USER_STACK_TOP) {
                    kprintf("arch_prctl SET_FS: bad addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                {
                    /* Touch only the TCB pages — a 2MiB identity ensure used to
                     * re-alias the BusyBox slab after vfork detach. */
                    uint64_t map_lo = addr & ~0xFFFULL;
                    uint64_t map_hi = (addr + 0x4000ULL + 0xFFFULL) & ~0xFFFULL;
                    if (map_hi > (uint64_t)USER_STACK_TOP) map_hi = (uint64_t)USER_STACK_TOP;
                    if (user_map_ensure_present_us_2m(map_lo, map_hi) != 0) {
                        kprintf("arch_prctl SET_FS: map fail addr=0x%llx lo=0x%llx hi=0x%llx\n",
                            (unsigned long long)addr,
                            (unsigned long long)map_lo, (unsigned long long)map_hi);
                        return ret_err(EFAULT);
                    }
                }
                /* Fix for early "stack smashing detected" in glibc:
                   If userspace executed stack-protected frames BEFORE TLS (FS base) was set,
                   then changing FS base later makes the epilogue compare against a different
                   guard at fs:0x28 -> abort().
                   Keep the guard stable by copying old fs:0x28 into new TLS fs:0x28. */
                uint64_t old_fs = msr_read_u64(MSR_FS_BASE);
                uint64_t old_guard = 0;
                if (old_fs >= 0x200000ULL && old_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    (void)copy_from_user_raw(&old_guard, (const void *)(uintptr_t)(old_fs + 0x28), sizeof(old_guard));
                } else {
                    old_guard = 0x8b13f00d2a11c000ULL;
                }

                cur->user_fs_base = addr;
                set_user_fs_base(addr);

                /* glibc static TLS (variant II) lives BELOW the TCB: __libc_setup_tls
                 * memcpy's .tdata then calls arch_prctl(SET_FS). Zeroing [fs-0x1000,fs)
                 * wiped locale pointers at fs:-0x80 and crashed in __ctype_init
                 * (mov (%rax),%rax with rax=NULL). Do not touch memory below FS.
                 * TCB fields at 0/8/0x10 are already written by userspace before the
                 * syscall; only ensure the TCB page is present and keep the canary. */
                {
                    uintptr_t fs = (uintptr_t)addr;
                    uint64_t mlo = (uint64_t)(fs & ~0xFFFu);
                    uint64_t mhi = ((uint64_t)fs + 0x1000u + 0xFFFu) & ~0xFFFu;
                    if (mhi > (uint64_t)USER_STACK_TOP) mhi = (uint64_t)USER_STACK_TOP;
                    (void)user_map_ensure_present_us_2m(mlo, mhi);
                    /* If userspace has not yet installed a self pointer (early ld.so),
                     * seed a minimal TCB header. Never overwrite a non-zero self.
                     * Publish via leaf PA — direct VA stores under kernel CR3 hit
                     * identity phys after vfork detach. */
                    uint64_t self0 = 0;
                    (void)copy_from_user_raw(&self0, (const void *)(uintptr_t)fs, sizeof(self0));
                    if (self0 == 0) {
                        uint64_t self = (uint64_t)fs;
                        (void)copy_to_user_safe((void *)(uintptr_t)(fs + 0x00u), &self, sizeof(self));
                        (void)copy_to_user_safe((void *)(uintptr_t)(fs + 0x10u), &self, sizeof(self));
                    }
                }

                if (addr + 0x30 <= (uint64_t)USER_STACK_TOP) {
                    uint64_t cur_guard = 0;
                    (void)copy_from_user_raw(&cur_guard,
                        (const void *)(uintptr_t)(addr + 0x28), sizeof(cur_guard));
                    if (cur_guard == 0)
                        (void)copy_to_user_safe((void *)(uintptr_t)(addr + 0x28),
                            &old_guard, sizeof(old_guard));
                }
                init_clear_rtld_errno(cur);
                /* Log PID1 and early sysinit children (mount) — TLS/brk bugs. */
                if (is_init_user(cur) ||
                    (cur->name[0] && (strstr(cur->name, "mount") ||
                                      strstr(cur->name, "busybox") ||
                                      strstr(cur->name, "linuxrc"))))
                    kprintf("arch_prctl SET_FS: tid=%llu fs=0x%llx guard=0x%llx tmpl=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (unsigned long long)addr, (unsigned long long)old_guard,
                        cur->mm_ptemplate ? 1 : 0);
                return 0;
            } else if (code == ARCH_GET_FS) {
                if (addr < 0x200000ULL || addr >= (uint64_t)MMIO_IDENTITY_LIMIT) {
                    kprintf("arch_prctl GET_FS: bad addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                if (copy_to_user_safe((void *)(uintptr_t)addr, &cur->user_fs_base, sizeof(cur->user_fs_base)) != 0) {
                    kprintf("arch_prctl GET_FS: copy fail addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                return 0;
            } else if (code == ARCH_GET_GS) {
                kprintf("arch_prctl GET_GS: ENOSYS\n");
                return ret_err(ENOSYS);
            }
            kprintf("arch_prctl: EINVAL code=0x%llx addr=0x%llx\n",
                (unsigned long long)code, (unsigned long long)addr);
            return ret_err(EINVAL);
        }
        case SYS_mount: {
            /* mount(source, target, fstype, flags, data) */
            const char *src_u = (const char*)(uintptr_t)a1;
            const char *tgt_u = (const char*)(uintptr_t)a2;
            const char *type_u = (const char*)(uintptr_t)a3;
            uint64_t mnt_flags = a4;
            (void)a5;
            enum { MS_REMOUNT_LOCAL = 32u };
            if (!tgt_u) return ret_err(EINVAL);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) return ret_err(EFAULT);
            char target[256];
            resolve_kernel_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') return ret_err(EINVAL);

            /* BusyBox inittab: mount -o remount,rw / — fstype may be empty. */
            if (mnt_flags & MS_REMOUNT_LOCAL) {
                kprintf("mount: remount flags=0x%llx target=%s (no-op ok)\n",
                    (unsigned long long)mnt_flags, target);
                return 0;
            }

            if (!type_u) return ret_err(EINVAL);
            char *k_type = copy_user_cstr(type_u, 64);
            if (!k_type) return ret_err(EFAULT);
            if (k_type[0] == '\0') {
                kfree(k_type);
                return ret_err(EINVAL);
            }

            int rc = -1;
            int errno_out = EINVAL;
            if (strcmp(k_type, "proc") == 0 || strcmp(k_type, "procfs") == 0) {
                struct fs_driver *md = fs_get_mount_driver(target);
                if (md && md->ops && md->ops->name &&
                    (strcmp(md->ops->name, "proc") == 0 || strcmp(md->ops->name, "procfs") == 0)) {
                    rc = 0;
                } else {
                    (void)procfs_register();
                    ramfs_mkdir(target);
                    rc = procfs_mount(target);
                    if (rc != 0) errno_out = EBUSY;
                }
            } else if (strcmp(k_type, "sysfs") == 0) {
                /* Already mounted (boot pre-mount or prior SYS_mount): treat as ok. */
                struct fs_driver *md = fs_get_mount_driver(target);
                if (md && md->ops && md->ops->name &&
                    strcmp(md->ops->name, "sysfs") == 0) {
                    rc = 0;
                } else if (sysfs_register() == 0) {
                    ramfs_mkdir(target);
                    rc = sysfs_mount(target);
                    if (rc == 0)
                        kernel_sysfs_populate_default();
                    else
                        errno_out = EBUSY;
                } else {
                    errno_out = EBUSY;
                }
            } else if (strcmp(k_type, "devfs") == 0 || strcmp(k_type, "devtmpfs") == 0 || strcmp(k_type, "tmpfs") == 0) {
                /* tmpfs as mount type for /dev: treat same as devtmpfs (init inittab fallback) */
                ramfs_mkdir(target);
                rc = devfs_mount(target);
                if (rc != 0) errno_out = EBUSY;
            } else if (strcmp(k_type, "fat32") == 0 || strcmp(k_type, "vfat") == 0 || strcmp(k_type, "msdos") == 0 || strcmp(k_type, "auto") == 0) {
                if (!src_u) { kfree(k_type); return ret_err(EINVAL); }
                char *k_src_raw = copy_user_cstr(src_u, 256);
                if (!k_src_raw) { kfree(k_type); return ret_err(EFAULT); }
                char source[256];
                resolve_kernel_path(cur, k_src_raw, source, sizeof(source));
                kfree(k_src_raw);
                if (source[0] == '\0') { kfree(k_type); return ret_err(EINVAL); }

                int dev_id = devfs_get_device_id(source);
                if (dev_id < 0) { kfree(k_type); return ret_err(ENOENT); }

                /* Ensure FAT32 state is initialized for this device. */
                if (fat32_probe_and_mount(dev_id) != 0) { kfree(k_type); return ret_err(EINVAL); }
                struct fs_driver *drv = fat32_get_driver();
                if (!drv) { kfree(k_type); return ret_err(EINVAL); }

                ramfs_mkdir(target);
                rc = fs_mount(target, drv);
                if (rc != 0) errno_out = EBUSY;
            } else {
                rc = -1;
                errno_out = EINVAL;
            }

            kfree(k_type);
            return (rc == 0) ? 0 : ret_err(errno_out);
        }
        case SYS_umount2: {
            /* umount2(target, flags) */
            const char *tgt_u = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            /* Linux: MNT_FORCE=1, MNT_DETACH=2, MNT_EXPIRE=4, UMOUNT_NOFOLLOW=8.
             * Accept and ignore these — we have no busy mounts to force. */
            enum {
                MNT_FORCE_K = 1,
                MNT_DETACH_K = 2,
                MNT_EXPIRE_K = 4,
                UMOUNT_NOFOLLOW_K = 8
            };
            if (flags & ~(MNT_FORCE_K | MNT_DETACH_K | MNT_EXPIRE_K | UMOUNT_NOFOLLOW_K))
                return ret_err(EINVAL);
            if (!tgt_u) return ret_err(EINVAL);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) return ret_err(EFAULT);
            char target[256];
            resolve_kernel_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') return ret_err(EINVAL);
            /* normalize: strip trailing slashes except root */
            size_t n = strlen(target);
            while (n > 1 && target[n - 1] == '/') target[--n] = '\0';

            struct fs_driver *drv = fs_get_mount_driver(target);
            int rc = fs_unmount(target);
            if (rc != 0) return ret_err(EINVAL);

            /* driver-specific cleanup */
            if (drv && drv->ops && drv->ops->name) {
                if (strcmp(drv->ops->name, "fat32") == 0) {
                    fat32_unmount_cleanup();
                }
            }
            return 0;
        }
        case SYS_brk:
            return user_syscall_brk(a1);
        case SYS_shmget: {
            int key = (int)a1;
            size_t size = (size_t)a2;
            int shmflg = (int)a3;
            enum { IPC_PRIVATE_LOCAL = 0, IPC_CREAT_LOCAL = 01000, IPC_EXCL_LOCAL = 02000 };
            if (size == 0) return ret_err(EINVAL);
            size = (size_t)user_mm_align_up((uintptr_t)size, 4096);
            if (size < 4096) size = 4096;

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uid_t uid = tcur ? tcur->euid : 0;
            gid_t gid = tcur ? tcur->egid : 0;
            uint32_t pid = (uint32_t)((tcur && tcur->tid) ? tcur->tid : 1);

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            if (key != IPC_PRIVATE_LOCAL) {
                sysv_shm_seg_t *seg = sysv_shm_find_by_key_nolock(key);
                if (seg) {
                    if ((shmflg & IPC_CREAT_LOCAL) && (shmflg & IPC_EXCL_LOCAL)) {
                        release_irqrestore(&g_sysv_shm_lock, fl);
                        return ret_err(EEXIST);
                    }
                    if (size > seg->size) {
                        release_irqrestore(&g_sysv_shm_lock, fl);
                        return ret_err(EINVAL);
                    }
                    int id = seg->shmid;
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return (uint64_t)id;
                }
                if (!(shmflg & IPC_CREAT_LOCAL)) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(ENOENT);
                }
            }

            int slot = -1;
            for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
                if (!g_sysv_shm[i].used) { slot = i; break; }
            }
            if (slot < 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            uintptr_t base = sysv_shm_alloc_va_nolock(size);
            if (base == 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOMEM);
            }

            sysv_shm_seg_t *seg = &g_sysv_shm[slot];
            memset(seg, 0, sizeof(*seg));
            seg->used = 1;
            seg->shmid = g_sysv_shm_next_id++;
            if (g_sysv_shm_next_id < 1) g_sysv_shm_next_id = 1;
            seg->key = key;
            seg->size = size;
            seg->base = base;
            seg->mode = (uint32_t)(shmflg & 0777);
            seg->uid = uid;
            seg->gid = gid;
            seg->cuid = uid;
            seg->cgid = gid;
            seg->cpid = pid;
            seg->lpid = 0;
            seg->atime = 0;
            seg->dtime = 0;
            seg->ctime = sysv_shm_now_secs();
            seg->nattch = 0;
            seg->removed = 0;
            int shmid = seg->shmid;
            release_irqrestore(&g_sysv_shm_lock, fl);

            if (mark_user_identity_range_2m_sys((uint64_t)base, (uint64_t)(base + size)) != 0) {
                acquire_irqsave(&g_sysv_shm_lock, &fl);
                seg->used = 0;
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EFAULT);
            }
            memset((void *)base, 0, size);
            return (uint64_t)shmid;
        }
        case SYS_shmat: {
            int shmid = (int)a1;
            uintptr_t req_addr = (uintptr_t)a2;
            int shmflg = (int)a3;
            enum { SHM_RDONLY_LOCAL = 010000, SHM_RND_LOCAL = 020000 };
            (void)req_addr;
            (void)shmflg;

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);
            uid_t uid = tcur ? tcur->euid : 0;

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            if (!seg || seg->removed) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            if (req_addr != 0) {
                uintptr_t want = req_addr;
                if (shmflg & SHM_RND_LOCAL) want &= ~0xFFFu;
                if (want != seg->base) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EINVAL);
                }
            }
            if ((shmflg & SHM_RDONLY_LOCAL) == 0) {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid && (seg->mode & 0222u) == 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EACCES);
                }
            } else {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid && (seg->mode & 0444u) == 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EACCES);
                }
            }
            if (sysv_shm_register_attach_nolock(shmid, tid, seg->base, (shmflg & SHM_RDONLY_LOCAL) ? 1 : 0) != 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            seg->nattch++;
            seg->lpid = (uint32_t)tid;
            seg->atime = sysv_shm_now_secs();
            uintptr_t addr = seg->base;
            size_t seg_size = seg->size;
            release_irqrestore(&g_sysv_shm_lock, fl);
            if (user_vma_add(tid, addr, seg_size, (shmflg & SHM_RDONLY_LOCAL) ? 1 : 3, USER_VMA_KIND_SHM) != 0) {
                acquire_irqsave(&g_sysv_shm_lock, &fl);
                int dshmid = -1;
                (void)sysv_shm_detach_one_by_tid_addr_nolock(tid, addr, &dshmid);
                sysv_shm_seg_t *dseg = sysv_shm_find_by_id_nolock(shmid);
                if (dseg) {
                    if (dseg->nattch > 0) dseg->nattch--;
                    dseg->dtime = sysv_shm_now_secs();
                    dseg->lpid = (uint32_t)tid;
                    sysv_shm_cleanup_removed_nolock(dseg);
                }
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            return (uint64_t)addr;
        }
        case SYS_shmdt: {
            uintptr_t addr = (uintptr_t)a1;
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            int shmid = -1;
            if (sysv_shm_detach_one_by_tid_addr_nolock(tid, addr, &shmid) != 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            size_t seg_size = seg ? seg->size : 0;
            if (seg) {
                if (seg->nattch > 0) seg->nattch--;
                seg->dtime = sysv_shm_now_secs();
                seg->lpid = (uint32_t)tid;
                sysv_shm_cleanup_removed_nolock(seg);
            }
            release_irqrestore(&g_sysv_shm_lock, fl);
            if (seg_size > 0)
                user_vma_unmap_range(tid, addr, seg_size);
            return 0;
        }
        case SYS_shmctl: {
            int shmid = (int)a1;
            int cmd = (int)a2;
            void *buf_u = (void *)(uintptr_t)a3;
            enum { IPC_RMID_LOCAL = 0, IPC_SET_LOCAL = 1, IPC_STAT_LOCAL = 2 };

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);
            uid_t uid = tcur ? tcur->euid : 0;

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            if (!seg) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            if (cmd == IPC_RMID_LOCAL) {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EPERM);
                }
                seg->removed = 1;
                seg->key = 0;
                seg->lpid = (uint32_t)tid;
                seg->dtime = sysv_shm_now_secs();
                sysv_shm_cleanup_removed_nolock(seg);
                release_irqrestore(&g_sysv_shm_lock, fl);
                return 0;
            }
            if (cmd == IPC_SET_LOCAL) {
                if (!buf_u || !user_range_ok(buf_u, sizeof(struct sysv_shmid_ds_compat))) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                if (uid != 0 && uid != seg->uid && uid != seg->cuid) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EPERM);
                }
                struct sysv_shmid_ds_compat ds;
                if (copy_from_user_raw(&ds, buf_u, sizeof(ds)) != 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                seg->mode = (seg->mode & ~0777u) | (uint32_t)(ds.shm_perm.mode & 0777u);
                seg->uid = (uid_t)ds.shm_perm.uid;
                seg->gid = (gid_t)ds.shm_perm.gid;
                seg->ctime = sysv_shm_now_secs();
                release_irqrestore(&g_sysv_shm_lock, fl);
                return 0;
            }
            if (cmd == IPC_STAT_LOCAL) {
                if (!buf_u || !user_range_ok(buf_u, sizeof(struct sysv_shmid_ds_compat))) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                struct sysv_shmid_ds_compat ds;
                memset(&ds, 0, sizeof(ds));
                ds.shm_perm.key = (uint32_t)seg->key;
                ds.shm_perm.uid = (uint32_t)seg->uid;
                ds.shm_perm.gid = (uint32_t)seg->gid;
                ds.shm_perm.cuid = (uint32_t)seg->cuid;
                ds.shm_perm.cgid = (uint32_t)seg->cgid;
                ds.shm_perm.mode = (uint16_t)(seg->mode & 0777u);
                ds.shm_segsz = (uint64_t)seg->size;
                ds.shm_atime = (int64_t)seg->atime;
                ds.shm_dtime = (int64_t)seg->dtime;
                ds.shm_ctime = (int64_t)seg->ctime;
                ds.shm_cpid = (int32_t)seg->cpid;
                ds.shm_lpid = (int32_t)seg->lpid;
                ds.shm_nattch = (uint64_t)seg->nattch;
                release_irqrestore(&g_sysv_shm_lock, fl);
                if (copy_to_user_safe(buf_u, &ds, sizeof(ds)) != 0) return ret_err(EFAULT);
                return 0;
            }
            release_irqrestore(&g_sysv_shm_lock, fl);
            return ret_err(EINVAL);
        }
        case SYS_mmap: {
            if (g_dl_libeinfo_fd >= 0 && (int)(int64_t)a5 == g_dl_libeinfo_fd) {
                devel_printf("dl-watch: mmap libeinfo fd=%d addr=0x%llx len=0x%llx prot=0x%x flags=0x%x off=0x%llx\n",
                    g_dl_libeinfo_fd,
                    (unsigned long long)a1, (unsigned long long)a2, (int)a3, (int)a4,
                    (unsigned long long)a6);
            }
            if (is_init_user(cur) && (int64_t)a5 >= 0 && (int)(int64_t)a5 < 64) {
                boot_io_log(cur, "mmap", (int)(int64_t)a5, (uint64_t)a2);
            }
            uint64_t mr = user_syscall_mmap(cur, a1, a2, a3, a4, a5, a6);
            if ((int64_t)mr < 0 && pid1_dl_trace_thread(cur)) {
                kprintf("dl-race mmap syscall errno=%d addr=0x%llx len=0x%llx prot=0x%x "
                    "flags=0x%x fd=%lld off=0x%llx\n",
                    (int)(-(int64_t)mr),
                    (unsigned long long)a1, (unsigned long long)a2, (int)a3, (int)a4,
                    (long long)(int64_t)a5, (unsigned long long)a6);
            }
            return mr;
        }
        case SYS_munmap:
            return user_syscall_munmap(a1, a2);
        case SYS_mincore: {
            /*
             * mincore(addr, length, vec) — Linux x86_64 #27.
             * Go runtime addrspace_free() probes candidate arenas one page at a
             * time: ENOMEM ⇒ unmapped (free), anything else ⇒ treated as mapped.
             * Returning ENOSYS made Go believe the whole 64-bit hint space was
             * occupied → mmap conflicts → runtime/cgo OOM in thread_start.
             */
            uint64_t addr = a1;
            size_t length = (size_t)a2;
            void *vec_u = (void *)(uintptr_t)a3;
            const uint64_t pgsz = PAGE_SIZE_4K;
            if (length == 0)
                return 0;
            if ((addr & (pgsz - 1u)) != 0)
                return ret_err(EINVAL);
            if (!vec_u)
                return ret_err(EFAULT);
            uint64_t end = addr + (uint64_t)length;
            if (end < addr)
                return ret_err(ENOMEM);
            size_t npages = (size_t)((length + (size_t)pgsz - 1u) / (size_t)pgsz);
            if (npages == 0 || npages > (16u * 1024u * 1024u))
                return ret_err(EINVAL);
            if (!user_range_ok(vec_u, npages))
                return ret_err(EFAULT);

            /* Linux: ENOMEM if any page in the range lacks a VMA mapping.
             * Go addrspace_free treats only -ENOMEM as "free to claim". */
            for (size_t i = 0; i < npages; i++) {
                uint64_t page = addr + (uint64_t)i * pgsz;
                if (!user_vma_overlaps_thread_range(cur, (uintptr_t)page, (size_t)pgsz))
                    return ret_err(ENOMEM);
            }

            /* All pages covered by VMAs — fill residency vector. */
            uint8_t *kvec = (uint8_t *)kmalloc(npages);
            if (!kvec) {
                /* npages is usually 1 (Go); stack buffer fallback */
                if (npages > 4096)
                    return ret_err(ENOMEM);
                uint8_t small[4096];
                for (size_t i = 0; i < npages; i++) {
                    uint64_t page = addr + (uint64_t)i * pgsz;
                    uint64_t pa = virt_to_phys(page);
                    small[i] = (pa != 0) ? 1u : 0u;
                }
                if (copy_to_user_safe(vec_u, small, npages) != 0)
                    return ret_err(EFAULT);
                return 0;
            }
            for (size_t i = 0; i < npages; i++) {
                uint64_t page = addr + (uint64_t)i * pgsz;
                uint64_t pa = virt_to_phys(page);
                kvec[i] = (pa != 0) ? 1u : 0u;
            }
            int cprc = copy_to_user_safe(vec_u, kvec, npages);
            kfree(kvec);
            if (cprc != 0)
                return ret_err(EFAULT);
            return 0;
        }
        case SYS_madvise: {
            /* madvise(addr, length, advice) - syscall 28; glibc/apm uses MADV_DONTNEED etc.; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case SYS_mprotect: {
            uint64_t mr = user_syscall_mprotect(a1, a2, a3);
            if ((int64_t)mr < 0 && pid1_dl_trace_thread(cur)) {
                kprintf("dl-trace mprotect syscall errno=%d addr=0x%llx len=0x%llx prot=0x%x\n",
                    (int)(-(int64_t)mr),
                    (unsigned long long)a1, (unsigned long long)a2, (int)a3);
            }
            return mr;
        }
        case SYS_exit: {
            (void)a1;
            if (cur && cur->name[0] && strstr(cur->name, "linuxrc"))
                devel_printf("linuxrc-exit-enter: tid=%llu code=%llu parent=%d waiter=%d\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)a1, cur->parent_tid, cur->waiter_tid);
            qemu_debug_printf("sys_exit: pid=%llu name=%s called exit(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            /* store exit status in wait format (status << 8) */
            if (cur) {
                /*
                 * Linux do_exit(): SYS_exit terminates only the calling task.
                 * A non-leader CLONE_THREAD member must not zombify the TGID,
                 * close the process fd table, remove process VMAs, reparent
                 * children, or emit SIGCHLD. Resolver workers use exactly this
                 * path after getaddrinfo().
                 */
                int thread_only = cur->process && cur->process->leader &&
                                  cur->process->leader != cur;
                if (thread_only) {
                    int code = (int)a1;
                    cur->exit_status = (code & 0xFF) << 8;
                    if (user_range_ok(
                            (const void *)(uintptr_t)cur->clear_child_tid, 4)) {
                        uint32_t zero = 0;
                        (void)copy_to_user_safe(
                            (void *)(uintptr_t)cur->clear_child_tid,
                            &zero, sizeof(zero));
                        {
                            extern int futex_syscall(uintptr_t uaddr, int op,
                                int val, const void *timeout,
                                uintptr_t uaddr2, int val3);
                            (void)futex_syscall(
                                (uintptr_t)cur->clear_child_tid,
                                1 | 128, 1, NULL, 0, 0);
                        }
                    }
                    cur->clear_child_tid = 0;
                    sysv_shm_detach_all_for_tid(
                        (uint64_t)(cur->tid ? cur->tid : 1));
                    /*
                     * Drop this task's fd refs. process->fds is shared:
                     * - Inherit (leader still mirrors the slot): drop the
                     *   extra fork_inherit ref only.
                     * - open/socket by this thread into process->fds: close
                     *   and clear the process slot. Leaving bound UDP DNS
                     *   sockets in ksock_registry stole replies from the
                     *   leader / next curl (error 6 after a successful run).
                     */
                    for (int fd = 0; fd < THREAD_MAX_FD; ++fd) {
                        struct fs_file *f = cur->fds[fd];
                        cur->fds[fd] = NULL;
                        if (!f)
                            continue;
                        if (cur->process && cur->process->fds[fd] == f) {
                            thread_t *lead = cur->process->leader;
                            if (lead && lead != cur && lead->fds[fd] == f) {
                                fs_file_free(f);
                                continue;
                            }
                            cur->process->fds[fd] = NULL;
                            cur->process->fd_cloexec[fd] = 0;
                        }
                        fs_file_free(f);
                    }
                    if (cur->mm_ptemplate) {
                        mm_release(cur->mm_ptemplate);
                        cur->mm_ptemplate = NULL;
                    }
                    if (cur->mm && cur->mm != mm_kernel()) {
                        mm_t *shared_mm = cur->mm;
                        cur->mm = NULL;
                        (void)mm_switch_away_from(shared_mm);
                        mm_release(shared_mm);
                    }
                    /* Detached task slots are reclaimed by the scheduler;
                     * pthread_join synchronization is clear_child_tid/futex. */
                    cur->parent_tid = -1;
                    cur->waiter_tid = -1;
                    cur->state = THREAD_TERMINATED;
                    if (thread_get_current_user() == cur)
                        thread_set_current_user(NULL);
                    thread_schedule();
                    for (;;)
                        asm volatile("sti; hlt" ::: "memory");
                }
                int ignore_sigchld = (user_sig_actions[SIGCHLD].handler == SIG_IGN) ||
                    ((user_sig_actions[SIGCHLD].flags & SA_NOCLDWAIT) != 0);
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                process_mark_zombie(cur->process, cur->exit_status);
                if (cur->process) {
                    process_t *init_process = NULL;
                    int init_tid = thread_get_init_user_tid();
                    thread_t *init_thread = init_tid >= 0 ? thread_get(init_tid) : NULL;
                    if (init_thread)
                        init_process = init_thread->process;
                    process_reparent_children(cur->process, init_process);
                }
                sysv_shm_detach_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                thread_close_all_fds(cur);
                /* glibc pthread_join waits on clear_child_tid; write 0 and FUTEX_WAKE so parent wakes */
                if (user_range_ok((const void *)(uintptr_t)cur->clear_child_tid, 4)) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    {
                        extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                        futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0);
                    }
                    cur->clear_child_tid = 0;
                } else if (cur->clear_child_tid != 0) {
                    cur->clear_child_tid = 0;
                }
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                exit_propagate_brk_mmap_to_parent(cur);
                {
                    int dead = (int)(cur->tid ? cur->tid : 1);
                    if (thread_reparent_orphans(dead) > 0) {
                        int init_tid = thread_get_init_user_tid();
                        if (init_tid >= 0) {
                            thread_t *it = thread_get(init_tid);
                            if (it) {
                                thread_set_pending_signal(it, SIGCHLD);
                                thread_unblock(init_tid);
                            }
                        }
                    }
                }
                /* Mark zombie BEFORE waking wait4/vfork waiters: thread_schedule() below
                   may run the parent while this thread is still in SYS_exit. */
                cur->state = THREAD_TERMINATED;
                if (ignore_sigchld) {
                    /* No zombie: allow scheduler to free this slot. */
                    cur->exit_status = 0x80000000;
                }
                if (is_watch_proc(cur)) {
                    qemu_debug_printf("exit: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                if (cur->mm_ptemplate) {
                    mm_release(cur->mm_ptemplate);
                    cur->mm_ptemplate = NULL;
                }
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_t *dead_mm = cur->mm;
                    cur->mm = NULL;
                    (void)mm_switch_away_from(dead_mm);
                    mm_release(dead_mm);
                }
                if (thread_get_current_user() == cur)
                    thread_set_current_user(NULL);
                /* Wake vfork parent only after TERMINATED + mm teardown. Waking at the
                 * start of exit let linuxrc wait4 process_reap while we still ran. */
                process_release_vfork_parent(cur->process, PROCESS_VFORK_EXIT);
                if (cur->parent_tid >= 0 && !ignore_sigchld) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        thread_unblock((int)(pt->tid ? pt->tid : 1));
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
                }
                if (cur->waiter_tid >= 0) {
                    if (is_watch_proc(cur)) {
                        qemu_debug_printf("exit: pid=%llu (%s) waking waiter=%d\n",
                            (unsigned long long)(cur->tid ? cur->tid : 1),
                            cur->name,
                            cur->waiter_tid);
                    }
                    thread_unblock(cur->waiter_tid);
                }
            }
            /* IMPORTANT:
               If this is a scheduled kernel thread (tid!=0), do not drop into ring0 shell.
               Run other READY threads (e.g. parent in wait4) once, then halt this task. */
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_schedule();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_exit_group: {
            (void)a1;
            if (cur && cur->name[0] && strstr(cur->name, "linuxrc"))
                devel_printf("linuxrc-exit-group-enter: tid=%llu code=%llu parent=%d waiter=%d\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)a1, cur->parent_tid, cur->waiter_tid);
            if (cur && pid1_dl_trace_thread(cur))
            qemu_debug_printf("sys_exit_group: pid=%llu name=%s called exit_group(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            if (cur) {
                int ignore_sigchld = (user_sig_actions[SIGCHLD].handler == SIG_IGN) ||
                    ((user_sig_actions[SIGCHLD].flags & SA_NOCLDWAIT) != 0);
                devfs_tty_remove_waiter_from_all_ttys((int)(cur->tid ? cur->tid : 1));
                exit_group_reap_peer_threads(cur);
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                process_mark_zombie(cur->process, cur->exit_status);
                if (cur->process) {
                    process_t *init_process = NULL;
                    int init_tid = thread_get_init_user_tid();
                    thread_t *init_thread = init_tid >= 0 ? thread_get(init_tid) : NULL;
                    if (init_thread)
                        init_process = init_thread->process;
                    process_reparent_children(cur->process, init_process);
                }
                sysv_shm_detach_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                thread_close_all_fds(cur);
                if (user_range_ok((const void *)(uintptr_t)cur->clear_child_tid, 4)) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    { extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                      futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0); }
                    cur->clear_child_tid = 0;
                } else if (cur->clear_child_tid != 0) {
                    cur->clear_child_tid = 0;
                }
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                exit_propagate_brk_mmap_to_parent(cur);
                {
                    int dead = (int)(cur->tid ? cur->tid : 1);
                    if (thread_reparent_orphans(dead) > 0) {
                        int init_tid = thread_get_init_user_tid();
                        if (init_tid >= 0) {
                            thread_t *it = thread_get(init_tid);
                            if (it) {
                                thread_set_pending_signal(it, SIGCHLD);
                                thread_unblock(init_tid);
                            }
                        }
                    }
                }
                cur->state = THREAD_TERMINATED;
                if (ignore_sigchld)
                    cur->exit_status = 0x80000000;
                if (is_watch_proc(cur)) {
                    qemu_debug_printf("exit_group: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                if (cur->mm_ptemplate) {
                    mm_release(cur->mm_ptemplate);
                    cur->mm_ptemplate = NULL;
                }
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_t *dead_mm = cur->mm;
                    cur->mm = NULL;
                    (void)mm_switch_away_from(dead_mm);
                    mm_release(dead_mm);
                }
                if (thread_get_current_user() == cur)
                    thread_set_current_user(NULL);
                /* After full teardown — see SYS_exit comment. */
                process_release_vfork_parent(cur->process, PROCESS_VFORK_EXIT);
                if (cur->parent_tid >= 0 && !ignore_sigchld) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        /* Parent may be blocked outside wait4 path (pipe/poll/read). */
                        thread_unblock((int)(pt->tid ? pt->tid : 1));
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
                }
                if (cur->waiter_tid >= 0) thread_unblock(cur->waiter_tid);
            }
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_yield();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_rt_sigreturn: {
            /* rt_sigreturn: restore from ucontext on user stack. RSP at entry = ucontext. */
            uintptr_t uc_ptr = (uintptr_t)cur->saved_user_rsp;
            if (uc_ptr < 0x200000 || uc_ptr + sizeof(k_ucontext_t) > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            k_ucontext_t uc;
            if (copy_from_user_raw(&uc, (const void *)uc_ptr, sizeof(uc)) != 0)
                return ret_err(EFAULT);
            k_sigcontext_t *sc = &uc.uc_mcontext;
            cur->saved_user_r8  = sc->r8;
            cur->saved_user_r9  = sc->r9;
            cur->saved_user_r10 = sc->r10;
            cur->saved_user_r11 = sc->r11;
            cur->saved_user_r12 = sc->r12;
            cur->saved_user_r13 = sc->r13;
            cur->saved_user_r14 = sc->r14;
            cur->saved_user_r15 = sc->r15;
            cur->saved_user_rdi = sc->rdi;
            cur->saved_user_rsi = sc->rsi;
            cur->saved_user_rbp = sc->rbp;
            cur->saved_user_rbx = sc->rbx;
            cur->saved_user_rdx = sc->rdx;
            cur->saved_user_rcx = sc->rcx;
            cur->saved_user_rip = sc->rip;
            cur->saved_user_rsp = sc->rsp;
            cur->saved_sig_mask = uc.uc_sigmask[0];
            rebuild_syscall_frame(cur);
            syscall_user_rsp_saved = sc->rsp;
            return sc->rax;
        }
        case SYS_resolve: { /* resolve(hostname, out_ip_be) - full resolver: hosts then DNS; hostname user ptr, out_ip_be user ptr to uint32_t */
            const char *host_u = (const char *)(uintptr_t)a1;
            uint32_t *out_u = (uint32_t *)(uintptr_t)a2;
            if (!host_u || !out_u || !user_range_ok(host_u, 1) || !user_range_ok(out_u, 4))
                return ret_err(EFAULT);
            static int resolve_dbg_left = 8;
            char host[256];
            size_t i = 0;
            for (; i < sizeof(host) - 1; i++) {
                char c;
                if (copy_from_user_raw(&c, host_u + i, 1) != 0) return ret_err(EFAULT);
                host[i] = c;
                if (c == '\0') break;
            }
            host[sizeof(host) - 1] = '\0';
            if (i >= sizeof(host) - 1) return ret_err(ENAMETOOLONG);

            /* Ensure net stack is initialized before reading dns/gw fields.
               Otherwise g_net.{dns_be,gw_be} can be 0 and resolver returns EIO. */
            if (net_ensure_ipv4() != 0) return ret_err(ENETDOWN);
            uint32_t dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
            if (!dns_be) return ret_err(ENETDOWN);
            if (resolve_dbg_left-- > 0) {
                klogprintf("resolve: host=%s ip=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u use_dns=%u.%u.%u.%u\n",
                    host,
                    (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                    (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                    (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                    (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF),
                    (unsigned)((g_net.dns_be >> 24) & 0xFF), (unsigned)((g_net.dns_be >> 16) & 0xFF),
                    (unsigned)((g_net.dns_be >> 8) & 0xFF), (unsigned)(g_net.dns_be & 0xFF),
                    (unsigned)((dns_be >> 24) & 0xFF), (unsigned)((dns_be >> 16) & 0xFF),
                    (unsigned)((dns_be >> 8) & 0xFF), (unsigned)(dns_be & 0xFF));
            }
            /* No 10.0.2.3 fallback: bridged/NAT would use wrong DNS */
            uint32_t ip_be;
            if (kernel_resolve_full(host, dns_be, &ip_be) != 0) return ret_err(EIO);
            /* User ABI: same as sockaddr_in.sin_addr / in_addr_t on x86_64 (LE memory = wire order). */
            {
                uint32_t ip_user = be32(ip_be);
                if (copy_to_user_safe(out_u, &ip_user, 4) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case 213: /* epoll_create(size) */
        case 291: { /* epoll_create1(flags) */
            int flags = (num == 291) ? (int)a1 : 0;
            if (flags & ~(EPOLL_CLOEXEC_K)) return ret_err(EINVAL);
            kepoll_t *ep = (kepoll_t *)kmalloc(sizeof(*ep));
            struct fs_file *f = (struct fs_file *)kmalloc(sizeof(*f));
            char *p = (char *)kmalloc(16);
            if (!ep || !f || !p) {
                if (ep) kfree(ep);
                if (f) kfree(f);
                if (p) kfree(p);
                return ret_err(ENOMEM);
            }
            memset(ep, 0, sizeof(*ep));
            memset(f, 0, sizeof(*f));
            ep->flags = flags;
            snprintf(p, 16, "anon_inode:[eventpoll]");
            f->path = p;
            f->type = SYSCALL_FTYPE_EPOLL;
            f->driver_private = ep;
            f->refcount = 1;
            int fd = thread_fd_alloc(f);
            if (fd < 0) {
                kfree(ep);
                kfree(p);
                kfree(f);
                return ret_err(EMFILE);
            }
            if (cur->process && (flags & EPOLL_CLOEXEC_K))
                cur->process->fd_cloexec[fd] = 1;
            return (uint64_t)fd;
        }
        case 214: /* epoll_ctl_old (legacy number; rarely used) */
        case 233: { /* epoll_ctl — Linux x86_64 / Go runtime netpoll */
            int epfd = (int)a1;
            int op = (int)a2;
            int fd = (int)a3;
            const void *event_u = (const void *)(uintptr_t)a4;
            kepoll_t *ep = epoll_from_fd(cur, epfd);
            if (!ep) return ret_err(EBADF);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (fd == epfd) return ret_err(EINVAL);
            struct fs_file *tf = syscall_fd_get(cur, fd);
            if (!tf) return ret_err(EBADF);
            if (op == EPOLL_CTL_DEL_K) {
                int idx = epoll_find_item(ep, fd);
                if (idx < 0) return ret_err(ENOENT);
                ep->items[idx] = ep->items[ep->nitems - 1];
                ep->nitems--;
                return 0;
            }
            epoll_event_k ev;
            memset(&ev, 0, sizeof(ev));
            if (op == EPOLL_CTL_ADD_K || op == EPOLL_CTL_MOD_K) {
                if (!event_u || !user_range_ok(event_u, sizeof(ev))) return ret_err(EFAULT);
                if (copy_from_user_raw(&ev, event_u, sizeof(ev)) != 0) return ret_err(EFAULT);
            } else {
                return ret_err(EINVAL);
            }
            int idx = epoll_find_item(ep, fd);
            if (op == EPOLL_CTL_ADD_K) {
                if (idx >= 0) return ret_err(EEXIST);
                if (ep->nitems >= EPOLL_MAX_ITEMS) return ret_err(EMFILE);
                ep->items[ep->nitems].fd = fd;
                ep->items[ep->nitems].events = ev.events;
                ep->items[ep->nitems].data = ev.data;
                ep->items[ep->nitems].et_delivered = 0;
                ep->nitems++;
                return 0;
            }
            /* MOD */
            if (idx < 0) return ret_err(ENOENT);
            ep->items[idx].events = ev.events;
            ep->items[idx].data = ev.data;
            ep->items[idx].et_delivered = 0; /* re-arm edge trigger */
            return 0;
        }
        case 232: /* epoll_wait */
        case 281: { /* epoll_pwait — sigmask ignored (same as ppoll) */
            int epfd = (int)a1;
            void *events_u = (void *)(uintptr_t)a2;
            int maxevents = (int)a3;
            int timeout = (int)a4;
            kepoll_t *ep = epoll_from_fd(cur, epfd);
            if (!ep) return ret_err(EBADF);
            if (maxevents <= 0 || maxevents > 1024) return ret_err(EINVAL);
            if (!events_u || !user_range_ok(events_u, (size_t)maxevents * sizeof(epoll_event_k)))
                return ret_err(EFAULT);
            thread_t *wait_thr = cur;
            int step = 2;
            int waited = 0;
            epoll_event_k *outbuf = (epoll_event_k *)kmalloc((size_t)maxevents * sizeof(epoll_event_k));
            if (!outbuf) return ret_err(ENOMEM);
            for (;;) {
                thread_cond_resched();
                if (thread_has_interrupt_signal(wait_thr)) {
                    kfree(outbuf);
                    return ret_err(EINTR);
                }
                net_pump_all_tcp(wait_thr);
                int nout = 0;
                for (int i = 0; i < ep->nitems && nout < maxevents; i++) {
                    epoll_item_t *it = &ep->items[i];
                    if (it->fd < 0) continue;
                    if (it->events == 0) continue; /* disabled after ONESHOT */
                    short want = (short)epoll_interest_to_poll(it->events);
                    short rev = fd_poll_revents(wait_thr, it->fd, want);
                    if (!rev) {
                        it->et_delivered = 0; /* edge re-arms when not ready */
                        continue;
                    }
                    uint32_t erev = poll_to_epoll_revents(rev, it->events);
                    if (!erev) {
                        it->et_delivered = 0;
                        continue;
                    }
                    /* EPOLLET: deliver once per ready period until quiesced. */
                    if ((it->events & EPOLLET_K) && it->et_delivered)
                        continue;
                    outbuf[nout].events = erev;
                    outbuf[nout].data = it->data;
                    nout++;
                    if (it->events & EPOLLET_K)
                        it->et_delivered = 1;
                    if (it->events & EPOLLONESHOT_K)
                        it->events = 0;
                }
                if (nout > 0) {
                    if (copy_to_user_safe(events_u, outbuf, (size_t)nout * sizeof(epoll_event_k)) != 0) {
                        kfree(outbuf);
                        return ret_err(EFAULT);
                    }
                    kfree(outbuf);
                    return (uint64_t)nout;
                }
                if (timeout == 0) {
                    kfree(outbuf);
                    return 0;
                }
                if (timeout > 0 && waited >= timeout) {
                    kfree(outbuf);
                    return 0;
                }
                thread_sleep((uint32_t)step);
                waited += step;
                if (timeout > 0 && waited > timeout) waited = timeout;
            }
        }
        default:
            /* Keep unknown syscalls mostly silent; log a few for docker/containerd. */
            (void)a4; (void)a5; (void)a6;
            {
                static int enosys_log_left = 48;
                if (enosys_log_left > 0 && cur && cur->name[0] &&
                    (strstr(cur->name, "docker") || strstr(cur->name, "containerd") ||
                     strstr(cur->name, "runc"))) {
                    enosys_log_left--;
                    kprintf("ENOSYS: nr=%llu tid=%d name=%s a1=0x%llx\n",
                        (unsigned long long)num,
                        (int)(cur->tid ? cur->tid : 1),
                        cur->name,
                        (unsigned long long)a1);
                }
            }
            return ret_err(ENOSYS);
    }
}

uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    thread_t *trace_t = syscall_resolve_thread();
    if (!trace_t)
        trace_t = thread_get_current_user();
    /* If this task forked on its previous syscall, that iretq has completed:
     * publishing now cannot race the old live syscall frame. */
    syscall_publish_deferred_fork_child();
    /* Entry log (budget): catch syscalls that block and never return. */
    if (trace_t && !trace_t->fork_child_user_rip && trace_t->name[0] &&
        strstr(trace_t->name, "linuxrc") && trace_t->vfork_waiting == 0) {
        static int linuxrc_parent_enter_left = 8;
        static int linuxrc_parent_enter_armed;
        if (num == SYS_wait4)
            linuxrc_parent_enter_armed = 1;
        if (linuxrc_parent_enter_armed && linuxrc_parent_enter_left-- > 0 &&
            num != SYS_wait4)
            devel_printf("linuxrc-parent-enter: tid=%llu nr=%llu rip=0x%llx a1=0x%llx\n",
                (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                (unsigned long long)num,
                (unsigned long long)trace_t->saved_user_rip,
                (unsigned long long)a1);
    }
    if (trace_t && trace_t->fork_child_user_rip && trace_t->name[0] &&
        (strstr(trace_t->name, "linuxrc") || strstr(trace_t->name, "openrc"))) {
        /* wait4/kill spam hides exec progress; skip after a few samples. */
        static int linuxrc_child_next_left = 16;
        static int linuxrc_waitkill_left = 4;
        int is_waitkill = (num == SYS_wait4 || num == 62);
        if (is_waitkill) {
            if (linuxrc_waitkill_left-- > 0)
                devel_printf("fork-child-next: tid=%llu nr=%llu rip=0x%llx rsp=0x%llx a1=%lld a2=%lld\n",
                    (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)trace_t->saved_user_rip,
                    (unsigned long long)trace_t->saved_user_rsp,
                    (long long)a1, (long long)a2);
        } else if (linuxrc_child_next_left-- > 0) {
            devel_printf("fork-child-next: tid=%llu nr=%llu rip=0x%llx rsp=0x%llx\n",
                (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                (unsigned long long)num,
                (unsigned long long)trace_t->saved_user_rip,
                (unsigned long long)trace_t->saved_user_rsp);
        }
    }
    if (trace_t && (num == SYS_fork || num == SYS_clone || num == SYS_clone3 || num == SYS_vfork)) {
        if (trace_t->saved_syscall_frame)
            trace_t->fork_child_trap_rip = trace_t->saved_syscall_frame[13];
        else if (trace_t->syscall_frame_kbuf)
            trace_t->fork_child_trap_rip = trace_t->syscall_frame_kbuf[13];
        if (trace_t->name[0] && strstr(trace_t->name, "openrc")) {
            devel_printf("fork-trap-rip: n=%llu trap=0x%llx frame13=0x%llx kbuf13=0x%llx tid=%d\n",
                (unsigned long long)num,
                (unsigned long long)trace_t->fork_child_trap_rip,
                (unsigned long long)(trace_t->saved_syscall_frame ? trace_t->saved_syscall_frame[13] : 0),
                (unsigned long long)(trace_t->syscall_frame_kbuf ? trace_t->syscall_frame_kbuf[13] : 0),
                (int)(trace_t->tid ? trace_t->tid : 1));
        }
    }
    int trace_pid1 = 0;
    int trace_this = 0;
    int trace_shell = 0;
    int trace_net = 0;
    if (trace_pid1) {
        switch ((int)num) {
            case SYS_read:
            case SYS_write:
            case SYS_mmap:
            case SYS_mprotect:
            case 17: /* pread64 */
            case SYS_fstat:
            case SYS_stat:
            case SYS_lstat:
            case SYS_readlink:
            case SYS_readlinkat:
            case SYS_rt_sigaction:
            case SYS_rt_sigprocmask:
            case SYS_rt_sigsuspend:
            case SYS_fork:
            case SYS_execve:
            case SYS_wait4:
            case SYS_ioctl:
            case SYS_setsid:
            case SYS_setpgid:
            case SYS_open:
            case SYS_openat:
            case SYS_newfstatat:
            case SYS_close:
            case SYS_access:
            case 269: /* faccessat */
            case SYS_futex:
            case SYS_readv:
            case SYS_writev:
            case SYS_arch_prctl:
            case SYS_exit:
            case SYS_exit_group:
                trace_this = 1;
                break;
            default:
                break;
        }
    }
    if (!trace_this && trace_t && trace_t->ring == 3) {
        switch ((int)num) {
            case 7:   /* poll */
            case 23:  /* select */
            case 41:  /* socket */
            case 44:  /* sendto */
            case 45:  /* recvfrom */
            case 46:  /* sendmsg */
            case 47:  /* recvmsg */
            case 49:  /* bind */
            case 54:  /* setsockopt */
            case 270: /* pselect6 */
            case 271: /* ppoll */
                if (g_net_trace_budget-- > 0) {
                    trace_this = 1;
                    trace_net = 1;
                }
                break;
            default:
                break;
        }
    }
    if (!trace_this && trace_t && trace_t->ring == 3 && trace_t->name[0] &&
        (strstr(trace_t->name, "busybox") || strstr(trace_t->name, "/sh") ||
         strstr(trace_t->name, "openrc"))) {
        static int shell_syscall_dbg_left = 256;
        /* Separate budget for openrc fork-child after _Fork: parent wait4/sigmask
         * otherwise burns the shared 160 and hides rt_sigaction→exec progress. */
        static int openrc_child_sc_left = 128;
        int is_openrc_child = (strstr(trace_t->name, "openrc") &&
                               trace_t->fork_child_user_rip);
        switch ((int)num) {
            case SYS_read:
            case SYS_write:
            case SYS_writev:
            case SYS_rt_sigaction:
            case SYS_rt_sigprocmask:
            case SYS_rt_sigsuspend:
            case SYS_fork:
            case SYS_clone:
            case SYS_execve:
            case SYS_wait4:
            case SYS_ioctl:
            case SYS_open:
            case SYS_openat:
            case SYS_newfstatat:
            case SYS_exit:
            case SYS_exit_group:
            case SYS_getpid:
            case SYS_gettid:
            case SYS_set_robust_list:
            case SYS_sched_yield:
            case SYS_set_tid_address:
            case SYS_futex:
            case SYS_arch_prctl:
                if (is_openrc_child && openrc_child_sc_left-- > 0) {
                    trace_this = 1;
                    trace_shell = 1;
                } else if (!is_openrc_child && syscall_pipe_watch_active &&
                           shell_syscall_dbg_left-- > 0) {
                    trace_this = 1;
                    trace_shell = 1;
                }
                break;
            default:
                break;
        }
    }
    if (trace_this) {
        devel_printf("%s syscall enter: tid=%llu name=%s n=%llu a1=0x%llx a2=0x%llx a3=0x%llx a4=0x%llx a5=0x%llx a6=0x%llx\n",
            trace_net ? "net" : (trace_shell ? "shell" : "pid1"),
            (unsigned long long)(trace_t && trace_t->tid ? trace_t->tid : 1),
            trace_t ? trace_t->name : "?",
            (unsigned long long)num,
            (unsigned long long)a1,
            (unsigned long long)a2,
            (unsigned long long)a3,
            (unsigned long long)a4,
            (unsigned long long)a5,
            (unsigned long long)a6);
    }
    uint64_t ret = syscall_do_inner(num, a1, a2, a3, a4, a5, a6);
    if (trace_t && trace_t->fork_child_user_rip && trace_t->name[0] &&
        strstr(trace_t->name, "linuxrc")) {
        static int linuxrc_child_done_left = 48;
        if (linuxrc_child_done_left-- > 0)
            devel_printf("fork-child-done: tid=%llu nr=%llu ret=0x%llx\n",
                (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                (unsigned long long)num,
                (unsigned long long)ret);
    }
    /* PID1 after first mount wait4: utmp/open/futex was a silent hang. */
    if (trace_t && !trace_t->fork_child_user_rip && trace_t->name[0] &&
        strstr(trace_t->name, "linuxrc")) {
        static int linuxrc_parent_sc_left = 12;
        static int linuxrc_parent_armed;
        if (num == SYS_wait4)
            linuxrc_parent_armed = 1;
        if (linuxrc_parent_armed && linuxrc_parent_sc_left-- > 0) {
            if (num == SYS_access) {
                char apath[96];
                apath[0] = '\0';
                if (a1 && user_range_ok((const void *)(uintptr_t)a1, 1))
                    resolve_user_path(trace_t, (const char *)(uintptr_t)a1,
                        apath, sizeof(apath));
                devel_printf("linuxrc-parent: tid=%llu nr=%llu ret=0x%llx rip=0x%llx path=%s\n",
                    (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)ret,
                    (unsigned long long)trace_t->saved_user_rip,
                    apath[0] ? apath : "?");
            } else {
                devel_printf("linuxrc-parent: tid=%llu nr=%llu ret=0x%llx rip=0x%llx rsp=0x%llx\n",
                    (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)ret,
                    (unsigned long long)trace_t->saved_user_rip,
                    (unsigned long long)trace_t->saved_user_rsp);
            }
        }
    }
    if (num == SYS_set_robust_list && trace_t && trace_t->name[0] &&
        strstr(trace_t->name, "linuxrc"))
        devel_printf("robust-inner-return: tid=%llu ret=0x%llx\n",
            (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
            (unsigned long long)ret);
    if (!trace_t || trace_t->ring != 3)
        trace_t = syscall_resolve_thread();
    if (trace_this) {
        devel_printf("%s syscall exit: tid=%llu n=%llu ret=0x%llx\n",
            trace_net ? "net" : (trace_shell ? "shell" : "pid1"),
            (unsigned long long)(trace_t && trace_t->tid ? trace_t->tid : 1),
            (unsigned long long)num,
            (unsigned long long)ret);
        if ((int64_t)ret < 0) {
            int err = (int)(-(int64_t)ret);
            kprintf("%s syscall exit err: tid=%llu n=%llu errno=%d\n",
                trace_net ? "net" : (trace_shell ? "shell" : "pid1"),
                (unsigned long long)(trace_t && trace_t->tid ? trace_t->tid : 1),
                (unsigned long long)num,
                err);
        }
    }
    if (pid1_dl_trace_thread(trace_t) && (int64_t)ret < 0) {
        kprintf("dl-trace syscall_err n=%llu errno=%d name=%s a1=0x%llx a2=0x%llx\n",
            (unsigned long long)num, (int)(-(int64_t)ret),
            trace_t && trace_t->name[0] ? trace_t->name : "?",
            (unsigned long long)a1, (unsigned long long)a2);
    }
    if (trace_t && pid1_dl_trace_thread(trace_t)) {
        dl_tail_push(num, a1, a2, (int64_t)ret);
        dl_boot_push(num, a1, a2, (int64_t)ret);
        if (g_dl_post_open_left > 0) {
            g_dl_post_open_left--;
            int err = (int64_t)ret < 0 ? (int)(-(int64_t)ret) : 0;
            kprintf("dl-post %s(%llu) ret=0x%llx err=%d a1=0x%llx left=%d\n",
                dl_tail_scname(num), (unsigned long long)num,
                (unsigned long long)ret, err,
                (unsigned long long)a1, g_dl_post_open_left);
        }
        if (g_dl_compact_left > 0) {
            g_dl_compact_left--;
            int err = (int64_t)ret < 0 ? (int)(-(int64_t)ret) : 0;
            kprintf("dl-compact %s(%llu) ret=0x%llx err=%d a1=0x%llx a2=0x%llx\n",
                dl_tail_scname(num), (unsigned long long)num,
                (unsigned long long)ret, err,
                (unsigned long long)a1, (unsigned long long)a2);
        }
    }
    if (trace_t && trace_t->ring == 3 && trace_t->fork_child_user_rip) {
        if (num == SYS_set_robust_list) {
            devel_printf("fork-child-robust: tid=%llu head=0x%llx len=0x%llx\n",
                (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                (unsigned long long)a1,
                (unsigned long long)a2);
            fork_child_finish_post_robust(trace_t);
            devel_printf("fork-child-robust-done: tid=%llu\n",
                (unsigned long long)(trace_t->tid ? trace_t->tid : 1));
        }
    }
    syscall_deferred_unblocks();
    /*
     * Fork/vfork already woke the child (wake_up_new_task). Schedule before
     * returning to userspace so a BLOCKED vfork parent yields to the child
     * immediately — same point as Linux's preemption after wake_up_new_task.
     */
    (void)syscall_publish_deferred_fork_child();
    if (num == SYS_fork || num == SYS_vfork || num == SYS_clone || num == SYS_clone3)
        thread_schedule();
    else
        thread_cond_resched();
    if (num == SYS_set_robust_list && trace_t && trace_t->name[0] &&
        strstr(trace_t->name, "linuxrc"))
        devel_printf("robust-dispatch-return: tid=%llu\n",
            (unsigned long long)(trace_t->tid ? trace_t->tid : 1));
    {
        uint64_t out = syscall_sanitize_user_ret(ret);
        if (trace_t && trace_t->fork_child_user_rip && trace_t->name[0] &&
            strstr(trace_t->name, "linuxrc") &&
            (num == SYS_getpid || num == SYS_ioctl || num == SYS_execve ||
             num == SYS_write || num == SYS_writev || num == SYS_clock_gettime ||
             num == 202 /* futex */ || num == SYS_socket || num == 42 /* connect */ ||
             num == SYS_openat || num == SYS_open)) {
            static int linuxrc_child_retuser_left = 8;
            if (linuxrc_child_retuser_left-- > 0)
                devel_printf("fork-child-retuser: tid=%llu nr=%llu ret=0x%llx rip=0x%llx pending=0x%llx\n",
                    (unsigned long long)(trace_t->tid ? trace_t->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)out,
                    (unsigned long long)trace_t->saved_user_rip,
                    (unsigned long long)trace_t->pending_signals);
        }
        return out;
    }
}

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    /* Record user rip/rsp for int0x80 path so fork/vfork can find return site. */
    syscall_user_return_rip = regs->rip;
    syscall_user_rsp_saved = regs->rsp;
    {
        thread_t *cur = thread_current();
        if (!cur || cur->ring != 3)
            cur = thread_get_current_user();
        if (cur) {
            cur->syscall_entry_rip = regs->rip;
            cur->fork_locked_syscall_rip = regs->rip;
            cur->saved_user_rip = regs->rip;
            cur->saved_user_rcx = regs->rip;
            cur->saved_user_rsp = regs->rsp;
        }
    }
    if (syscall_user_return_rip == 0) {
        debug_dump_kernel_syscall_stack();
    }
    /* Match Linux x86_64 syscall ABI: args 4–6 are r10, r8, r9 (same as SYSCALL path in syscall.S). */
    asm volatile("sti" ::: "memory");
    regs->rax = syscall_do(regs->rax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
    asm volatile("cli" ::: "memory");
    /* Same as syscall.S: vfork parent sleeps after C returns. */
    regs->rax = syscall_maybe_vfork_wait(regs->rax);
    /* Match wake_up_new_task ordering on the int 0x80 compatibility path. */
    (void)syscall_publish_deferred_fork_child();
    syscall_restore_user_fs_before_iretq();
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

    klogprintf("syscall: int0x80+SYSCALL ok; mmap cap < USER_STACK_TOP=0x%llx\n",
        (unsigned long long)(uint64_t)USER_STACK_TOP);
}


