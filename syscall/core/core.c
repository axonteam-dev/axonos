#include "syscall_internal.h"


__attribute__((noreturn)) void syscall_return_to_shell(void) {
    syscall_exit_to_shell_flag = 0;
    thread_set_current_user(NULL);
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

#ifndef SIGCHLD
#define SIGCHLD 17
#endif

void syscall_user_fatal_exit(int signo) {
    thread_t *cur = thread_get_current_user();
    if (!cur)
        cur = thread_current();
    if (cur && cur->ring == 3) {
        if (cur->attached_tty >= 0)
            devfs_tty_leave_alt_screen(cur->attached_tty);
        devfs_tty_remove_waiter_from_all_ttys((int)(cur->tid ? cur->tid : 1));
        exit_group_reap_peer_threads(cur);
        cur->exit_status = (signo & 0x7f) << 8;
        sysv_shm_detach_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
        user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
        for (int i = 0; i < THREAD_MAX_FD; i++) {
            if (cur->fds[i]) {
                struct fs_file *f = cur->fds[i];
                cur->fds[i] = NULL;
                fs_file_free(f);
            }
        }
        cur->state = THREAD_TERMINATED;
        if (cur->parent_tid >= 0) {
            thread_t *pt = thread_get(cur->parent_tid);
            if (pt) {
                thread_set_pending_signal(pt, SIGCHLD);
                thread_unblock((int)(pt->tid ? pt->tid : 1));
                if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty)
                    devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
            }
        }
        if (cur->waiter_tid >= 0)
            thread_unblock(cur->waiter_tid);
        if (cur->mm && cur->mm != mm_kernel()) {
            mm_release(cur->mm);
            cur->mm = mm_kernel();
        }
    }
    thread_set_current_user(NULL);
    thread_schedule();
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

extern void syscall_entry64(void);
/* helper entry for kernel-created user threads (defined in cpu/thread.c) */
extern void user_thread_entry(void);

__attribute__((noreturn)) void fork_child_return_entry(void) {
    thread_t *self = thread_current();
    if (!self) {
        for (;;) asm volatile("sti; hlt" ::: "memory");
    }
    self->ring = 3;
    thread_set_current_user(self);
    if (self->kernel_stack)
        tss_set_rsp0(self->kernel_stack);
    syscall_bind_kstack_for_thread(self);
    set_user_fs_base(self->user_fs_base);

    asm volatile(
        "movq %[self], %%rax\n\t"
        "pushq $0x23\n\t"
        "pushq %c[rsp_off](%%rax)\n\t"
        "movq %c[r11_off](%%rax), %%r11\n\t"
        "orq $0x200, %%r11\n\t"
        "pushq %%r11\n\t"
        "pushq $0x1B\n\t"
        "pushq %c[rip_off](%%rax)\n\t"
        "movq %c[r15_off](%%rax), %%r15\n\t"
        "movq %c[r14_off](%%rax), %%r14\n\t"
        "movq %c[r13_off](%%rax), %%r13\n\t"
        "movq %c[r12_off](%%rax), %%r12\n\t"
        "movq %c[r10_off](%%rax), %%r10\n\t"
        "movq %c[r9_off](%%rax), %%r9\n\t"
        "movq %c[r8_off](%%rax), %%r8\n\t"
        "movq %c[rdi_off](%%rax), %%rdi\n\t"
        "movq %c[rsi_off](%%rax), %%rsi\n\t"
        "movq %c[rbp_off](%%rax), %%rbp\n\t"
        "movq %c[rbx_off](%%rax), %%rbx\n\t"
        "movq %c[rdx_off](%%rax), %%rdx\n\t"
        "movq %c[rcx_off](%%rax), %%rcx\n\t"
        "xorq %%rax, %%rax\n\t"
        "cld\n\t"
        "iretq\n\t"
        :
        : [self] "r"(self),
          [rsp_off] "i"(offsetof(thread_t, saved_user_rsp)),
          [rip_off] "i"(offsetof(thread_t, saved_user_rip)),
          [r11_off] "i"(offsetof(thread_t, saved_user_r11)),
          [r15_off] "i"(offsetof(thread_t, saved_user_r15)),
          [r14_off] "i"(offsetof(thread_t, saved_user_r14)),
          [r13_off] "i"(offsetof(thread_t, saved_user_r13)),
          [r12_off] "i"(offsetof(thread_t, saved_user_r12)),
          [r10_off] "i"(offsetof(thread_t, saved_user_r10)),
          [r9_off] "i"(offsetof(thread_t, saved_user_r9)),
          [r8_off] "i"(offsetof(thread_t, saved_user_r8)),
          [rdi_off] "i"(offsetof(thread_t, saved_user_rdi)),
          [rsi_off] "i"(offsetof(thread_t, saved_user_rsi)),
          [rbp_off] "i"(offsetof(thread_t, saved_user_rbp)),
          [rbx_off] "i"(offsetof(thread_t, saved_user_rbx)),
          [rdx_off] "i"(offsetof(thread_t, saved_user_rdx)),
          [rcx_off] "i"(offsetof(thread_t, saved_user_rcx))
        : "memory"
    );
    __builtin_unreachable();
}


thread_t *uaccess_thread(void) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    return t;
}

void uaccess_clear(thread_t *t) {
    if (!t) return;
    t->uaccess_begin = 0;
    t->uaccess_end = 0;
    t->uaccess_resume_rip = 0;
    t->uaccess_active = 0;
}

int uaccess_arm(thread_t *t, const void *uptr, size_t n, void *resume_rip, int recv_range) {
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
void debug_dump_kernel_syscall_stack(void) {
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
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3) {
        cur = thread_get_current_user();
        if (!cur) return;
    }
    syscall_bind_kstack_for_thread(cur);
    if (!cur->syscall_frame_kbuf) {
        uint64_t *kbuf = (uint64_t *)kmalloc(16 * sizeof(uint64_t));
        if (kbuf) cur->syscall_frame_kbuf = kbuf;
    }
    if (cur->syscall_frame_kbuf) {
        memcpy(cur->syscall_frame_kbuf, frame, 16 * sizeof(uint64_t));
        cur->saved_syscall_frame = cur->syscall_frame_kbuf;
    } else {
        cur->saved_syscall_frame = frame;
    }
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
    int tid = cur->defer_unblock_tid;
    if (tid < 0) return;
    cur->defer_unblock_tid = -1;
    thread_unblock(tid);
    /* Do NOT thread_schedule() here: parent is still inside syscall_do on its
       per-thread syscall kstack. context_switch would snapshot the wrong RSP
       (scheduler frame on kernel_stack) and iretq back to user with RIP=0/garbage. */
}

void rebuild_syscall_frame(thread_t *t) {
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
    frame[13] = t->saved_user_rcx;
    /* leave frame[14] (saved rax) to be overwritten by syscall_entry64 */
    frame[15] = t->saved_user_rsp;
}

/* Keep stack layout consistent with core/elf.c user_stack_top_for_tid().
   Duplicated here because elf.c helper is static. */
uintptr_t user_stack_top_for_tid_like_exec(uint64_t tid) {
    const uintptr_t top = (uintptr_t)USER_STACK_TOP;
    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
    const uint64_t slot = tid + 1ULL;
    if (stride == 0) return top;
    if (slot > (uint64_t)((uintptr_t)-1) / (uint64_t)stride) return top;
    const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
    const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
    if (top <= min_room) return top;
    if (off >= (top - min_room)) return top;
    return top - off;
}

/* TLS layout matches core/elf.c (stack slot, not brk/heap). */
void fork_tls_layout_for_tid(uint64_t tid, uintptr_t stack_top,
        uintptr_t *tls_region, uintptr_t *fs_base, uintptr_t *pthread_fake) {
    if (!tls_region || !fs_base || !pthread_fake) return;
    if (!stack_top)
        stack_top = user_stack_top_for_tid_like_exec(tid);
    *tls_region = stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
    *fs_base = *tls_region + 0x1000u;
    *pthread_fake = *tls_region + 0x2000u;
}

/* Relocate user pointers from parent stack slice/slot into the child's copy. */

uint64_t fork_reloc_user_ptr(uint64_t val,
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

void fork_reloc_range_u64(uintptr_t base, uintptr_t nbytes,
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
int fork_copy_parent_tls(uintptr_t child_tls, uintptr_t parent_tls, mm_t *child_mm, mm_t *parent_mm) {
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
void fork_seed_glibc_tls(uintptr_t tls_region, uintptr_t fs_base, uintptr_t pthread_fake) {
    if (tls_region + 0x3000u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    uint64_t guard = 0x8b13f00d2a11c0deULL;
    guard &= ~0xFFULL;
    *(volatile uint64_t *)(uintptr_t)(fs_base + 0x28u) = guard;
    *(volatile uint64_t *)(uintptr_t)(fs_base - 0x78u) = (uint64_t)pthread_fake;
    {
        const uintptr_t c_str = tls_region + 0x2800u;
        if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            *(volatile uint8_t *)(uintptr_t)(c_str + 0) = (uint8_t)'C';
            *(volatile uint8_t *)(uintptr_t)(c_str + 1) = 0;
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

/* Linux-like fork behavior: keep parent's FS base when it is already set up by libc.
   This avoids moving the TCB to a different VA, which breaks static glibc. */
int fork_should_keep_parent_fs(uint64_t parent_fs_base) {
    const uint64_t user_min = 0x00200000ULL;
    if (parent_fs_base < user_min) return 0;
    if (parent_fs_base >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

void fork_stop_child(thread_t *child) {
    if (!child) return;
    thread_stop((int)(child->tid ? child->tid : 1));
    if (child->mm && child->mm != mm_kernel()) {
        mm_release(child->mm);
        child->mm = mm_retain(mm_kernel());
    }
    if (child->mm_ptemplate) {
        mm_release(child->mm_ptemplate);
        child->mm_ptemplate = NULL;
    }
}

#ifndef AXON_FORK_DEBUG
#define AXON_FORK_DEBUG 0
#endif

void axon_user_dbg(thread_t *cur, const char *tag, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
#if AXON_FORK_DEBUG
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "%s[%d] %s a=0x%llx b=0x%llx c=0x%llx\n",
        tag ? tag : "dbg", step, msg ? msg : "",
        a, b, c);
    if (n > 0 && (size_t)n < sizeof(buf)) {
        if (cur && cur->fds[1])
            (void)fs_write(cur->fds[1], buf, (size_t)n, cur->fds[1]->pos);
    }
    qemu_debug_printf("%s[%d] %s tid=%llu a=0x%llx b=0x%llx c=0x%llx\n",
        tag ? tag : "dbg", step, msg ? msg : "",
        (unsigned long long)(cur && cur->tid ? cur->tid : 0),
        a, b, c);
#else
    (void)cur; (void)tag; (void)step; (void)msg; (void)a; (void)b; (void)c;
#endif
}

#if AXON_FORK_DEBUG
void fork_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    axon_user_dbg(cur, "fork", step, msg, a, b, c);
}
#else
void fork_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    (void)cur; (void)step; (void)msg; (void)a; (void)b; (void)c;
}
#endif

#if AXON_FORK_DEBUG
void clone3_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    axon_user_dbg(cur, "clone3", step, msg, a, b, c);
}
#else
void clone3_dbg(thread_t *cur, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c) {
    (void)cur; (void)step; (void)msg; (void)a; (void)b; (void)c;
}
#endif

/* Restore parent's userspace stack snapshot for a vfork child.
   In AxonOS we block the parent until the child exits; however the child still
   runs in the same address space and may temporarily modify the parent's stack
   frames above the saved RSP. To avoid post-vfork corruption (seen as #GP with
   non-canonical RBP in busybox sh), we snapshot that region in SYS_vfork and
   restore it right before waking the parent on SYS_exit/SYS_exit_group. */
void vfork_restore_parent_stack(thread_t *child) {
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

/* forward for user brk state used in vfork restore */
static uintptr_t user_brk_cur;

void vfork_restore_parent_memory(thread_t *child) {
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

/* exit_group must tear down clone3 peers: they share pgid and may sit in devfs tty waiters.
 * waiters[] is only 8 slots; excess blocks the shell's read(stdin) after wget returns. */
void exit_group_reap_peer_threads(thread_t *cur) {
    if (!cur || cur->ring != 3) return;
    /* vfork child before execve still has parent's pgid; reaping would kill the shell. */
    if (cur->parent_tid >= 0) {
        thread_t *pt = thread_get(cur->parent_tid);
        if (pt && pt->ring == 3 && (int)cur->pgid == (int)pt->pgid)
            return;
    }
    int group_pgid = cur->pgid;
    int nt = thread_get_count();
    for (int i = 0; i < nt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t == cur) continue;
        if (t->ring != 3) continue;
        if (t->state == THREAD_TERMINATED) continue;
        if ((int)t->pgid != group_pgid) continue;
        devfs_tty_remove_waiter_from_all_ttys((int)(t->tid ? t->tid : 1));
        if (t->waiter_tid >= 0) {
            int w = t->waiter_tid;
            t->waiter_tid = -1;
            thread_unblock(w);
        }
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            if (t->fds[fd]) {
                struct fs_file *f = t->fds[fd];
                t->fds[fd] = NULL;
                fs_file_free(f);
            }
        }
        if (t->mm && t->mm != mm_kernel()) {
            mm_release(t->mm);
            t->mm = mm_kernel();
        }
        t->exit_status = 9; /* WTERMSIG: SIGKILL */
        t->state = THREAD_TERMINATED;
    }
}

/* Helper: copy up to `max` bytes from user pointer `uptr` into newly allocated buffer. */
void *copy_from_user_safe(const void *uptr, size_t count, size_t max, size_t *out_copied) {
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
#define EFAULT  14
#define EINVAL  22
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
#define ENOTCONN 107
#define EISCONN 106
#define ENODEV   19
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#ifndef ECONNRESET
#define ECONNRESET 104
#endif

ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur);
ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur);

void pipe_release_end(struct fs_file *f) {
    if (!f || f->type != FS_TYPE_PIPE || !f->driver_private) return;
    pipe_t *p = (pipe_t *)f->driver_private;
    unsigned long fl = 0;
    acquire_irqsave(&p->lock, &fl);
    p->refcount--;
    int ref = p->refcount;
    /* Wake waiter on the other end so they see EOF or EPIPE */
    if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
    if (p->writer_waiter_tid >= 0) { thread_unblock(p->writer_waiter_tid); p->writer_waiter_tid = -1; }
    release_irqrestore(&p->lock, fl);
    if (ref == 0) {
        kfree(p->buf);
        kfree(p);
    }
}

ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur) {
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
            return (ssize_t)n;
        }
        if (p->refcount < 2) { release_irqrestore(&p->lock, fl); return 0; } /* EOF */
        p->reader_waiter_tid = cur ? (int)cur->tid : -1;
        release_irqrestore(&p->lock, fl);
        if (p->reader_waiter_tid >= 0) {
            thread_block(p->reader_waiter_tid);
            thread_yield();
        }
    }
}

ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur) {
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
            if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
            release_irqrestore(&p->lock, fl);
            continue;
        }
        if (p->refcount < 2) { release_irqrestore(&p->lock, fl); return written > 0 ? (ssize_t)written : -EPIPE; }
        p->writer_waiter_tid = cur ? (int)cur->tid : -1;
        release_irqrestore(&p->lock, fl);
        if (p->writer_waiter_tid >= 0) {
            thread_block(p->writer_waiter_tid);
            thread_yield();
        }
    }
    return (ssize_t)written;
}


int copy_to_user_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, uptr, n, &&fault, 0) != 0) return -1;
    volatile uint8_t *dst = (volatile uint8_t *)uptr;
    const uint8_t *src = (const uint8_t *)kptr;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

int copy_from_user_raw(void *kdst, const void *usrc, size_t n) {
    if (!kdst || !usrc) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, usrc, n, &&fault, 0) != 0) return -1;
    uint8_t *dst = (uint8_t *)kdst;
    const volatile uint8_t *src = (const volatile uint8_t *)usrc;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

inline int user_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    /* Restrict to user-mapped identity range only.
       This prevents user pointers from targeting kernel heap/stack, which can
       corrupt saved syscall frames and thread structs (seen as #GP after vfork). */
    const uintptr_t user_min = 0x00010000u;
    if (start < user_min) return 0;
    if (end > (uintptr_t)USER_STACK_TOP) return 0;
    return 1;
}

inline int user_recv_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    if (start < 0x00010000u) return 0;
    if (end > (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

int copy_to_user_recv_safe(void *uptr, const void *kptr, size_t n) {
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

int user_read_u64(const void *uaddr, uint64_t *out) {
    if (!out) return -1;
    if (!user_range_ok(uaddr, sizeof(uint64_t))) return -1;
    /* copy to avoid alignment surprises */
    if (copy_from_user_raw(out, uaddr, sizeof(uint64_t)) != 0) return -1;
    return 0;
}

int user_write_u64(void *uaddr, uint64_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

int user_write_u8(void *uaddr, uint8_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

size_t user_strnlen_bounded(const char *s, size_t max) {
    if (!s) return 0;
    if (max == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, s, max, &&fault, 0) != 0) return max;
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
    uaccess_clear(t);
    return max;
}

char *copy_user_cstr(const char *u, size_t maxlen) {
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
