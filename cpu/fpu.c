#include <fpu.h>
#include <heap.h>
#include <klog.h>
#include <stdint.h>
#include <string.h>
#include <thread.h>

/*
 * Enable FPU/SSE and, when the CPU supports it, XSAVE + AVX (XCR0.YMM).
 *
 * glibc/openrc IFUNC paths use VEX/AVX (e.g. vmovdqu ymm) when CPUID.AVX is set.
 * Without CR4.OSXSAVE and XCR0 bit 2 those opcodes #UD in user mode.
 */

static void cpuid4(uint32_t leaf, uint32_t sub,
                   uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    asm volatile("cpuid"
                 : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                 : "a"(leaf), "c"(sub));
}

enum { FPU_STATE_MAX = 4096 };
static uint8_t fpu_initial_state[FPU_STATE_MAX] __attribute__((aligned(64)));
static uint32_t fpu_state_size = 512;
static uint64_t fpu_xcr0_mask = 0x3;
static int fpu_use_xsave;
static int fpu_initial_ready;

static void fpu_save_area(void *area) {
    if (!area)
        return;
    if (fpu_use_xsave) {
        uint32_t lo = (uint32_t)fpu_xcr0_mask;
        uint32_t hi = (uint32_t)(fpu_xcr0_mask >> 32);
        asm volatile("xsave64 (%0)" :: "r"(area), "a"(lo), "d"(hi) : "memory");
    } else {
        asm volatile("fxsave64 (%0)" :: "r"(area) : "memory");
    }
}

static void fpu_restore_area(const void *area) {
    if (!area)
        return;
    if (fpu_use_xsave) {
        uint32_t lo = (uint32_t)fpu_xcr0_mask;
        uint32_t hi = (uint32_t)(fpu_xcr0_mask >> 32);
        asm volatile("xrstor64 (%0)" :: "r"(area), "a"(lo), "d"(hi) : "memory");
    } else {
        asm volatile("fxrstor64 (%0)" :: "r"(area) : "memory");
    }
}

void fpu_init_cpu(void) {
    uint64_t cr0, cr4;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1ULL << 2); /* EM=0: allow FPU/SSE */
    cr0 |= (1ULL << 1);  /* MP=1 */
    cr0 &= ~(1ULL << 3); /* TS=0: no lazy #NM until we implement it */
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");

    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 9);  /* OSFXSR */
    cr4 |= (1ULL << 10); /* OSXMMEXCPT */

    uint32_t a1 = 0, b1 = 0, c1 = 0, d1 = 0;
    cpuid4(1, 0, &a1, &b1, &c1, &d1);
    int have_xsave = (c1 & (1u << 26)) != 0;
    int have_avx = (c1 & (1u << 28)) != 0;

    if (have_xsave)
        cr4 |= (1ULL << 18); /* OSXSAVE */

    asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");

    if (have_xsave) {
        uint32_t xa = 0, xb = 0, xc = 0, xd = 0;
        cpuid4(0xD, 0, &xa, &xb, &xc, &xd);
        /* XCR0 must enable x87+SSE; add AVX (bit 2) when supported. */
        uint64_t xcr0 = 0x3ULL;
        if (have_avx && (xa & (1u << 2)))
            xcr0 |= (1ULL << 2);
        xcr0 &= ((uint64_t)xd << 32) | (uint64_t)xa;
        if (xcr0 < 0x3ULL)
            xcr0 = 0x3ULL;
        uint32_t lo = (uint32_t)xcr0;
        uint32_t hi = (uint32_t)(xcr0 >> 32);
        asm volatile("xsetbv" :: "c"(0), "a"(lo), "d"(hi) : "memory");
        cpuid4(0xD, 0, &xa, &xb, &xc, &xd);
        if (xb > FPU_STATE_MAX) {
            /* Keep x87+SSE only if this CPU's enabled XSAVE image is larger
             * than the bounded per-thread storage. */
            xcr0 = 0x3ULL;
            lo = (uint32_t)xcr0;
            hi = 0;
            asm volatile("xsetbv" :: "c"(0), "a"(lo), "d"(hi) : "memory");
            cpuid4(0xD, 0, &xa, &xb, &xc, &xd);
        }
        if (xb >= 512 && xb <= FPU_STATE_MAX) {
            fpu_use_xsave = 1;
            fpu_state_size = xb;
            fpu_xcr0_mask = xcr0;
        }
        static int logged;
        if (!logged) {
            logged = 1;
            klogprintf("fpu: XSAVE xcr0=0x%llx avx=%d\n",
                    (unsigned long long)xcr0, have_avx ? 1 : 0);
        }
    }

    asm volatile("fninit");
    {
        /* Default MXCSR: flush-to-zero off, denormals-are-zero off, all masks set. */
        uint32_t mxcsr = 0x1F80u;
        asm volatile("ldmxcsr %0" :: "m"(mxcsr) : "memory");
    }
    if (!fpu_initial_ready) {
        memset(fpu_initial_state, 0, sizeof(fpu_initial_state));
        fpu_save_area(fpu_initial_state);
        fpu_initial_ready = 1;
    }
}

int fpu_thread_init(struct thread *thread) {
    if (!thread || !fpu_initial_ready)
        return -1;
    void *raw = kmalloc((size_t)fpu_state_size + 63u);
    if (!raw)
        return -1;
    uintptr_t aligned = ((uintptr_t)raw + 63u) & ~(uintptr_t)63u;
    thread->fpu_state_raw = raw;
    thread->fpu_state = (void *)aligned;
    memcpy(thread->fpu_state, fpu_initial_state, fpu_state_size);
    return 0;
}

void fpu_thread_destroy(struct thread *thread) {
    if (!thread)
        return;
    if (thread->fpu_state_raw)
        kfree(thread->fpu_state_raw);
    thread->fpu_state_raw = NULL;
    thread->fpu_state = NULL;
}

void fpu_thread_fork(struct thread *parent, struct thread *child) {
    if (!parent || !child || !parent->fpu_state || !child->fpu_state)
        return;
    /* fork is entered by the running parent, so memory may be stale until
     * the live hardware image is captured here. */
    fpu_save_area(parent->fpu_state);
    memcpy(child->fpu_state, parent->fpu_state, fpu_state_size);
}

void fpu_switch(struct thread *prev, struct thread *next) {
    if (!fpu_initial_ready || prev == next)
        return;
    if (prev && prev->fpu_state)
        fpu_save_area(prev->fpu_state);
    if (next && next->fpu_state)
        fpu_restore_area(next->fpu_state);
    else
        fpu_restore_area(fpu_initial_state);
}
