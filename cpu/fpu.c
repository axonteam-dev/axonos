#include <fpu.h>
#include <klog.h>
#include <stdint.h>

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
}
