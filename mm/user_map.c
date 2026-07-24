#include <user_map.h>
#include <exec.h>
#include <heap.h>
#include <mmio.h>
#include <mm.h>
#include <paging.h>
#include <thread.h>

#define USER_DATA_REGION_LO 0x200000ULL
#define USER_DATA_REGION_HI ((uint64_t)0x10000000ULL)

int user_map_unmap_range(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t l1i = (va >> 12) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) continue;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) continue;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) continue;
        uint64_t l2_phys = l3e & ~0xFFFULL;
        uint64_t *l2 = (uint64_t *)(uintptr_t)l2_phys;
        if (!(l2[l2i] & PG_PRESENT)) continue;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            uint64_t page_lo = va & ~((uint64_t)(PAGE_SIZE_2M - 1));
            uint64_t page_hi = page_lo + PAGE_SIZE_2M;
            uint64_t l3_phys = l4[l4i] & ~0xFFFULL;
            uint64_t l4_phys = cr3 & ~0xFFFULL;
            if ((l2_phys >= page_lo && l2_phys < page_hi) ||
                (l3_phys >= page_lo && l3_phys < page_hi) ||
                (l4_phys >= page_lo && l4_phys < page_hi))
                continue;
            l2[l2i] = 0;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
        l1[l1i] = 0;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

int user_map_mprotect_range(uint64_t va_begin, uint64_t va_end, int prot) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t prot_begin = va_begin & ~0xFFFULL;
    uint64_t prot_end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (prot_end > (uint64_t)MMIO_IDENTITY_LIMIT) prot_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    /*
     * Prefer the task mm root. During bprm load CR3 is still oldmm; walking
     * live CR3 would mprotect the frozen vfork parent's leaves.
     */
    uint64_t *l4 = NULL;
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        mm_t *k = mm_kernel();
        if (t && t->mm && t->mm->pml4 && k && k->pml4 && t->mm->pml4 != k->pml4)
            l4 = t->mm->pml4;
    }
    if (!l4) {
        uint64_t cr3 = paging_read_cr3();
        l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    }
    if (!l4) return -1;
    uint64_t new_flags = 0;
    if (prot != 0) {
        new_flags = PG_PRESENT | PG_US | PG_PS_2M;
        if (prot & 2) new_flags |= PG_RW;
        if (!(prot & 4)) new_flags |= PG_NX;
        if (va_begin < USER_DATA_REGION_HI && va_end > USER_DATA_REGION_LO)
            new_flags |= PG_RW;
    }
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) return -1;
        uint64_t *l2 = (uint64_t *)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            if (prot_begin > va || prot_end < va + PAGE_SIZE_2M) {
                /* We cannot express sub-2MiB permissions on a large page without
                 * splitting it. Return success for ld.so RELRO-style mprotects,
                 * but do not accidentally NX the neighbouring executable text. */
                invlpg((void *)(uintptr_t)va);
                continue;
            }
            uint64_t pa = l2e & PG_ADDR_MASK_2M;
            uint64_t f = new_flags |
                (l2e & (PG_SOFT_COW | PG_SOFT_OWNED));
            if (f & PG_SOFT_COW)
                f &= ~PG_RW;
            l2[l2i] = pa | f;
        } else {
            uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
            uint64_t chunk_lo = va;
            uint64_t chunk_hi = va + PAGE_SIZE_2M;
            if (chunk_lo < prot_begin) chunk_lo = prot_begin;
            if (chunk_hi > prot_end) chunk_hi = prot_end;
            for (uint64_t v = chunk_lo; v < chunk_hi && v < (uint64_t)MMIO_IDENTITY_LIMIT; v += 0x1000ULL) {
                uint64_t l1i = (v >> 12) & 0x1FF;
                /* Never install PA==VA into a hole — that re-identities the
                 * BusyBox slab/stack after vfork detach (ash GPF at RIP=="ls"). */
                if (!(l1[l1i] & PG_PRESENT))
                    continue;
                uint64_t pa = l1[l1i] & PG_ADDR_MASK;
                uint64_t f = (new_flags & ~PG_PS_2M) |
                    (l1[l1i] & (PG_SOFT_COW | PG_SOFT_OWNED));
                if (f & PG_SOFT_COW)
                    f &= ~PG_RW;
                l1[l1i] = pa | f;
                invlpg((void *)(uintptr_t)v);
            }
        }
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

int user_map_ensure_present_us_2m(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    if (begin >= end) return -1;

    /*
     * Tasks with a private CR3 must never grow via map_page_2m(va,va).
     * arch_prctl(SET_FS) for BusyBox (fs≈0x8003c0) used to re-identity the
     * whole 0x800000 2MiB slab after vfork detach → parent ash GPF at "ls".
     */
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        mm_t *k = mm_kernel();
        if (t && t->mm && k && t->mm->pml4 && k->pml4 &&
            t->mm->pml4 != k->pml4) {
            mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : k;
            uint64_t req_lo = va_begin & ~0xFFFULL;
            uint64_t req_hi = (va_end + 0xFFFULL) & ~0xFFFULL;
            if (req_hi > (uint64_t)MMIO_IDENTITY_LIMIT)
                req_hi = (uint64_t)MMIO_IDENTITY_LIMIT;
            /*
             * Low 2MiB is kernel identity under the process CR3. Fork probes
             * [0x10000,0x200000); blanking that window zeroed IDT/text →
             * triple-fault. Anon zero pages (do_brk_flags) start at user VA.
             */
            const uint64_t user_anon_floor = 0x200000ULL;
            if (req_hi <= user_anon_floor)
                return user_map_mark_identity_2m(req_lo, req_hi);
            if (req_lo < user_anon_floor)
                req_lo = user_anon_floor;
            /*
             * ensure_present is not do_brk_flags. Present identity may already
             * hold user content (glibc __libc_setup_tls writes .tdata/TCB, then
             * arch_prctl(SET_FS)). Blanking that page → NULL TLS ptrs → #PF RIP=0.
             * Copy-privatize identity; only absent pages get anon zero.
             */
            mm_dbg_ash_touch("ensure-present", t->mm, req_lo, req_hi);
            if (mm_privatize_identity_range(t->mm, req_lo, req_hi) != 0)
                return -1;
            for (uint64_t va = req_lo; va < req_hi; va += 0x1000ULL) {
                uint64_t leaf = 0;
                if (mm_va_leaf_pa(t->mm, va, &leaf) == 0)
                    continue;
                if (mm_make_private_range_noyield(t->mm, va, va + 0x1000ULL, 0, share) != 0)
                    return -1;
            }
            /* Leaves already PG_US from sharedaware — do not mark_identity on
             * live CR3 (during vfork-exec load that is still oldmm). */
            return 0;
        }
    }

    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
            return -1;
    }
    return 0;
}

int user_map_mark_identity_2m(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    /*
     * During bprm load CR3 stays on oldmm while t->mm is nascent. Stamping
     * PG_US/RW on the live tables would mutate the frozen vfork parent
     * (ash GPF at RIP=="ls"). Private leaves already carry PG_US.
     */
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        mm_t *k = mm_kernel();
        if (t && t->mm && k && t->mm->pml4 && k->pml4 &&
            t->mm->pml4 != k->pml4) {
            uint64_t live = paging_read_cr3() & ~0xFFFULL;
            uint64_t want = (uint64_t)(uintptr_t)t->mm->pml4;
            if (live != want)
                return 0;
        }
    }
    uint64_t cr3 = paging_read_cr3();
    uint64_t *active_l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!active_l4) return -1;
    /* Do not publish identity-mapped kernel heap pages to ring3. */
    {
        uintptr_t hlo = heap_base_addr();
        uintptr_t hhi = heap_region_end_exclusive();
        if (hlo && hhi > hlo) {
            if (va_end > (uint64_t)hlo && va_begin < (uint64_t)hhi) {
                if (va_begin < (uint64_t)hlo && va_end > (uint64_t)hhi) {
                    if (user_map_mark_identity_2m(va_begin, (uint64_t)hlo) != 0)
                        return -1;
                    return user_map_mark_identity_2m((uint64_t)hhi, va_end);
                }
                if (va_begin < (uint64_t)hlo)
                    va_end = (uint64_t)hlo;
                else if (va_end > (uint64_t)hhi)
                    va_begin = (uint64_t)hhi;
                else
                    return 0;
                if (va_end <= va_begin)
                    return 0;
            }
        }
    }
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = active_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US | PG_RW;
        l4[l4i] &= ~PG_NX;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US | PG_RW;
        l3[l3i] &= ~PG_NX;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) {
            l3[l3i] |= PG_US;
            if (l3[l3i] & PG_SOFT_COW)
                l3[l3i] &= ~PG_RW;
            else
                l3[l3i] |= PG_RW;
            l3[l3i] &= ~PG_NX;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l2 = (uint64_t *)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        l2[l2i] |= PG_US | PG_RW;
        l2[l2i] &= ~PG_NX;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            l2[l2i] = (l2e | PG_US) & ~PG_NX;
            if (l2e & PG_SOFT_COW)
                l2[l2i] &= ~PG_RW;
            else
                l2[l2i] |= PG_RW;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
        uint64_t chunk_end = va + PAGE_SIZE_2M;
        if (chunk_end > end) chunk_end = end;
        for (uint64_t p = va; p < chunk_end; p += PAGE_SIZE_4K) {
            uint64_t idx = (p >> 12) & 0x1FF;
            if (l1[idx] & PG_PRESENT) {
                l1[idx] |= PG_US;
                if (l1[idx] & PG_SOFT_COW)
                    l1[idx] &= ~PG_RW;
                else
                    l1[idx] |= PG_RW;
                l1[idx] &= ~PG_NX;
            }
            invlpg((void *)(uintptr_t)p);
        }
    }
    return 0;
}
