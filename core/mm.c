#include <mm.h>
#include <paging.h>
#include <heap.h>
#include <string.h>
#include <mmio.h>
#include <thread.h>
#include <user_vma.h>
#include <user_layout.h>
#include <klog.h>
#include <vga.h>
#include <debug.h>
#include <frame.h>

#ifndef USER_STACK_TOP
#define USER_STACK_TOP USER_STACK_TOP_LAYOUT
#endif

static mm_t g_kernel_mm;
static int g_mm_ready = 0;
static int mm_va_leaf_entry(mm_t *mm, uint64_t va, uint64_t *entry_out);
static int mm_va_leaf_entry_direct(mm_t *mm, uint64_t va, uint64_t *entry_out);
static int mm_user_leaf_pa_direct(mm_t *mm, uint64_t va, int write,
                                  uint64_t *pa_out);

typedef struct mm_alloc_node {
    void *raw;
    struct mm_alloc_node *next;
} mm_alloc_node_t;

static void *kmalloc_aligned(size_t size, size_t align, void **out_raw) {
    if (!out_raw || align == 0) return NULL;
    void *raw = kmalloc(size + align);
    if (!raw) return NULL;
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)align - 1u) & ~((uintptr_t)align - 1u);
    *out_raw = raw;
    return (void*)aligned;
}

/*
 * User leaf backing is not mm-owned heap memory.  A fork may keep the frame
 * alive after the mm that first allocated it exits or execs, so lifetime must
 * be controlled solely by frame refs.  Page-table pages remain in mm->allocs.
 */
static void *mm_user_frame_alloc(int zero) {
    return zero ? frame_alloc_zero() : frame_alloc();
}

static void mm_user_frame_put(void *page) {
    if (page)
        frame_release((uint64_t)(uintptr_t)page);
}

/*
 * Kernel heap / PMM share the identity VA space with user mappings.  A frame
 * whose PA equals the target VA is not a private leaf — it aliases that VA.
 * Hold colliding pages aside so the allocator cannot immediately return the
 * same PA, then release them once a distinct frame is in hand.
 */
static void *mm_user_frame_alloc_avoid_va(uint64_t va, int zero) {
    void *hold[8];
    int n = 0;
    uint64_t page = va & ~0xFFFULL;
    void *p = NULL;

    while (n < 8) {
        p = mm_user_frame_alloc(zero);
        if (!p)
            break;
        if (((uint64_t)(uintptr_t)p & ~0xFFFULL) != page)
            break;
        hold[n++] = p;
        p = NULL;
    }
    while (n > 0)
        mm_user_frame_put(hold[--n]);
    return p;
}

static int mm_track_raw(mm_t *mm, void *raw) {
    if (!mm || !raw) return -1;
    mm_alloc_node_t *n = (mm_alloc_node_t*)kmalloc(sizeof(*n));
    if (!n)
        return -1;
    n->raw = raw;
    n->next = (mm_alloc_node_t*)mm->allocs;
    mm->allocs = (struct mm_alloc_node*)n;
    return 0;
}

static uint64_t *alloc_pt_page(mm_t *mm) {
    void *raw = NULL;
    void *aligned = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
    if (!aligned)
        return NULL;
    if (mm_track_raw(mm, raw) != 0) {
        kfree(raw);
        return NULL;
    }
    memset(aligned, 0, (size_t)PAGE_SIZE_4K);
    return (uint64_t*)aligned;
}

/* Page-table pages must live in the identity-mapped low region; otherwise
 * casting PTE physical addresses to pointers faults (e.g. PA == 4GiB). */
static inline int pt_page_pa_ok(uint64_t ent) {
    if (!(ent & PG_PRESENT)) return 1;
    return (ent & PG_ADDR_MASK) < (uint64_t)MMIO_IDENTITY_LIMIT;
}

/*
 * Linux services page-table walks through the direct map (__va / page_address),
 * which userspace munmap / PROT_NONE cannot punch. AxonOS uses identity VA==PA
 * for the same role: software casts of PTE PAs must run under swapper CR3 so
 * a process hole at e.g. 0x8119000 (Go arena reserve) cannot Oops the kernel
 * while reading share_l3 in mm_fork_private_pt_path / mm_map_4k_sharedaware.
 *
 * Critical: hold IF=0 for the whole window. thread_schedule → mm_switch would
 * otherwise reload the process CR3 mid-walk and either Oops or corrupt user
 * memory (seen as Go poison regs after docker pthread + PROT_NONE).
 */
static uint64_t mm_direct_map_cr3(void) {
    if (g_mm_ready && g_kernel_mm.cr3)
        return g_kernel_mm.cr3;
    if (g_mm_ready && g_kernel_mm.pml4)
        return (uint64_t)(uintptr_t)g_kernel_mm.pml4;
    return paging_read_cr3();
}

mm_dm_ctx_t mm_enter_direct_map(void) {
    mm_dm_ctx_t ctx;
    asm volatile(
        "pushfq\n\t"
        "pop %0\n\t"
        "cli"
        : "=r"(ctx.irqf)
        :
        : "memory");
    ctx.cr3 = paging_read_cr3();
    uint64_t want = mm_direct_map_cr3();
    if ((ctx.cr3 & ~0xFFFULL) != (want & ~0xFFFULL))
        paging_write_cr3(want);
    return ctx;
}

void mm_leave_direct_map(mm_dm_ctx_t ctx) {
    if ((paging_read_cr3() & ~0xFFFULL) != (ctx.cr3 & ~0xFFFULL))
        paging_write_cr3(ctx.cr3);
    asm volatile("push %0; popfq" :: "r"(ctx.irqf) : "memory", "cc");
}

static uint64_t *dup_pt_page(mm_t *mm, uint64_t *src) {
    if (!src || (uintptr_t)src >= (uintptr_t)MMIO_IDENTITY_LIMIT) return NULL;
    uint64_t *dst = alloc_pt_page(mm);
    if (!dst) return NULL;
    memcpy(dst, src, (size_t)PAGE_SIZE_4K);
    return dst;
}

/* True if `pt` was allocated into this mm (exclusive PT page). */
static int mm_owns_pt_page(mm_t *mm, const uint64_t *pt) {
    if (!mm || !pt)
        return 0;
    uintptr_t want = (uintptr_t)pt;
    for (mm_alloc_node_t *n = (mm_alloc_node_t *)mm->allocs; n; n = n->next) {
        if (!n->raw)
            continue;
        uintptr_t raw = (uintptr_t)n->raw;
        uintptr_t aligned = (raw + (uintptr_t)PAGE_SIZE_4K - 1u) &
                            ~((uintptr_t)PAGE_SIZE_4K - 1u);
        if (aligned == want)
            return 1;
    }
    return 0;
}

static int split_2m_to_4k(mm_t *mm, uint64_t *l2, int l2i, uint64_t va) {
    uint64_t ent2 = l2[l2i];
    if (!(ent2 & PG_PRESENT) || !(ent2 & PG_PS_2M)) return 0;
    uint64_t base_pa = ent2 & PG_ADDR_MASK_2M;
    uint64_t keep = ent2 & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD |
                            PG_GLOBAL | PG_SOFT_COW | PG_NX);
    /* Bootstrap identity 2MiB leaves are supervisor-only (U=0). Splitting them for
     * fork COW must not leave the other 511 4K siblings inaccessible to userland. */
    if (va >= 0x200000ULL && va < (uint64_t)MMIO_IDENTITY_LIMIT)
        keep |= PG_US;
    /*
     * Do NOT punch non-present holes for "identity siblings" here. That broke
     * boot: kernel memcpy to tip VA (CR2=0x3fffxxxx) under process CR3 after
     * exec tip split. Stack isolation is exec_map_stack_tip fail-closed +
     * leaf-PA stores, not emptying the 2MiB.
     */
    uint64_t *l1 = alloc_pt_page(mm);
    if (!l1) return -1;
    for (size_t i = 0; i < 512; i++) {
        uint64_t pa = base_pa + ((uint64_t)i * PAGE_SIZE_4K);
        l1[i] = (pa & PG_ADDR_MASK) | (keep & ~PG_PS_2M);
    }
    l2[l2i] = ((uint64_t)(uintptr_t)l1) | (keep & ~PG_PS_2M);
    return 0;
}

/* Split a 1GiB L3 leaf (bootstrap identity) into a L2 table of 2MiB pages. */
static int split_l3_1g_to_l2(mm_t *mm, uint64_t *l3, int l3i) {
    uint64_t ent3 = l3[l3i];
    if (!(ent3 & PG_PRESENT) || !(ent3 & PG_PS_2M)) return 0;
    uint64_t base_pa = ent3 & PG_ADDR_MASK_1G;
    uint64_t keep = ent3 & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
    uint64_t *l2 = alloc_pt_page(mm);
    if (!l2) return -1;
    for (size_t i = 0; i < 512; i++) {
        uint64_t pa = base_pa + (uint64_t)i * PAGE_SIZE_2M;
        l2[i] = (pa & PG_ADDR_MASK_2M) | keep | PG_PS_2M;
    }
    l3[l3i] = ((uint64_t)(uintptr_t)l2) | (keep & ~PG_PS_2M);
    return 0;
}

/*
 * True if `ent` names the same next-level PT page as `other` (both present,
 * non-leaf). Used to break sharing with oldmm *and* with swapper_pg_dir —
 * Linux never mutates init_mm page tables from a task mm.
 */
static int mm_pte_same_pt_page(uint64_t ent, uint64_t other) {
    if (!(ent & PG_PRESENT) || !(other & PG_PRESENT))
        return 0;
    if ((ent & PG_PS_2M) || (other & PG_PS_2M))
        return 0;
    if (!pt_page_pa_ok(ent) || !pt_page_pa_ok(other))
        return 0;
    return (ent & PG_ADDR_MASK) == (other & PG_ADDR_MASK);
}

/* Map one 4K user page at `va` -> `pa` in `mm`, breaking sharing with baseline
 * page tables one level at a time. `share_l4` is oldmm (exec) or parent (fork).
 * Always dup away from mm_kernel()/swapper before any split or leaf write —
 * mm_alloc() shallow-clones swapper L4, so comparing only to oldmm would miss
 * shared L3/L2/L1 and corrupt the kernel heap (seen as magic=0xe5c5403e).
 * Caller must hold the direct-map CR3 (see mm_map_4k_sharedaware). */
static int mm_map_4k_sharedaware_body(mm_t *mm, uint64_t *share_l4, uint64_t va, uint64_t pa, uint64_t flags) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (mm == &g_kernel_mm) return -1;

    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);

    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return -1;
    uint64_t *swapper_l4 = g_mm_ready ? g_kernel_mm.pml4 : NULL;
    uint64_t ke4 = (swapper_l4 && (swapper_l4[l4i] & PG_PRESENT)) ? swapper_l4[l4i] : 0;

    uint64_t ent4 = mm->pml4[l4i];
    uint64_t *l3 = NULL;
    if (ent4 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent4)) return -1;
        if (mm_pte_same_pt_page(ent4, se4) || mm_pte_same_pt_page(ent4, ke4)) {
            l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
            uint64_t *n3 = dup_pt_page(mm, l3);
            if (!n3) return -1;
            l3 = n3;
            mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFFULL);
        } else {
            l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
        }
    } else {
        l3 = alloc_pt_page(mm);
        if (!l3) return -1;
        mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t *share_l3 = (uint64_t*)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    uint64_t ke3 = 0;
    if ((ke4 & PG_PRESENT) && !(ke4 & PG_PS_2M) && pt_page_pa_ok(ke4)) {
        uint64_t *kl3 = (uint64_t *)(uintptr_t)(ke4 & ~0xFFFULL);
        ke3 = kl3[l3i];
    }

    uint64_t ent3 = l3[l3i];
    if ((ent3 & PG_PRESENT) && (ent3 & PG_PS_2M)) {
        if (split_l3_1g_to_l2(mm, l3, l3i) != 0) return -1;
        ent3 = l3[l3i];
    }
    if (ent3 & PG_PS_2M) return -1;
    uint64_t *l2 = NULL;
    if (ent3 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent3)) return -1;
        l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
        /* Dup L2 if still shared with oldmm or swapper. */
        if (mm_pte_same_pt_page(ent3, se3) || mm_pte_same_pt_page(ent3, ke3)) {
            uint64_t *n2 = dup_pt_page(mm, l2);
            if (!n2) return -1;
            l2 = n2;
            l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
            ent3 = l3[l3i];
        }
    } else {
        l2 = alloc_pt_page(mm);
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | PG_PRESENT | PG_RW | PG_US;
        ent3 = l3[l3i];
    }

    uint64_t *share_l2 = NULL;
    uint64_t se2 = 0;
    if (!(se3 & PG_PRESENT)) return -1;
    if (!(se3 & PG_PS_2M)) {
        share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
        se2 = share_l2[l2i];
    }
    uint64_t *swapper_l2 = NULL;
    uint64_t ke2 = 0;
    if ((ke3 & PG_PRESENT) && !(ke3 & PG_PS_2M) && pt_page_pa_ok(ke3)) {
        swapper_l2 = (uint64_t *)(uintptr_t)(ke3 & ~0xFFFULL);
        ke2 = swapper_l2[l2i];
    }

    /*
     * L2 must be exclusive before split/leaf writes — vs oldmm and vs swapper.
     */
    if ((share_l2 && (uintptr_t)l2 == (uintptr_t)share_l2) ||
        (swapper_l2 && (uintptr_t)l2 == (uintptr_t)swapper_l2) ||
        mm_pte_same_pt_page(ent3, se3) || mm_pte_same_pt_page(ent3, ke3)) {
        uint64_t *n2 = dup_pt_page(mm, l2);
        if (!n2) return -1;
        l2 = n2;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
        ent3 = l3[l3i];
    }

    if (split_2m_to_4k(mm, l2, l2i, va) != 0) return -1;
    uint64_t ce2 = l2[l2i];

    /* Re-sample share after possible split on a previously-shared L2. */
    if (share_l2)
        se2 = share_l2[l2i];
    if (swapper_l2)
        ke2 = swapper_l2[l2i];

    uint64_t *l1 = NULL;
    if (!(ce2 & PG_PRESENT)) {
        l1 = alloc_pt_page(mm);
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | PG_PRESENT | PG_RW | PG_US;
    } else {
        if (!pt_page_pa_ok(ce2)) return -1;
        if (ce2 & PG_PS_2M) return -1;
        l1 = (uint64_t *)(uintptr_t)(ce2 & ~0xFFFULL);
        /*
         * Dup L1 unless this mm already owns it. Pointer inequality vs
         * share_l1 alone missed aliases after partial splits — child
         * make-private-zero then rewrote the parent's brk PTE (ash GPF at
         * RIP=="ls"). Fresh split_2m L1 is in mm->allocs → no re-dup.
         */
        {
            uint64_t *share_l1 = NULL;
            uint64_t *swapper_l1 = NULL;
            if (share_l2 && (se2 & PG_PRESENT) && !(se2 & PG_PS_2M) && pt_page_pa_ok(se2))
                share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
            if (swapper_l2 && (ke2 & PG_PRESENT) && !(ke2 & PG_PS_2M) && pt_page_pa_ok(ke2))
                swapper_l1 = (uint64_t *)(uintptr_t)(ke2 & ~0xFFFULL);
            int need_dup = !mm_owns_pt_page(mm, l1);
            if (share_l1 && (uintptr_t)l1 == (uintptr_t)share_l1)
                need_dup = 1;
            if (swapper_l1 && (uintptr_t)l1 == (uintptr_t)swapper_l1)
                need_dup = 1;
            if (mm_pte_same_pt_page(ce2, se2) || mm_pte_same_pt_page(ce2, ke2))
                need_dup = 1;
            if (need_dup) {
                uint64_t *n1 = dup_pt_page(mm, l1);
                if (!n1) return -1;
                l1 = n1;
                l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ce2 & 0xFFFULL);
                ce2 = l2[l2i];
            }
            /* Fail-closed: never store a leaf through a shared L1. */
            if (!mm_owns_pt_page(mm, l1) ||
                (share_l1 && (uintptr_t)l1 == (uintptr_t)share_l1) ||
                (swapper_l1 && (uintptr_t)l1 == (uintptr_t)swapper_l1) ||
                mm_pte_same_pt_page(ce2, se2) || mm_pte_same_pt_page(ce2, ke2)) {
                kprintf("map4k: non-exclusive L1 va=0x%llx mm=%p\n",
                        (unsigned long long)va, (void *)mm);
                return -1;
            }
        }
    }

    /*
     * Snapshot share leaf before store — must be unchanged after (parent/oldmm
     * isolation). Ash GPF class: child zero-page install mutating parent brk.
     */
    uint64_t share_pa_before = 0;
    mm_t share_mm_tmp;
    memset(&share_mm_tmp, 0, sizeof(share_mm_tmp));
    share_mm_tmp.pml4 = share_l4;
    int share_had = (mm_va_leaf_pa(&share_mm_tmp, va, &share_pa_before) == 0);
    /*
     * Bootstrap identity mappings begin supervisor-only.  A fork COW leaf
     * must make the complete translation path user-accessible now; otherwise
     * the later U=0 fault repair can re-enable a shared writable mapping and
     * bypass COW entirely.
     */
    mm->pml4[l4i] |= PG_US;
    l3[l3i] |= PG_US;
    l2[l2i] |= PG_US;
    /*
     * x86 permission checks AND the RW/US bits across every paging level.
     * A writable leaf under a copied read-only parent entry still faults
     * forever.  COW replacement is writable only when the complete path is.
     */
    if (flags & PG_RW) {
        mm->pml4[l4i] |= PG_RW;
        l3[l3i] |= PG_RW;
        l2[l2i] |= PG_RW;
    }
    /* Callers explicitly distinguish a private replacement from a retained
     * shared COW leaf through PG_SOFT_COW. */
    l1[l1i] = (pa & PG_ADDR_MASK) | (flags & ~PG_PS_2M) | PG_PRESENT;
    if (va >= 0x200000ULL && va < (uint64_t)MMIO_IDENTITY_LIMIT)
        l1[l1i] |= PG_US;
    l1[l1i] &= ~PG_PS_2M;
    if (l1[l1i] & PG_SOFT_COW)
        l1[l1i] &= ~PG_RW;
    invlpg((void *)(uintptr_t)va);
    if (share_had) {
        uint64_t share_pa_after = 0;
        if (mm_va_leaf_pa(&share_mm_tmp, va, &share_pa_after) != 0 ||
            (share_pa_after & PG_ADDR_MASK) !=
                (share_pa_before & PG_ADDR_MASK)) {
            kprintf("share-mutate-bug: va=0x%llx before=0x%llx after=0x%llx mm=%p\n",
                    (unsigned long long)va,
                    (unsigned long long)share_pa_before,
                    (unsigned long long)share_pa_after,
                    (void *)mm);
            return -1;
        }
    }
    return 0;
}

static int mm_map_4k_sharedaware(mm_t *mm, uint64_t *share_l4, uint64_t va, uint64_t pa, uint64_t flags) {
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = mm_map_4k_sharedaware_body(mm, share_l4, va, pa, flags);
    mm_leave_direct_map(dm);
    return rc;
}

static int mm_map_user_page_locked(mm_t *mm, uint64_t va, uint64_t pa,
				   uint64_t flags)
{
	uint64_t *l3, *l2, *l1;
	uint64_t e4, e3, e2, old;
	int l4i, l3i, l2i, l1i;

	if (!mm || !mm->pml4 || mm == &g_kernel_mm)
		return -1;
	if (va >= (uint64_t)MMIO_IDENTITY_LIMIT)
		return -2;
	/*
	 * Leaf PA: RAM frames stay in the identity window. Device maps
	 * (/dev/fb0) may use a 64-bit BAR; those leaves are never PG_SOFT_OWNED.
	 */
	if (pa & ~PG_ADDR_MASK)
		return -2;
	if ((flags & PG_SOFT_OWNED) && pa >= (uint64_t)MMIO_IDENTITY_LIMIT)
		return -2;

	l4i = (int)((va >> 39) & 0x1ff);
	l3i = (int)((va >> 30) & 0x1ff);
	l2i = (int)((va >> 21) & 0x1ff);
	l1i = (int)((va >> 12) & 0x1ff);

	e4 = mm->pml4[l4i];
	if (!(e4 & PG_PRESENT)) {
		l3 = alloc_pt_page(mm);
		if (!l3)
			return -3;
		mm->pml4[l4i] = (uint64_t)(uintptr_t)l3 |
					PG_PRESENT | PG_RW | PG_US;
	} else {
		if (!pt_page_pa_ok(e4)) {
			devel_printf("mm: bad pml4e mm=%p va=0x%llx e4=0x%llx\n",
				     (void *)mm, (unsigned long long)va,
				     (unsigned long long)e4);
			return -4;
		}
		l3 = (uint64_t *)(uintptr_t)(e4 & PG_ADDR_MASK);
		if (!mm_owns_pt_page(mm, l3)) {
			l3 = dup_pt_page(mm, l3);
			if (!l3)
				return -5;
			mm->pml4[l4i] = (uint64_t)(uintptr_t)l3 |
					(e4 & 0xfffULL);
		}
		mm->pml4[l4i] |= PG_PRESENT | PG_RW | PG_US;
	}

	e3 = l3[l3i];
	if ((e3 & (PG_PRESENT | PG_PS_2M)) ==
	    (PG_PRESENT | PG_PS_2M)) {
		if (split_l3_1g_to_l2(mm, l3, l3i))
			return -6;
		e3 = l3[l3i];
	}
	if (!(e3 & PG_PRESENT)) {
		l2 = alloc_pt_page(mm);
		if (!l2)
			return -7;
		l3[l3i] = (uint64_t)(uintptr_t)l2 |
			  PG_PRESENT | PG_RW | PG_US;
	} else {
		if (!pt_page_pa_ok(e3))
			return -8;
		l2 = (uint64_t *)(uintptr_t)(e3 & PG_ADDR_MASK);
		if (!mm_owns_pt_page(mm, l2)) {
			l2 = dup_pt_page(mm, l2);
			if (!l2)
				return -9;
			l3[l3i] = (uint64_t)(uintptr_t)l2 |
				  (e3 & 0xfffULL);
		}
		l3[l3i] |= PG_PRESENT | PG_RW | PG_US;
	}

	e2 = l2[l2i];
	if ((e2 & (PG_PRESENT | PG_PS_2M)) ==
	    (PG_PRESENT | PG_PS_2M)) {
		if (split_2m_to_4k(mm, l2, l2i, va))
			return -10;
		e2 = l2[l2i];
	}
	if (!(e2 & PG_PRESENT)) {
		l1 = alloc_pt_page(mm);
		if (!l1)
			return -11;
		l2[l2i] = (uint64_t)(uintptr_t)l1 |
			  PG_PRESENT | PG_RW | PG_US;
	} else {
		if (!pt_page_pa_ok(e2))
			return -12;
		l1 = (uint64_t *)(uintptr_t)(e2 & PG_ADDR_MASK);
		if (!mm_owns_pt_page(mm, l1)) {
			l1 = dup_pt_page(mm, l1);
			if (!l1)
				return -13;
			l2[l2i] = (uint64_t)(uintptr_t)l1 |
				  (e2 & 0xfffULL);
		}
		l2[l2i] |= PG_PRESENT | PG_RW | PG_US;
	}

	old = l1[l1i];
	l1[l1i] = (pa & PG_ADDR_MASK) |
		  (flags & ~(PG_PS_2M | PG_PRESENT)) | PG_PRESENT | PG_US;
	if (old & PG_SOFT_OWNED) {
		uint64_t old_pa = old & PG_ADDR_MASK;

		if (old_pa != (pa & PG_ADDR_MASK))
			frame_release(old_pa);
	}
	return 0;
}

int mm_map_user_page(mm_t *mm, uint64_t va, uint64_t pa,
		     uint64_t flags)
{
	mm_dm_ctx_t dm;
	int ret;

	dm = mm_enter_direct_map();
	ret = mm_map_user_page_locked(mm, va, pa, flags);
	mm_leave_direct_map(dm);
	return ret;
}

/* Ensure child mm has a private page-table path to `va` (dup shared levels vs share_l4).
 * Caller must hold the direct-map CR3. */
static int mm_fork_private_pt_path(mm_t *mm, uint64_t *share_l4, uint64_t va,
                                   uint64_t **out_l2, int *out_l2i, uint64_t **out_l1) {
    if (!mm || !mm->pml4 || !share_l4 || !out_l2 || !out_l2i || !out_l1) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;

    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);

    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return -1;

    uint64_t ent4 = mm->pml4[l4i];
    uint64_t *l3 = NULL;
    if (ent4 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent4)) return -1;
        l3 = (uint64_t *)(uintptr_t)(ent4 & ~0xFFFULL);
        if ((ent4 & ~0xFFFULL) == (se4 & ~0xFFFULL)) {
            uint64_t *n3 = dup_pt_page(mm, l3);
            if (!n3) return -1;
            l3 = n3;
            mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFFULL);
        }
    } else {
        return -1;
    }

    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    uint64_t ent3 = l3[l3i];
    if (!(ent3 & PG_PRESENT)) return -1;
    if ((ent3 & PG_PS_2M) || (se3 & PG_PS_2M)) {
        if (split_l3_1g_to_l2(mm, l3, l3i) != 0) return -1;
        ent3 = l3[l3i];
    }
    if (ent3 & PG_PS_2M) return -1;

    uint64_t *l2 = NULL;
    if (ent3 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent3)) return -1;
        l2 = (uint64_t *)(uintptr_t)(ent3 & ~0xFFFULL);
        if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3) &&
            (ent3 & ~0xFFFULL) == (se3 & ~0xFFFULL)) {
            uint64_t *n2 = dup_pt_page(mm, l2);
            if (!n2) return -1;
            l2 = n2;
            l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
        }
    } else {
        return -1;
    }

    uint64_t se2 = 0;
    if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3)) {
        uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
        se2 = share_l2[l2i];
    }

    uint64_t ent2 = l2[l2i];
    if (!(ent2 & PG_PRESENT)) return -1;
    if (ent2 & PG_PS_2M) {
        *out_l2 = l2;
        *out_l2i = l2i;
        *out_l1 = NULL;
        return 0;
    }

    uint64_t *l1 = (uint64_t *)(uintptr_t)(ent2 & ~0xFFFULL);
    if (!pt_page_pa_ok(ent2)) return -1;
    if ((se2 & PG_PRESENT) && !(se2 & PG_PS_2M) && pt_page_pa_ok(se2) &&
        (ent2 & ~0xFFFULL) == (se2 & ~0xFFFULL)) {
        uint64_t *n1 = dup_pt_page(mm, l1);
        if (!n1) return -1;
        l1 = n1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ent2 & 0xFFFULL);
    }

    *out_l2 = l2;
    *out_l2i = l2i;
    *out_l1 = l1;
    return 0;
}

int mm_clear_range_private(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;

    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    for (uint64_t va = begin; va < end; ) {
        uint64_t *l2 = NULL;
        int l2i = 0;
        uint64_t *l1 = NULL;
        if (mm_fork_private_pt_path(mm, share_l4, va, &l2, &l2i, &l1) != 0) {
            va += 0x1000ULL;
            continue;
        }
        uint64_t ent2 = l2[l2i];
        uint64_t page2m_lo = va & ~((uint64_t)PAGE_SIZE_2M - 1ULL);
        uint64_t page2m_hi = page2m_lo + PAGE_SIZE_2M;
        if (ent2 & PG_PS_2M) {
            if (begin <= page2m_lo && end >= page2m_hi) {
                l2[l2i] = 0;
                invlpg((void *)(uintptr_t)page2m_lo);
                va = page2m_hi;
                continue;
            }
            if (split_2m_to_4k(mm, l2, l2i, va) != 0) {
                mm_leave_direct_map(dm);
                return -1;
            }
            if (mm_fork_private_pt_path(mm, share_l4, va, &l2, &l2i, &l1) != 0) {
                mm_leave_direct_map(dm);
                return -1;
            }
            ent2 = l2[l2i];
            if (ent2 & PG_PS_2M) {
                mm_leave_direct_map(dm);
                return -1;
            }
        }
        if (l1) {
            int l1i = (int)((va >> 12) & 0x1FF);
            l1[l1i] = 0;
            invlpg((void *)(uintptr_t)va);
        }
        va += 0x1000ULL;
    }
    mm_leave_direct_map(dm);
    return 0;
}

/*
 * Remove user mappings from one mm without modifying page tables shared with
 * the fork parent or swapper.  Linux munmap drops one mapping reference for
 * every removed frame; mmput must not be the first place that releases it.
 *
 * The retained supervisor identity map is an AxonOS kernel implementation
 * detail, not a userspace mapping.  Do not punch holes in it unless the leaf
 * is user-accessible.
 */
int mm_unmap_user_range(mm_t *mm, uint64_t *share_l4,
                        uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4 || !share_l4 || mm == mm_kernel())
        return -1;
    if (va_end <= va_begin)
        return 0;
    if (va_begin < 0x200000ULL)
        va_begin = 0x200000ULL;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT)
        va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end)
        return 0;

    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    /* Caller's CR3: invlpg must hit the process TLB, not swapper's. */
    uint64_t caller_cr3 = paging_read_cr3();
    uint64_t mm_cr3 = mm->cr3 & ~0xFFFULL;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;

    /*
     * Preparation pass: make every page-table path exclusive and perform all
     * required huge-page splits before clearing a single leaf.  A failure may
     * leave equivalent (split/private) tables behind, but never a half-unmapped
     * VMA.
     */
    /*
     * Use mm_va_leaf_pa (not mm_user_leaf_pa): mm_demote_user_identity clears
     * PG_US on the mmap window. Requiring US made unmap a no-op success while
     * leaving demoted identity leaves mapped — pthread stacks then saw RAM
     * garbage (musl cancelbuf → #GP on non-canonical rax).
     */
    for (uint64_t va = begin; va < end; ) {
        uint64_t mapped_pa = 0;
        if (mm_va_leaf_pa(mm, va, &mapped_pa) != 0) {
            va += PAGE_SIZE_4K;
            continue;
        }
        uint64_t *l2 = NULL;
        int l2i = 0;
        uint64_t *l1 = NULL;
        if (mm_fork_private_pt_path(mm, share_l4, va,
                                    &l2, &l2i, &l1) != 0)
            goto out;

        uint64_t ent2 = l2[l2i];
        uint64_t page2m_lo = va & ~((uint64_t)PAGE_SIZE_2M - 1ULL);
        uint64_t page2m_hi = page2m_lo + PAGE_SIZE_2M;
        if (ent2 & PG_PS_2M) {
            if (ent2 & PG_SOFT_OWNED)
                goto out; /* Owned huge frames have no allocator contract. */
            if (begin <= page2m_lo && end >= page2m_hi) {
                va = page2m_hi;
                continue;
            }
            if (split_2m_to_4k(mm, l2, l2i, va) != 0)
                goto out;
        }
        va += PAGE_SIZE_4K;
    }

    /* Commit pass: no allocations or fallible splits remain. */
    for (uint64_t va = begin; va < end; ) {
        uint64_t mapped_pa = 0;
        if (mm_va_leaf_pa(mm, va, &mapped_pa) != 0) {
            va += PAGE_SIZE_4K;
            continue;
        }
        uint64_t *l2 = NULL;
        int l2i = 0;
        uint64_t *l1 = NULL;
        if (mm_fork_private_pt_path(mm, share_l4, va,
                                    &l2, &l2i, &l1) != 0)
            goto out;
        uint64_t ent2 = l2[l2i];
        uint64_t page2m_lo = va & ~((uint64_t)PAGE_SIZE_2M - 1ULL);
        uint64_t page2m_hi = page2m_lo + PAGE_SIZE_2M;
        if (ent2 & PG_PS_2M) {
            /*
             * Only drop a whole 2MiB leaf when the unmap span covers it.
             * Partial clears must stay 4K — wiping the huge leaf destroyed
             * sibling anon pages (curl TLS body) → write(stdout) EFAULT →
             * curl error 23 ("passed N returned 0").
             */
            if (ent2 & PG_SOFT_OWNED)
                goto out;
            if (begin <= page2m_lo && end >= page2m_hi) {
                l2[l2i] = 0;
                if ((caller_cr3 & ~0xFFFULL) == mm_cr3) {
                    paging_write_cr3(caller_cr3);
                    invlpg((void *)(uintptr_t)page2m_lo);
                    paging_write_cr3(mm_direct_map_cr3());
                }
                va = page2m_hi;
                continue;
            }
            if (split_2m_to_4k(mm, l2, l2i, va) != 0)
                goto out;
            if (mm_fork_private_pt_path(mm, share_l4, va,
                                        &l2, &l2i, &l1) != 0)
                goto out;
            ent2 = l2[l2i];
            if (ent2 & PG_PS_2M)
                goto out;
        }
        if (l1) {
            int l1i = (int)((va >> 12) & 0x1FF);
            uint64_t old = l1[l1i];
            if (old & PG_PRESENT) {
                uint64_t old_pa = old & PG_ADDR_MASK;
                l1[l1i] = 0;
                if ((caller_cr3 & ~0xFFFULL) == mm_cr3) {
                    paging_write_cr3(caller_cr3);
                    invlpg((void *)(uintptr_t)va);
                    paging_write_cr3(mm_direct_map_cr3());
                }
                if (old & PG_SOFT_OWNED)
                    frame_release(old_pa);
            }
        }
        va += PAGE_SIZE_4K;
    }
    rc = 0;
out:
    mm_leave_direct_map(dm);
    return rc;
}

static int mm_privatize_identity_range_ex(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                          int seed_from_live) {
    if (!mm || !mm->pml4 || mm == mm_kernel())
        return -1;
    mm_dbg_ash_touch(seed_from_live ? "privatize-seed" : "privatize-blank",
                     mm, va_begin, va_end);
    /* Share baseline: oldmm during exec load; otherwise swapper (mm_kernel). */
    mm_t *share = mm_kernel();
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        if (t && t->mm_ptemplate && t->mm_ptemplate->pml4)
            share = t->mm_ptemplate;
    }
    if (!share || !share->pml4)
        return -1;
    if (va_end <= va_begin)
        return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT)
        va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (begin >= end)
        return 0;

    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t pa = 0;
        if (mm_va_leaf_pa(mm, va, &pa) != 0)
            continue;
        pa &= ~0xFFFULL;
        /* Already a real private frame — do not replace with an identity copy. */
        if (pa != (va & ~0xFFFULL))
            continue;
        /*
         * Anon blank (do_brk_flags) must not wipe fork Soft_COW leaves — those
         * still carry parent content until mm_cow_fault_page. Skip them here.
         */
        if (!seed_from_live) {
            int l4i = (int)((va >> 39) & 0x1FF);
            int l3i = (int)((va >> 30) & 0x1FF);
            int l2i = (int)((va >> 21) & 0x1FF);
            int l1i = (int)((va >> 12) & 0x1FF);
            uint64_t e4 = mm->pml4[l4i];
            if ((e4 & PG_PRESENT) && !(e4 & PG_PS_2M) && pt_page_pa_ok(e4)) {
                uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
                uint64_t e3 = l3[l3i];
                if ((e3 & PG_PRESENT) && !(e3 & PG_PS_2M) && pt_page_pa_ok(e3)) {
                    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
                    uint64_t e2 = l2[l2i];
                    if ((e2 & (PG_PRESENT | PG_PS_2M | PG_SOFT_COW)) ==
                        (PG_PRESENT | PG_PS_2M | PG_SOFT_COW))
                        continue;
                    if ((e2 & PG_PRESENT) && !(e2 & PG_PS_2M) && pt_page_pa_ok(e2)) {
                        uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
                        if (l1[l1i] & PG_SOFT_COW)
                            continue;
                    }
                }
            }
        }

        void *newp = mm_user_frame_alloc(!seed_from_live);
        if (!newp)
            goto out;
        if (((uint64_t)(uintptr_t)newp & ~0xFFFULL) == (va & ~0xFFFULL)) {
            mm_user_frame_put(newp);
            goto out;
        }
        if (seed_from_live) {
            /*
             * Identity PA==VA may be a hole under swapper (USER_MMAP demote /
             * PROT_NONE) while still present in this mm. Seed under the process
             * L4 — never memcpy from identity through the direct-map CR3.
             */
            if (pa == (va & ~0xFFFULL)) {
                uint64_t proc = (uint64_t)(uintptr_t)mm->pml4;
                paging_write_cr3(proc);
                memcpy(newp, (void *)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
                paging_write_cr3(mm_direct_map_cr3());
            } else {
                memcpy(newp, (void *)(uintptr_t)pa, (size_t)PAGE_SIZE_4K);
            }
        }
        if (mm_map_4k_sharedaware(mm, share->pml4, va, (uint64_t)(uintptr_t)newp,
                                  PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
            mm_user_frame_put(newp);
            goto out;
        }
        {
            uint64_t got = 0;
            if (mm_va_leaf_pa(mm, va, &got) != 0 ||
                (got & ~0xFFFULL) == (va & ~0xFFFULL) ||
                (got & ~0xFFFULL) != ((uint64_t)(uintptr_t)newp & ~0xFFFULL)) {
                kprintf("ident-priv-bug: va=0x%llx want=0x%llx got=0x%llx\n",
                        (unsigned long long)va,
                        (unsigned long long)(uintptr_t)newp,
                        (unsigned long long)got);
                goto out;
            }
        }
        invlpg((void *)(uintptr_t)va);
    }
    rc = 0;
out:
    /* Always reload caller CR3 so identity→private leaf updates flush TLBs. */
    mm_leave_direct_map(dm);
    return rc;
}

int mm_privatize_identity_range(mm_t *mm, uint64_t va_begin, uint64_t va_end) {
    return mm_privatize_identity_range_ex(mm, va_begin, va_end, 1);
}

int mm_privatize_identity_range_blank(mm_t *mm, uint64_t va_begin, uint64_t va_end) {
    return mm_privatize_identity_range_ex(mm, va_begin, va_end, 0);
}

void mm_init(void) {
    if (g_mm_ready)
        return;
    frame_init();
    memset(&g_kernel_mm, 0, sizeof(g_kernel_mm));
    g_kernel_mm.cr3 = paging_read_cr3();
    g_kernel_mm.pml4 = (uint64_t *)(uintptr_t)(g_kernel_mm.cr3 & ~0xFFFULL);
    g_kernel_mm.pml4_alloc_raw = NULL;
    g_kernel_mm.refcount = 1;
    g_mm_ready = 1;
}

mm_t *mm_kernel(void) {
    if (!g_mm_ready) mm_init();
    return &g_kernel_mm;
}

mm_t *mm_retain(mm_t *mm) {
    if (!mm) return mm_kernel();
    if (mm->refcount <= 0) mm->refcount = 1;
    else mm->refcount++;
    return mm;
}

/*
 * Drop this mm's reference to every refcounted user leaf.  Limiting this to
 * PG_SOFT_COW was wrong: after one side faults, the new RW leaf is still a
 * frame-owned mapping and must be released at mmput.  Conversely, user frames
 * must never appear in mm->allocs or mmput would kfree them while a fork peer
 * still maps them.
 */
static void mm_release_user_frames(mm_t *mm) {
    if (!mm || !mm->pml4 || mm == &g_kernel_mm)
        return;
    /*
     * PT pages are reached by casting PTE PAs to VAs.  After Soft_COW punches
     * identity holes in a process CR3 (e.g. Go PROT_NONE / ELF scrub), those
     * PAs may be unmapped under the current CR3 — seen as Oops in this walker
     * at CR2≈0x841000 while reaping wget/apm after clone.  Walk under swapper
     * with IF=0, same as mm_fork_private_pt_path.
     *
     * Pulse IF every so often: a failed fork can leave hundreds of Soft_OWNED
     * leaves; holding cli across the whole walk freezes the machine (no Ctrl+C)
     * after thread_stop.  Also never frame_release a PA that backs this mm's
     * page tables (identity alias of a PT page).
     */
    mm_dm_ctx_t dm = mm_enter_direct_map();
    unsigned progress = 0;
    uint64_t *l4 = mm->pml4;
    for (int l4i = 0; l4i < 512; ++l4i) {
        uint64_t e4 = l4[l4i];
        if (!(e4 & PG_PRESENT) || !pt_page_pa_ok(e4))
            continue;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
        for (int l3i = 0; l3i < 512; ++l3i) {
            uint64_t e3 = l3[l3i];
            if (!(e3 & PG_PRESENT) || (e3 & PG_PS_2M) || !pt_page_pa_ok(e3))
                continue;
            uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
            for (int l2i = 0; l2i < 512; ++l2i) {
                uint64_t e2 = l2[l2i];
                if (!(e2 & PG_PRESENT))
                    continue;
                if (e2 & PG_PS_2M) {
                    /*
                     * PG_SOFT_OWNED is a 4K-frame contract.  Releasing only
                     * the base of an alleged owned 2M leaf corrupts the frame
                     * allocator; leak the impossible mapping safely instead.
                     */
                    continue;
                }
                if (!pt_page_pa_ok(e2))
                    continue;
                uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
                for (int l1i = 0; l1i < 512; ++l1i) {
                    uint64_t e1 = l1[l1i];
                    if ((e1 & (PG_PRESENT | PG_US | PG_SOFT_OWNED)) !=
                        (PG_PRESENT | PG_US | PG_SOFT_OWNED)) {
                        if (++progress >= 512u) {
                            progress = 0;
                            mm_leave_direct_map(dm);
                            dm = mm_enter_direct_map();
                        }
                        continue;
                    }
                    uint64_t pa = e1 & PG_ADDR_MASK;
                    if (mm_owns_pt_page(mm, (const uint64_t *)(uintptr_t)pa))
                        continue;
                    frame_release(pa);
                    if (++progress >= 64u) {
                        progress = 0;
                        mm_leave_direct_map(dm);
                        dm = mm_enter_direct_map();
                    }
                }
            }
        }
    }
    mm_leave_direct_map(dm);
}

void mm_release(mm_t *mm) {
    if (!mm) return;
    if (mm == &g_kernel_mm) return;
    if (mm->refcount <= 0) return;
    mm->refcount--;
    if (mm->refcount == 0) {
        mm_release_user_frames(mm);
        /* Free page-table allocations only; user leaves are frame-owned. */
        mm_alloc_node_t *n = (mm_alloc_node_t*)mm->allocs;
        while (n) {
            mm_alloc_node_t *nx = n->next;
            if (n->raw) kfree(n->raw);
            kfree(n);
            n = nx;
        }
        if (mm->vma_storage)
            kfree(mm->vma_storage);
        if (mm->pml4_alloc_raw) kfree(mm->pml4_alloc_raw);
        kfree(mm);
    }
}

mm_t *mm_clone_current(void) {
    if (!g_mm_ready) mm_init();
    mm_t *m = (mm_t*)kmalloc(sizeof(mm_t));
    if (!m) return NULL;
    memset(m, 0, sizeof(*m));

    void *raw = kmalloc((size_t)PAGE_SIZE_4K + (size_t)PAGE_SIZE_4K);
    if (!raw) {
        kfree(m);
        return NULL;
    }
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)PAGE_SIZE_4K - 1u) & ~((uintptr_t)PAGE_SIZE_4K - 1u);
    uint64_t *new_l4 = (uint64_t*)aligned;
    uint64_t cur_cr3 = paging_read_cr3();
    uint64_t *src_l4 = (uint64_t*)(uintptr_t)(cur_cr3 & ~0xFFFULL);
    if (!src_l4) {
        kfree(raw);
        kfree(m);
        return NULL;
    }
    mm_dm_ctx_t dm = mm_enter_direct_map();
    memcpy(new_l4, (void*)src_l4, (size_t)PAGE_SIZE_4K);
    mm_leave_direct_map(dm);

    m->pml4 = new_l4;
    m->cr3 = (uint64_t)(uintptr_t)new_l4;
    m->pml4_alloc_raw = raw;
    m->refcount = 1;
    return m;
}

/* Clone page tables from an explicit mm (not live CR3). Fork must use this:
 * a prior helper may have left CR3 on the kernel tree, and cloning that gives
 * the child no user mappings → later COW/privatize fails with ENOMEM. */
mm_t *mm_clone_from(mm_t *src) {
    if (!g_mm_ready) mm_init();
    if (!src || !src->pml4)
        return mm_clone_current();
    uint64_t src_cr3 = src->cr3 ? src->cr3 : (uint64_t)(uintptr_t)src->pml4;
    if (!src_cr3 || (src_cr3 & ~0xFFFULL) >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return mm_clone_current();

    mm_t *m = (mm_t *)kmalloc(sizeof(mm_t));
    if (!m) return NULL;
    memset(m, 0, sizeof(*m));

    void *raw = kmalloc((size_t)PAGE_SIZE_4K + (size_t)PAGE_SIZE_4K);
    if (!raw) {
        kfree(m);
        return NULL;
    }
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)PAGE_SIZE_4K - 1u) & ~((uintptr_t)PAGE_SIZE_4K - 1u);
    uint64_t *new_l4 = (uint64_t *)aligned;
    uint64_t *src_l4 = (uint64_t *)(uintptr_t)(src_cr3 & ~0xFFFULL);
    mm_dm_ctx_t dm = mm_enter_direct_map();
    memcpy(new_l4, src_l4, (size_t)PAGE_SIZE_4K);
    mm_leave_direct_map(dm);

    m->pml4 = new_l4;
    m->cr3 = (uint64_t)(uintptr_t)new_l4;
    m->pml4_alloc_raw = raw;
    m->refcount = 1;
    return m;
}

/*
 * Linux mm_alloc / init_new_context: nascent mm must not expose bootstrap
 * identity as *user* memory. AxonOS still needs low identity PRESENT under
 * process CR3 for kernel phys and some stack tip VA pokes — unmapping the
 * stack slot or punching split holes oopses boot (CR2=0x3fffxxxx).
 *
 * Policy (incremental Linux):
 *  - User window: keep PRESENT, strip PG_US (ring3 cannot use identity).
 *  - Brk slab [MM_ASH_WATCH_LO, MM_ASH_WATCH_HI): unmap identity (no parent
 *    phys alias at 0x801738).
 *  - Stack: stays present|~US until setup_arg_pages; tip pages become private
 *    via bulk_zero + exec_map_stack_tip fail-closed (not identity / not oldmm).
 */
int mm_demote_user_identity(mm_t *mm) {
    if (!mm || !mm->pml4 || mm == &g_kernel_mm)
        return -1;
    mm_t *k = mm_kernel();
    if (!k || !k->pml4 || (uintptr_t)mm->pml4 == (uintptr_t)k->pml4)
        return -1;

    uint64_t lo = 0x200000ULL;
    uint64_t hi = (uint64_t)USER_STACK_TOP;
    if (hi > (uint64_t)MMIO_IDENTITY_LIMIT)
        hi = (uint64_t)MMIO_IDENTITY_LIMIT;
    uintptr_t hlo = heap_base_addr();
    uintptr_t hhi = heap_region_end_exclusive();
    const uint64_t brk_unmap_lo = MM_ASH_WATCH_LO;
    const uint64_t brk_unmap_hi = MM_ASH_WATCH_HI;

    /*
     * Walk one L2 table at a time (1GiB / 512×2MiB). Dup shared L3/L2 once,
     * then strip PG_US on every leaf in-range — not once per 2MiB with full
     * L4→L3→L2 rewalk (that dominated mm_alloc/execve).
     */
    for (uint64_t l2_base = lo & ~((1ULL << 30) - 1ULL); l2_base < hi;
         l2_base += (1ULL << 30)) {
        uint64_t range_lo = l2_base < lo ? lo : l2_base;
        uint64_t range_hi = l2_base + (1ULL << 30);
        if (range_hi > hi)
            range_hi = hi;
        if (range_lo >= range_hi)
            continue;
        if (hlo && hhi > hlo && range_lo >= (uint64_t)hlo && range_hi <= (uint64_t)hhi)
            continue;

        int l4i = (int)((range_lo >> 39) & 0x1FF);
        int l3i = (int)((range_lo >> 30) & 0x1FF);

        uint64_t ke4 = k->pml4[l4i];
        uint64_t e4 = mm->pml4[l4i];
        if (!(e4 & PG_PRESENT) || !pt_page_pa_ok(e4))
            continue;
        if (mm_pte_same_pt_page(e4, ke4)) {
            uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
            uint64_t *n3 = dup_pt_page(mm, l3);
            if (!n3)
                return -1;
            mm->pml4[l4i] = ((uint64_t)(uintptr_t)n3) | (e4 & 0xFFFULL);
            e4 = mm->pml4[l4i];
        }

        uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
        uint64_t e3 = l3[l3i];
        if (!(e3 & PG_PRESENT) || !pt_page_pa_ok(e3))
            continue;
        if (e3 & PG_PS_2M)
            continue;

        uint64_t ke3 = 0;
        if ((ke4 & PG_PRESENT) && !(ke4 & PG_PS_2M) && pt_page_pa_ok(ke4)) {
            uint64_t *kl3 = (uint64_t *)(uintptr_t)(ke4 & ~0xFFFULL);
            ke3 = kl3[l3i];
        }
        if (mm_pte_same_pt_page(e3, ke3)) {
            uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
            uint64_t *n2 = dup_pt_page(mm, l2);
            if (!n2)
                return -1;
            l3[l3i] = ((uint64_t)(uintptr_t)n2) | (e3 & 0xFFFULL);
            e3 = l3[l3i];
        }

        uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
        int l2i_begin = (int)((range_lo >> 21) & 0x1FF);
        int l2i_end = (int)(((range_hi - 1ULL) >> 21) & 0x1FF);
        for (int l2i = l2i_begin; l2i <= l2i_end; l2i++) {
            uint64_t va = l2_base + ((uint64_t)l2i << 21);
            if (va < lo || va >= hi)
                continue;
            if (hlo && hhi > hlo && va >= (uint64_t)hlo && va < (uint64_t)hhi)
                continue;
            int unmap_identity =
                (va < brk_unmap_hi && (va + PAGE_SIZE_2M) > brk_unmap_lo);

            uint64_t e2 = l2[l2i];
            if (!(e2 & PG_PRESENT))
                continue;
            if (e2 & PG_PS_2M) {
                uint64_t pa2 = e2 & ~(PAGE_SIZE_2M - 1ULL);
                if (unmap_identity && pa2 == va)
                    l2[l2i] = 0;
                else
                    l2[l2i] = e2 & ~PG_US;
                continue;
            }
            if (!pt_page_pa_ok(e2))
                continue;
            uint64_t ke2 = 0;
            if ((ke3 & PG_PRESENT) && !(ke3 & PG_PS_2M) && pt_page_pa_ok(ke3)) {
                uint64_t *kl2 = (uint64_t *)(uintptr_t)(ke3 & ~0xFFFULL);
                ke2 = kl2[l2i];
            }
            if (mm_pte_same_pt_page(e2, ke2) ||
                !mm_owns_pt_page(mm, (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL))) {
                uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
                uint64_t *n1 = dup_pt_page(mm, l1);
                if (!n1)
                    return -1;
                l2[l2i] = ((uint64_t)(uintptr_t)n1) | (e2 & 0xFFFULL);
                e2 = l2[l2i];
            }
            uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
            for (int i = 0; i < 512; i++) {
                uint64_t e1 = l1[i];
                if (!(e1 & PG_PRESENT))
                    continue;
                uint64_t p1 = e1 & ~0xFFFULL;
                uint64_t page_va = va + ((uint64_t)i << 12);
                if (unmap_identity && p1 == page_va &&
                    page_va >= brk_unmap_lo && page_va < brk_unmap_hi)
                    l1[i] = 0;
                else
                    l1[i] = e1 & ~PG_US;
            }
        }
    }
    return 0;
}

mm_t *mm_alloc(void) {
    /* Linux mm_alloc() + init_new_context(): clone swapper_pg_dir, then make
     * the user VA window non-user identity (do_mmap/do_brk install anon). */
    if (!g_mm_ready)
        mm_init();
    mm_t *m = mm_clone_from(mm_kernel());
    if (!m)
        return NULL;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int ret = mm_demote_user_identity(m);
    mm_leave_direct_map(dm);
    if (ret != 0) {
        kprintf("mm_alloc: demote user identity failed\n");
        mm_release(m);
        return NULL;
    }
    return m;
}

int mm_switch(mm_t *mm) {
    if (!g_mm_ready) mm_init();
    mm_t *target = mm ? mm : &g_kernel_mm;
    if (mm) {
        uintptr_t ma = (uintptr_t)mm;
        if (ma < 0x1000u || ma + sizeof(mm_t) > (uintptr_t)MMIO_IDENTITY_LIMIT) {
            klogprintf("mm_switch: bad mm %p, using kernel mm\n", (void *)mm);
            target = &g_kernel_mm;
        }
    }
    uint64_t want = target->cr3 ? target->cr3 : (uint64_t)(uintptr_t)target->pml4;
    if (want == 0) want = g_kernel_mm.cr3;
    uint64_t cur = paging_read_cr3();
    if (cur != want) {
        paging_write_cr3(want);
    }
    return 0;
}

/*
 * Leave `dead` before mm_release frees its page tables.
 * Prefer another live task mm; otherwise activate swapper (mm_kernel).
 */
int mm_switch_away_from(mm_t *dead) {
    if (!g_mm_ready) mm_init();
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || !t->mm || t->mm == dead)
            continue;
        if (!t->mm->pml4)
            continue;
        uint64_t cr3 = t->mm->cr3 ? t->mm->cr3 : (uint64_t)(uintptr_t)t->mm->pml4;
        if (!cr3 || cr3 >= (uint64_t)MMIO_IDENTITY_LIMIT)
            continue;
        if ((paging_read_cr3() & ~0xFFFULL) == (cr3 & ~0xFFFULL))
            return 0;
        paging_write_cr3(cr3);
        return 0;
    }
    if (dead != &g_kernel_mm)
        return mm_switch(&g_kernel_mm);
    return -1;
}

/* 0 absent, 1 present read-only user, 2 present writable user (4K or 2MiB). */
static int mm_share_pte_class(uint64_t *share_l4, uint64_t va) {
    if (!share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT)) return 0;
    if (se3 & PG_PS_2M) {
        if (!(se3 & PG_US)) {
            if (se3 & PG_RW) return 2;
            return 0;
        }
        return (se3 & PG_RW) ? 2 : 1;
    }
    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT)) return 0;
    if (se2 & PG_PS_2M) {
        if (!(se2 & PG_US)) {
            if (se2 & PG_RW) return 2;
            return 0;
        }
        return (se2 & PG_RW) ? 2 : 1;
    }
    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if (!(se1 & PG_PRESENT)) return 0;
    if (!(se1 & PG_US)) {
        if (se1 & PG_RW) return 2;
        return 0;
    }
    return (se1 & PG_RW) ? 2 : 1;
}

static int mm_share_pte_user_writable(uint64_t *share_l4, uint64_t va) {
    if (!share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT)) return 0;
    if (se3 & PG_PS_2M)
        return ((se3 & (PG_US | PG_RW)) == (PG_US | PG_RW));
    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT)) return 0;
    if (se2 & PG_PS_2M)
        return ((se2 & (PG_US | PG_RW)) == (PG_US | PG_RW));
    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if (!(se1 & PG_PRESENT)) return 0;
    return ((se1 & (PG_US | PG_RW)) == (PG_US | PG_RW));
}

static int mm_share_pte_user_writable_pa(uint64_t *share_l4, uint64_t va, uint64_t *out_pa, uint64_t *out_flags) {
    if (!share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t off4k = va & 0xFFFULL;
    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT)) return 0;
    if (se3 & PG_PS_2M) {
        /* Linux COW only private user mappings — never supervisor identity. */
        if ((se3 & (PG_US | PG_RW)) != (PG_US | PG_RW)) return 0;
        if (out_pa) *out_pa = (se3 & PG_ADDR_MASK_1G) +
                              (va & 0x3FFFFFFFULL);
        if (out_flags) *out_flags = se3;
        return 1;
    }
    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT)) return 0;
    if (se2 & PG_PS_2M) {
        if ((se2 & (PG_US | PG_RW)) != (PG_US | PG_RW)) return 0;
        if (out_pa) *out_pa = (se2 & PG_ADDR_MASK_2M) +
                              (va & (PAGE_SIZE_2M - 1ULL));
        if (out_flags) *out_flags = se2;
        return 1;
    }
    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if (!(se1 & PG_PRESENT)) return 0;
    if ((se1 & (PG_US | PG_RW)) != (PG_US | PG_RW)) return 0;
    if (out_pa) *out_pa = (se1 & PG_ADDR_MASK) + off4k;
    if (out_flags) *out_flags = se1;
    return 1;
}

/* Nested fork must retain pages that are already read-only fork-COW. */
static int mm_share_pte_user_cowable_pa(uint64_t *share_l4, uint64_t va,
                                        uint64_t *out_pa, uint64_t *out_flags) {
    if (mm_share_pte_user_writable_pa(share_l4, va, out_pa, out_flags))
        return 1;
    if (!share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT) || (se3 & PG_PS_2M) || !pt_page_pa_ok(se3)) return 0;
    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT) || (se2 & PG_PS_2M) || !pt_page_pa_ok(se2)) return 0;
    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if ((se1 & (PG_PRESENT | PG_US | PG_SOFT_COW | PG_RW)) !=
        (PG_PRESENT | PG_US | PG_SOFT_COW))
        return 0;
    if (out_pa) *out_pa = (se1 & PG_ADDR_MASK) + (va & 0xFFFULL);
    if (out_flags) *out_flags = se1;
    return 1;
}

int mm_cow_mark_user_readonly_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t pa = 0, flags = 0;
        if (!mm_share_pte_user_writable_pa(share_l4, va, &pa, &flags)) continue;
        flags &= (PG_PRESENT | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
        flags &= ~(PG_RW | PG_PS_2M);
        flags |= PG_US;
        if (mm_map_4k_sharedaware(mm, share_l4, va, pa, flags) != 0)
            return -1;
    }
    return 0;
}

static int mm_mark_share_user_readonly_page(mm_t *owner, uint64_t *share_l4, uint64_t va) {
    if (!owner || !owner->pml4 || !share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;

    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);

    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT)) return 0;
    if (se3 & PG_PS_2M) {
        if (!(se3 & PG_RW)) return 0;
        if (split_l3_1g_to_l2(owner, share_l3, l3i) != 0) return -1;
        se3 = share_l3[l3i];
    }
    if (!pt_page_pa_ok(se3) || (se3 & PG_PS_2M)) return -1;

    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT)) return 0;
    if (se2 & PG_PS_2M) {
        if (!(se2 & PG_RW)) return 0;
        if (split_2m_to_4k(owner, share_l2, l2i, va) != 0) return -1;
        se2 = share_l2[l2i];
    }
    if (!pt_page_pa_ok(se2) || (se2 & PG_PS_2M)) return -1;

    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if ((se1 & (PG_PRESENT | PG_US | PG_SOFT_OWNED)) ==
        (PG_PRESENT | PG_US | PG_SOFT_OWNED)) {
        /*
         * A write-protected user page is not necessarily a fork-COW page:
         * ELF RELRO and mprotect(PROT_READ) must remain read-only.  Record
         * COW explicitly in a software-available PTE bit so #PF can tell the
         * difference without guessing from error_code == PF_USER|PF_WRITE.
         */
        share_l4[l4i] |= PG_US;
        share_l3[l3i] |= PG_US;
        share_l2[l2i] |= PG_US;
        share_l1[l1i] = (se1 & ~PG_RW) | PG_US | PG_SOFT_COW;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

/*
 * Linux copy_page_range: share PA, write-protect both peers (Soft_COW).
 * After mm_clone_from (shallow L4), skipping a cowable leaf leaves shared
 * PG_RW — child dirties parent brk (ash GPF at RIP=="ls" @ 0x801738).
 * Fail closed on frame ownership, map, or parent-WP failure.
 */
int mm_cow_mark_user_readonly_pair_l4(mm_t *child, mm_t *parent, uint64_t *parent_l4,
                                      uint64_t va_begin, uint64_t va_end) {
    if (!child || !parent || !child->pml4 || !parent->pml4 || !parent_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t pa = 0, flags = 0;
        if (!mm_share_pte_user_cowable_pa(parent_l4, va, &pa, &flags))
            continue;
        if (frame_retain(pa) != 0) {
            devel_printf("cow: unowned user frame va=0x%llx pa=0x%llx\n",
                    (unsigned long long)va,
                    (unsigned long long)(pa & ~0xFFFULL));
            return -1;
        }
        flags &= (PG_PRESENT | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
        flags &= ~(PG_RW | PG_PS_2M);
        flags |= PG_US | PG_SOFT_COW | PG_SOFT_OWNED;
        if (mm_map_4k_sharedaware(child, parent_l4, va, pa, flags) != 0) {
            frame_release(pa);
            return -1;
        }
        if (mm_mark_share_user_readonly_page(parent, parent_l4, va) != 0)
            return -1;
    }
    return 0;
}

int mm_cow_restore_user_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t *l4 = mm->pml4;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        int l4i = (int)((va >> 39) & 0x1FF);
        int l3i = (int)((va >> 30) & 0x1FF);
        int l2i = (int)((va >> 21) & 0x1FF);
        int l1i = (int)((va >> 12) & 0x1FF);
        uint64_t e4 = l4[l4i];
        if (!(e4 & PG_PRESENT) || !pt_page_pa_ok(e4)) continue;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
        uint64_t e3 = l3[l3i];
        if (!(e3 & PG_PRESENT) || (e3 & PG_PS_2M) || !pt_page_pa_ok(e3)) continue;
        uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
        uint64_t e2 = l2[l2i];
        if (!(e2 & PG_PRESENT)) continue;
        if (e2 & PG_PS_2M) {
            if ((e2 & (PG_US | PG_SOFT_COW)) == (PG_US | PG_SOFT_COW)) {
                l2[l2i] = (e2 | PG_RW) & ~PG_SOFT_COW;
                invlpg((void *)(uintptr_t)va);
            }
            continue;
        }
        if (!pt_page_pa_ok(e2)) continue;
        uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
        uint64_t e1 = l1[l1i];
        if ((e1 & (PG_PRESENT | PG_US | PG_SOFT_COW)) !=
            (PG_PRESENT | PG_US | PG_SOFT_COW))
            continue;
        l1[l1i] = (e1 | PG_RW) & ~PG_SOFT_COW;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

/* Child-only Soft_COW leaf: share PA, RO|SOFT_COW in child, parent stays RW. */
static int mm_cow_mark_user_readonly_child_only_l4(mm_t *child, uint64_t *parent_l4,
                                                    uint64_t va_begin, uint64_t va_end) {
    if (!child || !child->pml4 || !parent_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t pa = 0, flags = 0;
        if (!mm_share_pte_user_cowable_pa(parent_l4, va, &pa, &flags))
            continue;
        if (frame_retain(pa) != 0) {
            devel_printf("cow-child: unowned user frame va=0x%llx pa=0x%llx\n",
                    (unsigned long long)va,
                    (unsigned long long)(pa & ~0xFFFULL));
            return -1;
        }
        flags &= (PG_PRESENT | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
        flags &= ~(PG_RW | PG_PS_2M);
        flags |= PG_US | PG_SOFT_COW | PG_SOFT_OWNED;
        if (mm_map_4k_sharedaware(child, parent_l4, va, pa, flags) != 0) {
            frame_release(pa);
            return -1;
        }
    }
    return 0;
}

/*
 * Brk heap is not a VMA — fork must still duplicate it.
 * Exec also materializes a TLS/bootstrap window above brk_current without
 * raising the break; musl malloc then lives there (tmux ~0x801xxx).  Treat
 * that committed window as part of the brk slab for fork COW.
 */
static uint64_t mm_brk_fork_hi(const mm_t *mm) {
    uint64_t lo, hi, win;
    if (!mm || !mm->brk_base)
        return 0;
    lo = (uint64_t)mm->brk_base;
    hi = (uint64_t)mm->brk_current;
    if (hi < lo)
        hi = lo;
    /* Match user_as_set_brk_after_load tls_window, with headroom for early malloc. */
    win = lo + (256ull << 10);
    if (win > hi)
        hi = win;
    if (hi > (uint64_t)MMIO_IDENTITY_LIMIT)
        hi = (uint64_t)MMIO_IDENTITY_LIMIT;
    return hi;
}

static int mm_va_in_brk(const mm_t *mm, uint64_t va) {
    uint64_t lo, hi;
    if (!mm || !mm->brk_base)
        return 0;
    lo = (uint64_t)mm->brk_base;
    hi = mm_brk_fork_hi(mm);
    if (hi <= lo)
        return 0;
    return (va >= lo && va < hi) ? 1 : 0;
}

/* True if [lo,hi) intersects mm's brk range. */
static int mm_range_in_brk(const mm_t *mm, uint64_t lo, uint64_t hi) {
    uint64_t blo, bhi;
    if (!mm || !mm->brk_base)
        return 0;
    blo = (uint64_t)mm->brk_base;
    bhi = mm_brk_fork_hi(mm);
    if (bhi <= blo)
        return 0;
    return (hi > blo && lo < bhi) ? 1 : 0;
}

/* Primary stack + TLS: keep the parent RW across clone (VMware triple-faulted
 * when the syscall-return stack was Soft_COW).  All other private leaves follow
 * Linux copy_page_range (share RO; Soft_COW writable). */
static int mm_fork_va_is_primary_stack(uint64_t va) {
    uint64_t lo = (uint64_t)USER_TLS_BASE_LAYOUT;
    uint64_t hi = (uint64_t)USER_STACK_TOP_LAYOUT + 0x10000ULL;
    return (va >= lo && va < hi) ? 1 : 0;
}

static int mm_fork_copy_user_leaf(mm_t *child, mm_t *parent,
                                  uint64_t *parent_l4, uint64_t owner_tid,
                                  uint64_t va, uint64_t parent_pa,
                                  uint64_t parent_pte, int protect_parent,
                                  int shared_hint) {
    /*
     * shared_hint comes from the fork snapshot probe (MV_SNAP_SHARED) computed
     * once per page BESIDE the walk, not from a fresh O(USER_VMA_MAX=4096) scan
     * here.  The old per-leaf user_vma_is_shared_page_mm()/_page() pair was the
     * residual fork() hot path after the snapshot skip: ~2x4096 slot compares
     * per COW'd leaf made `( : ) & wait $!` cost ~20ms.  parent==NULL (vfork
     * child-writable pass) never shares, matching the old parent&& short-cut.
     */
    int shared = parent && shared_hint;
    int owned = (parent_pte & PG_SOFT_OWNED) != 0;
    uint64_t child_pa = parent_pa & PG_ADDR_MASK;
    uint64_t flags = parent_pte &
        (PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL |
         PG_SOFT_COW | PG_SOFT_OWNED | PG_NX);
    int retained = 0;
    void *private_copy = NULL;
    int parent_wr = ((parent_pte & PG_RW) || (parent_pte & PG_SOFT_COW)) ? 1 : 0;

    if (shared) {
        flags &= ~PG_SOFT_COW;
        if (owned) {
            if (frame_retain(child_pa) != 0) {
                devel_printf("fork-cow: retain failed va=0x%llx pa=0x%llx "
                        "pte=0x%llx refs=%u shared=%d\n",
                        (unsigned long long)va,
                        (unsigned long long)child_pa,
                        (unsigned long long)parent_pte,
                        frame_refcount(child_pa), shared);
                return -1;
            }
            retained = 1;
        }
    } else {
        uint64_t src_pa = parent_pa & PG_ADDR_MASK;
        int eager;

        if (src_pa >= (uint64_t)MMIO_IDENTITY_LIMIT)
            return -1;
        /*
         * Eager-copy only:
         *  - the live primary stack/TLS (parent must stay RW through iret)
         *  - writable identity leftovers with no frame ref (cannot Soft_COW
         *    them without pmm_free'ing kernel identity on last release)
         * Everything else is Linux copy_page_range: share RO text, Soft_COW
         * private heap/mmap (apt's 128MiB cache used to be memcpy'd and the
         * child's xz then died with LZMA_MEM_ERROR).
         */
        eager = parent_wr && (!owned || mm_fork_va_is_primary_stack(va));
        if (eager) {
            private_copy = mm_user_frame_alloc_avoid_va(va, 0);
            if (!private_copy) {
                devel_printf("fork-cow: copy alloc failed va=0x%llx pte=0x%llx\n",
                        (unsigned long long)va,
                        (unsigned long long)parent_pte);
                return -1;
            }
            /*
             * Identity PA==VA may be a hole / demoted leaf under swapper while
             * the parent process CR3 still has live heap bytes.  Seed like
             * mm_privatize_identity_range: copy under the parent L4.
             */
            if (src_pa == (va & ~0xFFFULL) && parent_l4) {
                uint64_t parent_cr3 = (parent && parent->cr3) ? parent->cr3
                    : ((uint64_t)(uintptr_t)parent_l4);
                uint64_t saved = paging_read_cr3();
                paging_write_cr3(parent_cr3);
                memcpy(private_copy, (void *)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
                paging_write_cr3(saved);
            } else {
                memcpy(private_copy, (void *)(uintptr_t)src_pa, (size_t)PAGE_SIZE_4K);
            }
            child_pa = (uint64_t)(uintptr_t)private_copy;
            flags &= ~(PG_SOFT_COW | PG_SOFT_OWNED);
            if (parent_pte & PG_SOFT_COW)
                flags |= PG_RW;
            flags |= PG_SOFT_OWNED;
        } else {
            child_pa = src_pa;
            if (owned) {
                if (frame_retain(child_pa) == 0) {
                    retained = 1;
                    flags |= PG_SOFT_OWNED;
                } else {
                    /* 2MiB Soft_OWNED sliced to 4K: only the huge base is in
                     * the frame table. Share without a ref so mmput does not
                     * pmm_free a page the parent still maps. */
                    flags &= ~PG_SOFT_OWNED;
                }
            }
            if (parent_wr) {
                flags &= ~PG_RW;
                flags |= PG_SOFT_COW;
            } else {
                flags &= ~PG_SOFT_COW;
            }
        }
    }

    int map_ret = mm_map_user_page(child, va, child_pa, flags);
    if (map_ret) {
        devel_printf("fork: child map failed rc=%d va=0x%llx pa=0x%llx "
                "pte=0x%llx flags=0x%llx shared=%d owned=%d\n",
                map_ret,
                (unsigned long long)va,
                (unsigned long long)child_pa,
                (unsigned long long)parent_pte,
                (unsigned long long)flags, shared, owned);
        if (retained || private_copy)
            frame_release(child_pa);
        return -1;
    }
    if (!shared && parent_wr && !private_copy && protect_parent && parent &&
        parent_l4 && mm_mark_share_user_readonly_page(parent, parent_l4, va) != 0)
        return -1;
    return 0;
}

#define MV_SNAP_CAP 256        /* > real VMA count for any process (barring
                                  >256-mmap apps, which fall back to the exact
                                  predicate path). */
#define MV_SNAP_VMA       0x01u
#define MV_SNAP_SHARED    0x02u
#define MV_SNAP_LAZY_FILE 0x04u
#define MV_SNAP_LAZY_ANON 0x08u

/* Compact probe over the fork snapshot.  g_user_vmas entries (i<g_cnt) carry
 * the full flag set; mm-only entries (i>=g_cnt) contribute SHARED (mm-scoped
 * SHM is authoritative) and otherwise only set *any_mm_only so the caller does
 * not fast-skip a chunk on g/mm divergence. */
static unsigned mm_mv_probe(const user_vma_t *v, int total, int g_cnt,
                            uintptr_t lo, uintptr_t hi, int *any_mm_only) {
    unsigned f = 0;
    int guard = 0;
    for (int i = 0; i < total; ++i) {
        const user_vma_t *ve = &v[i];
        if (!ve->used)
            continue;
        uintptr_t a = ve->addr;
        uintptr_t e = a + ve->len;
        if (!(e > a && lo < e && hi > a))
            continue;
        if (i < g_cnt) {
            f |= MV_SNAP_VMA;
            if (ve->kind == USER_VMA_KIND_SHM)
                f |= MV_SNAP_SHARED;
            if (ve->file && (ve->kind == USER_VMA_KIND_MMAP_LAZY ||
                             ve->kind == USER_VMA_KIND_ELF_LOAD ||
                             ve->kind == USER_VMA_KIND_MMAP ||
                             ve->kind == USER_VMA_KIND_SHM))
                f |= MV_SNAP_LAZY_FILE;
            if (ve->kind == USER_VMA_KIND_MMAP_LAZY && !ve->file)
                f |= MV_SNAP_LAZY_ANON;
        } else {
            if (ve->kind == USER_VMA_KIND_SHM)
                f |= MV_SNAP_SHARED;
            guard = 1;
        }
    }
    if (any_mm_only)
        *any_mm_only = guard;
    return f;
}

static unsigned mm_mv_page_exact(uint64_t owner_tid, mm_t *parent_for_vma,
                                 uintptr_t va) {
    unsigned f = 0;
    if (parent_for_vma && user_vma_is_shared_page_mm(parent_for_vma, va))
        f |= MV_SNAP_SHARED;
    if (user_vma_is_shared_page(owner_tid, va))
        f |= MV_SNAP_SHARED;
    if (user_vma_covers_page(owner_tid, va))
        f |= MV_SNAP_VMA;
    if (user_vma_is_lazy_file_page(owner_tid, va))
        f |= MV_SNAP_LAZY_FILE;
    if (user_vma_is_lazy_anon_page(owner_tid, va))
        f |= MV_SNAP_LAZY_ANON;
    return f;
}

static int mm_cow_mark_all_user_writable_walk(mm_t *child, mm_t *parent_for_vma,
                                              uint64_t *parent_l4, uint64_t owner_tid,
                                              int protect_parent) {
    if (!child || !child->pml4 || !parent_l4)
        return -1;
    if (protect_parent && (!parent_for_vma || !parent_for_vma->pml4))
        return -1;
    uint64_t limit = (uint64_t)USER_STACK_TOP;
    if (limit > (uint64_t)MMIO_IDENTITY_LIMIT)
        limit = (uint64_t)MMIO_IDENTITY_LIMIT;

    /*
     * Snapshot the owner's VMAs once, under one lock grab.  The old code called
     * user_vma_is_shared_page(_mm) / user_vma_covers_page / user_vma_is_lazy_*
     * per 4K page — each an O(USER_VMA_MAX=4096) scan under irqsave, so every
     * fork() of a bash-sized process cost ~150ms sweeping ~1.5GiB of identity
     * RAM.  The frozen parent guarantees the snapshot's lifetime.
     */
    user_vma_t *snap = NULL;
    int snap_cnt = 0, snap_g = 0, snap_full = 0;
    snap = (user_vma_t *)kmalloc(sizeof(user_vma_t) * (size_t)MV_SNAP_CAP);
    if (!snap) {
        snap_full = 1;
    } else {
        int mm_only = 0;
        snap_cnt = user_vma_snapshot(owner_tid, parent_for_vma,
                                     snap, (size_t)MV_SNAP_CAP, &mm_only);
        snap_g = snap_cnt - mm_only;
        if (snap_cnt >= MV_SNAP_CAP || snap_g < 0 || snap_g > snap_cnt)
            snap_full = 1;
    }

    /*
     * Walk parent PTs under swapper (Linux direct map): process CR3 may have
     * Soft_COW / exec-scrub holes at PT-frame PAs.  Skip raw identity leaves
     * (pa==va, !SOFT_OWNED) — Linux fork only copies VMA-backed pages; AxonOS
     * exec already privatizes ELF/stack/brk into Soft_OWNED frames.  Eagerly
     * copying leftover PG_US identity 2MiB windows OOMs fork and then hangs
     * mmput under cli (apm update → clone → thread_stop).
     */
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;

    for (int l4i = 0; l4i < 512; ++l4i) {
        uint64_t e4 = parent_l4[l4i];
        if (!(e4 & PG_PRESENT) || !pt_page_pa_ok(e4))
            continue;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
        for (int l3i = 0; l3i < 512; ++l3i) {
            uint64_t va_l3 = ((uint64_t)l4i << 39) | ((uint64_t)l3i << 30);
            if (va_l3 >= limit) {
                rc = 0;
                goto out;
            }
            uint64_t e3 = l3[l3i];
            if (!(e3 & PG_PRESENT) || (e3 & PG_PS_2M) || !pt_page_pa_ok(e3))
                continue;
            uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
            for (int l2i = 0; l2i < 512; ++l2i) {
                uint64_t va_l2 = va_l3 | ((uint64_t)l2i << 21);
                if (va_l2 < 0x200000ULL || va_l2 >= limit)
                    continue;
                uint64_t e2 = l2[l2i];
                if (!(e2 & PG_PRESENT))
                    continue;
                if (e2 & PG_PS_2M) {
                    if (!(e2 & PG_US))
                        continue;
                    uint64_t leaf2 = e2 & PG_ADDR_MASK_2M;
                    uint64_t chunk_end = va_l2 + PAGE_SIZE_2M;
                    if (chunk_end > limit)
                        chunk_end = limit;
                    /*
                     * Fast path: a bare-identity 2MiB chunk with no VMA, SHM,
                     * lazy reservation or brk anywhere in it cannot feed a
                     * single mm_fork_copy_user_leaf — every 4K subpage hits the
                     * identity continue below.  Skip it with one compact probe.
                     */
                    if (!snap_full && leaf2 == va_l2 &&
                        !(e2 & PG_SOFT_OWNED)) {
                        int any_mm = 0;
                        unsigned pf = mm_mv_probe(snap, snap_cnt, snap_g,
                                                  va_l2, chunk_end, &any_mm);
                        if (pf == 0 && !any_mm &&
                            !(parent_for_vma &&
                              mm_range_in_brk(parent_for_vma, va_l2, chunk_end)))
                            continue;
                    }
                    /* Entire 2MiB identity window — not a privatized user leaf.
                     * Exception: MAP_SHARED anon also uses identity VA==PA and
                     * must be installed into the child (nginx shm zones).
                     * Also copy ELF_LOAD / other VMA-backed identity pages: PID1
                     * used to load without Soft_OWNED; skipping left the child
                     * with demoted U=0 text and #PF right after clone/_Fork. */
                    for (uint64_t va = va_l2; va < chunk_end; va += PAGE_SIZE_4K) {
                        uint64_t pa = leaf2 + (va - va_l2);
                        int any_mm = 0;
                        unsigned pf = snap_full
                            ? mm_mv_page_exact(owner_tid, parent_for_vma, va)
                            : mm_mv_probe(snap, snap_cnt, snap_g,
                                          va, va + PAGE_SIZE_4K, &any_mm);
                        int shared_pg = !!(pf & MV_SNAP_SHARED);
                        int page_vma = !!(pf & MV_SNAP_VMA);
                        int in_brk = parent_for_vma &&
                            mm_va_in_brk(parent_for_vma, va);
                        int lazy_file = !!(pf & MV_SNAP_LAZY_FILE);
                        int lazy_anon = !!(pf & MV_SNAP_LAZY_ANON);
                        /*
                         * File-backed MMAP_LAZY: only Soft_OWNED leaves hold real
                         * file bytes.  Identity PG_US leftovers (or 2MiB siblings
                         * after a 4K split) are physical RAM, not libc.so —
                         * copying them made grub-install's fork children execute
                         * junk at ~0x808xxxx (add [rsi],al → #PF cr2=0) then the
                         * parent continued after two SIGSEGVs.
                         * Anonymous MMAP_LAZY (apt Dynamic MMap) is the same:
                         * only faulted Soft_OWNED pages are user data.
                         */
                        if ((lazy_file || lazy_anon) &&
                            (!(e2 & PG_SOFT_OWNED) || pa == (va & ~0xFFFULL)))
                            continue;
                        if (pa == (va & ~0xFFFULL) && !(e2 & PG_SOFT_OWNED) &&
                            !shared_pg && !page_vma && !in_brk)
                            continue;
                        if (mm_fork_copy_user_leaf(child, parent_for_vma,
                                parent_l4, owner_tid, va, pa, e2,
                                protect_parent,
                                (parent_for_vma ? shared_pg : 0)) != 0)
                            goto out;
                    }
                    continue;
                }
                if (!pt_page_pa_ok(e2))
                    continue;
                {
                    uint64_t chunk_end = va_l2 + PAGE_SIZE_2M;
                    if (chunk_end > limit)
                        chunk_end = limit;
                    /*
                     * Fast path (4K-table form): if nothing mapped, shared or
                     * brked in the whole 2MiB L2 span, all 512 leaves are bare
                     * identity — the per-leaf loop below can only skip them.
                     * Privatization always registers a VMA, so this cannot drop
                     * a Soft_OWNED / eagerly-copied leaf.
                     */
                    if (!snap_full) {
                        int any_mm = 0;
                        unsigned pf = mm_mv_probe(snap, snap_cnt, snap_g,
                                                  va_l2, chunk_end, &any_mm);
                        if (pf == 0 && !any_mm &&
                            !(parent_for_vma &&
                              mm_range_in_brk(parent_for_vma, va_l2, chunk_end)))
                            continue;
                    }
                }
                uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
                for (int l1i = 0; l1i < 512; ++l1i) {
                    uint64_t va = va_l2 | ((uint64_t)l1i << 12);
                    if (va < 0x200000ULL || va >= limit)
                        continue;
                    uint64_t e1 = l1[l1i];
                    if ((e1 & (PG_PRESENT | PG_US)) !=
                        (PG_PRESENT | PG_US))
                        continue;
                    uint64_t pa = e1 & PG_ADDR_MASK;
                    if (pa >= (uint64_t)MMIO_IDENTITY_LIMIT || !pt_page_pa_ok(e1))
                        continue;
                    int any_mm = 0;
                    unsigned pf = snap_full
                        ? mm_mv_page_exact(owner_tid, parent_for_vma, va)
                        : mm_mv_probe(snap, snap_cnt, snap_g,
                                      va, va + PAGE_SIZE_4K, &any_mm);
                    int shared_4k = !!(pf & MV_SNAP_SHARED);
                    int page_vma = !!(pf & MV_SNAP_VMA);
                    int in_brk = parent_for_vma &&
                        mm_va_in_brk(parent_for_vma, va);
                    int lazy_file = !!(pf & MV_SNAP_LAZY_FILE);
                    int lazy_anon = !!(pf & MV_SNAP_LAZY_ANON);
                    /* Unpopulated or bogus Soft_OWNED-on-identity: skip. */
                    if ((lazy_file || lazy_anon) &&
                        (!(e1 & PG_SOFT_OWNED) || pa == (va & ~0xFFFULL)))
                        continue;
                    if (pa == (va & ~0xFFFULL) && !(e1 & PG_SOFT_OWNED) &&
                        !shared_4k && !page_vma && !in_brk)
                        continue;
                    if (mm_fork_copy_user_leaf(child, parent_for_vma,
                            parent_l4, owner_tid, va, pa, e1,
                            protect_parent,
                            (parent_for_vma ? shared_4k : 0)) != 0)
                        goto out;
                }
            }
        }
    }
    rc = 0;
out:
    if (snap)
        kfree(snap);
    mm_leave_direct_map(dm);
    return rc;
}

int mm_cow_mark_all_user_writable_pair_l4(mm_t *child, mm_t *parent,
                                          uint64_t *parent_l4, uint64_t owner_tid) {
    /*
     * Linux dup_mmap/copy_page_range style: walk present user leaves only.
     * Skip identity-mapped kernel heap pages (VA==PA inside heap arena).
     */
    return mm_cow_mark_all_user_writable_walk(child, parent, parent_l4, owner_tid, 1);
}

int mm_cow_mark_all_user_writable_child_l4(mm_t *child, uint64_t *parent_l4,
                                           uint64_t owner_tid) {
    /* AxonOS vfork: parent stays RW; child Soft_COW until exec. */
    return mm_cow_mark_all_user_writable_walk(child, NULL, parent_l4, owner_tid, 0);
}

/*
 * Fail-closed second pass: every present user leaf in the parent's brk range
 * must exist as Soft_OWNED in the child.  The main walker can still miss a page
 * if Soft_OWNED was dropped by a 2M split; blank-filling that hole later
 * destroys musl malloc metadata (tmux server a_crash/hlt @ ~0x801xxx).
 */
static int mm_dup_ensure_brk_copied(mm_t *child, mm_t *parent, uint64_t owner_tid)
{
	uintptr_t lo, hi;
	mm_dm_ctx_t dm;

	if (!child || !parent || !parent->pml4)
		return -1;
	lo = parent->brk_base;
	hi = (uintptr_t)mm_brk_fork_hi(parent);
	if (!lo || hi <= lo)
		return 0;
	lo &= ~((uintptr_t)0xFFFULL);
	hi = (hi + 0xFFFULL) & ~((uintptr_t)0xFFFULL);
	if (hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
		hi = (uintptr_t)MMIO_IDENTITY_LIMIT;

	dm = mm_enter_direct_map();
	for (uintptr_t va = lo; va < hi; va += 0x1000ULL) {
		uint64_t parent_pte = 0;
		uint64_t child_pte = 0;
		uint64_t pa;

		if (mm_va_leaf_entry_direct(parent, (uint64_t)va, &parent_pte) != 0)
			continue;
		if ((parent_pte & (PG_PRESENT | PG_US)) != (PG_PRESENT | PG_US))
			continue;
		pa = parent_pte & PG_ADDR_MASK;
		if (pa >= (uint64_t)MMIO_IDENTITY_LIMIT || !pt_page_pa_ok(parent_pte))
			continue;

		if (mm_va_leaf_entry_direct(child, (uint64_t)va, &child_pte) == 0 &&
		    (child_pte & (PG_PRESENT | PG_US | PG_SOFT_OWNED)) ==
			    (PG_PRESENT | PG_US | PG_SOFT_OWNED) &&
		    (child_pte & PG_ADDR_MASK) != ((uint64_t)va & ~0xFFFULL))
			continue;

		if (mm_fork_copy_user_leaf(child, parent, parent->pml4, owner_tid,
					   (uint64_t)va, pa, parent_pte, 0,
					   user_vma_is_shared_page_mm(parent, (uintptr_t)va) ||
					   user_vma_is_shared_page(owner_tid, (uintptr_t)va)) != 0) {
			mm_leave_direct_map(dm);
			return -1;
		}
	}
	mm_leave_direct_map(dm);
	return 0;
}

mm_t *mm_dup_user(mm_t *parent, uint64_t owner_tid)
{
	mm_t *child;

	if (!parent || !parent->pml4)
		return NULL;

	child = mm_alloc();
	if (!child)
		return NULL;

	if (user_vma_clone_mm(child, parent))
		goto fail;

	/* protect_parent: Linux WP on private writable leaves.  The primary
	 * stack/TLS is eager-copied in mm_fork_copy_user_leaf so clone return
	 * never write-faults the live syscall stack (VMware triple-fault). */
	if (mm_cow_mark_all_user_writable_walk(child, parent, parent->pml4,
					       owner_tid, 1))
		goto fail;

	if (mm_dup_ensure_brk_copied(child, parent, owner_tid))
		goto fail;

	/*
	 * Punch holes for lazy libc.so/etc. pages that were not private
	 * Soft_OWNED frames.  mm_alloc leaves demoted identity (~US); skipping
	 * the copy without unmap makes user I-fetch a protection fault that
	 * never reaches filemap_fault.
	 */
	if (user_vma_fork_scrub_lazy_file(child, owner_tid))
		goto fail;

	child->brk_base = parent->brk_base;
	child->brk_current = parent->brk_current;
	child->mmap_cursor = parent->mmap_cursor;
	return child;

fail:
	mm_release(child);
	return NULL;
}

static int mm_cow_fork_copy_one_page(mm_t *mm, uint64_t *share_l4, uint64_t va) {
    /*
     * Eager break runs AFTER mm_cow_mark_* turned leaves into RO|SOFT_COW.
     * Requiring class==2 (still writable) skipped every page → pages=0 and the
     * openrc child then hit kernel copy_to_user on a COW stack in rt_sigaction.
     */
    uint64_t old_pa = 0, flags = 0;
    if (!mm_share_pte_user_cowable_pa(share_l4, va, &old_pa, &flags))
        return 0;
    uint64_t old_child_pte = 0;
    (void)mm_va_leaf_entry(mm, va, &old_child_pte);
    void *newp = mm_user_frame_alloc(0);
    if (!newp)
        return -1;
    memcpy(newp, (void *)(uintptr_t)(old_pa & PG_ADDR_MASK),
           (size_t)PAGE_SIZE_4K);
    if (mm_map_4k_sharedaware(mm, share_l4, va, (uint64_t)(uintptr_t)newp,
                              PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
        mm_user_frame_put(newp);
        return -1;
    }
    if (old_child_pte & PG_SOFT_OWNED)
        frame_release(old_pa & PG_ADDR_MASK);
    return 1;
}

int mm_cow_fork_pages(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out) {
    if (copied_out) *copied_out = 0;
    if (!mm || !mm->pml4 || max_pages == 0) return 0;
    if (!share_l4) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    unsigned copied = 0;
    for (uint64_t va = (end > begin) ? (end - 0x1000ULL) : begin; copied < max_pages; ) {
        if (va < begin) break;
        int rc = mm_cow_fork_copy_one_page(mm, share_l4, va);
        if (rc < 0) return (copied > 0) ? 0 : -1;
        if (rc > 0)
            copied++;
        if (va < begin + 0x1000ULL) break;
        va -= 0x1000ULL;
    }
    if (copied_out) *copied_out = copied;
    return 0;
}

int mm_cow_fork_pages_forward(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out) {
    if (copied_out) *copied_out = 0;
    if (!mm || !mm->pml4 || max_pages == 0) return 0;
    if (!share_l4) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    unsigned copied = 0;
    for (uint64_t va = begin; copied < max_pages && va < end; va += 0x1000ULL) {
        int rc = mm_cow_fork_copy_one_page(mm, share_l4, va);
        if (rc < 0) return (copied > 0) ? 0 : -1;
        if (rc > 0)
            copied++;
    }
    if (copied_out) *copied_out = copied;
    return 0;
}

static int mm_cow_private_writable_impl(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
        unsigned max_span, unsigned max_pages, int skip_2m, int user_only) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (max_span && end - begin > (uint64_t)max_span)
        end = begin + (uint64_t)max_span;
    unsigned page_idx = 0;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        if (user_only) {
            if (!mm_share_pte_user_writable(share_l4, va)) continue;
        } else {
            int cls = mm_share_pte_class(share_l4, va);
            if (cls != 2) continue;
        }
        if (skip_2m) {
            int l4i = (int)((va >> 39) & 0x1FF);
            int l3i = (int)((va >> 30) & 0x1FF);
            int l2i = (int)((va >> 21) & 0x1FF);
            uint64_t se4 = share_l4[l4i];
            if (se4 & PG_PRESENT) {
                uint64_t *l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
                uint64_t se3 = l3[l3i];
                if ((se3 & PG_PRESENT) && (se3 & PG_PS_2M)) {
                    va = (va & ~((uint64_t)PAGE_SIZE_2M - 1)) + PAGE_SIZE_2M;
                    continue;
                }
                if (se3 & PG_PRESENT && !(se3 & PG_PS_2M)) {
                    uint64_t *l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
                    uint64_t se2 = l2[l2i];
                    if ((se2 & PG_PRESENT) && (se2 & PG_PS_2M)) {
                        va = (va & ~((uint64_t)PAGE_SIZE_2M - 1)) + PAGE_SIZE_2M;
                        continue;
                    }
                }
            }
        }
        if (max_pages && page_idx >= max_pages)
            break;
        page_idx++;
        if ((page_idx & 31u) == 0u)
            thread_yield();
        uint64_t old_pa = 0;
        uint64_t old_child_pte = 0;
        mm_t source_mm;
        memset(&source_mm, 0, sizeof(source_mm));
        source_mm.pml4 = share_l4;
        if (mm_va_leaf_pa(&source_mm, va, &old_pa) != 0)
            continue;
        (void)mm_va_leaf_entry(mm, va, &old_child_pte);
        void *newp = mm_user_frame_alloc(0);
        if (!newp) return -1;
        memcpy(newp, (void *)(uintptr_t)(old_pa & ~0xFFFULL),
               (size_t)PAGE_SIZE_4K);
        /* The whole range already runs under the direct-map CR3. Avoid a
         * nested pushfq/cli/CR3 check for every 4 KiB page. */
        if (mm_map_4k_sharedaware_body(mm, share_l4, va, (uint64_t)(uintptr_t)newp,
                                      PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
            mm_user_frame_put(newp);
            return -1;
        }
        if (old_child_pte & PG_SOFT_OWNED)
            frame_release(old_pa);
    }
    return 0;
}

int mm_cow_private_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end) {
    uint64_t *share_l4 = (uint64_t *)(uintptr_t)(paging_read_cr3() & ~0xFFFULL);
    return mm_cow_private_writable_impl(mm, share_l4, va_begin, va_end, 512u * 1024u, 48u, 1, 0);
}

int mm_cow_private_writable_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end) {
    return mm_cow_private_writable_impl(mm, share_l4, va_begin, va_end, 0, 0, 0, 0);
}

int mm_cow_private_user_writable_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end) {
    return mm_cow_private_writable_impl(mm, share_l4, va_begin, va_end, 0, 0, 0, 1);
}

/* COW page-fault path: install one private 4K leaf.  NEVER walk/split in place
 * without breaking sharing — that silently rewrites the parent's PTEs
 * (GPF at RIP=="ls" after ash fork).  Always dup vs a comparison L4. */
static int mm_map_4k_private_force(mm_t *mm, uint64_t va, uint64_t pa, uint64_t flags) {
    if (!mm || !mm->pml4) return -101;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -102;
    mm_t *share = mm_kernel();
    if (!share || !share->pml4) return -103;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share->pml4) return -104;
    return mm_map_4k_sharedaware(mm, share->pml4, va, pa, flags);
}

int mm_fork_sync_from_parent(mm_t *child_mm, mm_t *parent_mm, uint64_t va_begin, uint64_t va_end,
                             unsigned max_pages, int force_all) {
    if (!child_mm || !child_mm->pml4 || !parent_mm || max_pages == 0)
        return 0;
    if (va_end <= va_begin)
        return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT)
        va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end)
        return 0;

    mm_switch(parent_mm);
    uint64_t *parent_l4 = (uint64_t *)(uintptr_t)(paging_read_cr3() & ~0xFFFULL);
    uint64_t child_cr3 = child_mm->cr3 & ~0xFFFULL;
    uint64_t *child_l4 = child_cr3 ? (uint64_t *)(uintptr_t)child_cr3 : child_mm->pml4;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT)
        end = (uint64_t)MMIO_IDENTITY_LIMIT;

    unsigned copied = 0;
    for (uint64_t va = begin; va < end && copied < max_pages; va += 0x1000ULL) {
        int pcl = mm_share_pte_class(parent_l4, va);
        if (pcl == 0)
            continue;
        if (!force_all) {
            int ccl = mm_share_pte_class(child_l4, va);
            /* Still shared read-only COW — parent has not written this page yet. */
            if (pcl == 1 && ccl == 1)
                continue;
        }

        uint64_t old_pa = 0;
        uint64_t old_child_pte = 0;
        if (mm_va_leaf_pa(parent_mm, va, &old_pa) != 0)
            continue;
        (void)mm_va_leaf_entry(child_mm, va, &old_child_pte);
        void *newp = mm_user_frame_alloc(0);
        if (!newp) {
            mm_switch(child_mm);
            return (copied > 0) ? 0 : -1;
        }
        memcpy(newp, (void *)(uintptr_t)(old_pa & ~0xFFFULL),
               (size_t)PAGE_SIZE_4K);
        mm_switch(child_mm);
        if (mm_map_4k_sharedaware(child_mm, parent_l4, va, (uint64_t)(uintptr_t)newp,
                                  PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
            mm_user_frame_put(newp);
            mm_switch(parent_mm);
            return (copied > 0) ? 0 : -1;
        }
        if (old_child_pte & PG_SOFT_OWNED)
            frame_release(old_pa);
        copied++;
        mm_switch(parent_mm);
    }
    mm_switch(child_mm);
    return 0;
}

int mm_fork_sync_page_from_parent(mm_t *child_mm, mm_t *parent_mm, uint64_t va) {
    if (!child_mm || !parent_mm)
        return -1;
    va &= ~0xFFFULL;
    if (va < 0x1000ULL || va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    return mm_fork_sync_from_parent(child_mm, parent_mm, va, va + 0x1000ULL, 1, 1);
}

static int mm_active_pte_flags(uint64_t va, uint64_t *flags_out) {
    if (!flags_out || va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    uint64_t *l4 = (uint64_t *)(uintptr_t)(paging_read_cr3() & ~0xFFFULL);
    if (!l4)
        return -1;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t e4 = l4[l4i];
    if (!(e4 & PG_PRESENT) || !pt_page_pa_ok(e4)) return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[l3i];
    if (!(e3 & PG_PRESENT)) return -1;
    if (e3 & PG_PS_2M) {
        *flags_out = e3;
        return 0;
    }
    if (!pt_page_pa_ok(e3)) return -1;
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[l2i];
    if (!(e2 & PG_PRESENT)) return -1;
    if (e2 & PG_PS_2M) {
        *flags_out = e2;
        return 0;
    }
    if (!pt_page_pa_ok(e2)) return -1;
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    *flags_out = l1[l1i];
    return (*flags_out & PG_PRESENT) ? 0 : -1;
}

/* Split a present 2MiB/1GiB leaf so do_wp_page can replace a single 4K page. */
static int mm_split_huge_leaf_for_va(mm_t *mm, uint64_t va) {
    if (!mm || !mm->pml4)
        return -1;
    va &= ~0xFFFULL;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    uint64_t e4 = mm->pml4[l4i];
    if (!(e4 & PG_PRESENT) || (e4 & PG_PS_2M) || !pt_page_pa_ok(e4))
        return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[l3i];
    if (!(e3 & PG_PRESENT))
        return -1;
    if (e3 & PG_PS_2M) {
        if (split_l3_1g_to_l2(mm, l3, l3i) != 0)
            return -1;
        e3 = l3[l3i];
    }
    if (!pt_page_pa_ok(e3) || (e3 & PG_PS_2M))
        return -1;
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[l2i];
    if (!(e2 & PG_PRESENT))
        return -1;
    if (e2 & PG_PS_2M) {
        if (split_2m_to_4k(mm, l2, l2i, va) != 0)
            return -1;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

int mm_cow_fault_page(mm_t *mm, uint64_t va, mm_t *share_cmp_mm) {
    if (!mm || !mm->pml4) return -1;
    uint64_t pg = va & ~0xFFFULL;
    if (pg < 0x1000ULL || pg >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    extern int syscall_pipe_watch_active;
    /*
     * Linux resolves a COW fault through its permanent kernel direct map; it
     * never needs to run on the target task's CR3. This matters especially for
     * fork_store_child_tid(): exec-scrub may have removed identity leaves from
     * both parent and child at physical addresses subsequently returned by the
     * frame allocator. Copying through either process CR3 can then fault in the
     * kernel fault handler and escalate to a double/triple fault on VMware.
     *
     * Keep swapper CR3 and IF=0 for the complete PT walk/copy/map transaction.
     * mm_map_4k_sharedaware() nests the same direct-map guard safely.
     */
    uint64_t saved_cr3 = paging_read_cr3();
    uint64_t want_cr3 = mm->cr3 ? mm->cr3 : (uint64_t)(uintptr_t)mm->pml4;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;
    uint64_t old_pte = 0;
    if (mm_va_leaf_entry_direct(mm, pg, &old_pte) != 0) {
        rc = -2;
        goto out;
    }
    /* Huge Soft_COW / WP leaves must be split before a 4K private replacement. */
    if (old_pte & PG_PS_2M) {
        if (mm_split_huge_leaf_for_va(mm, pg) != 0) {
            rc = -1;
            goto out;
        }
        if (mm_va_leaf_entry_direct(mm, pg, &old_pte) != 0) {
            rc = -2;
            goto out;
        }
    }
    /*
     * Linux do_wp_page: Soft_COW write-protect faults get a private copy.
     * Soft_OWNED is optional — fork also Soft_COW-marks identity leaves that
     * never held a frame ref (parent ash heap). Ordinary RO (RELRO/mprotect)
     * has no Soft_COW and must not become writable here.
     */
    if ((old_pte & (PG_PRESENT | PG_US | PG_RW | PG_SOFT_COW)) !=
        (PG_PRESENT | PG_US | PG_SOFT_COW)) {
        rc = -2;
        goto out;
    }
    uint64_t old_pa = old_pte & PG_ADDR_MASK;
    int old_owned = (old_pte & PG_SOFT_OWNED) != 0;

    /* Exclusive owned Soft_COW: reuse the frame (Linux reuse_swap_page path). */
    if (old_owned && frame_refcount(old_pa) == 1) {
        int map_rc;
        if (share_cmp_mm && share_cmp_mm != mm && share_cmp_mm->pml4) {
            map_rc = mm_map_4k_sharedaware(mm, share_cmp_mm->pml4, pg, old_pa,
                                            PG_RW | PG_US | PG_SOFT_OWNED);
        } else {
            map_rc = mm_map_4k_private_force(mm, pg, old_pa,
                                             PG_RW | PG_US | PG_SOFT_OWNED);
        }
        rc = (map_rc == 0) ? 0 : -1;
        goto out;
    }

    /* Lunaix/Linux do_wp_page: a write to shared COW always gets a private copy. */
    uint64_t service_cr3 = paging_read_cr3();
    if (syscall_pipe_watch_active) {
        static int cow_stage_left = 12;
        if (cow_stage_left-- > 0)
            devel_printf("cow-stage: va=0x%llx old=0x%llx want=0x%llx svc=0x%llx saved=0x%llx\n",
                    (unsigned long long)pg,
                    (unsigned long long)old_pa,
                    (unsigned long long)want_cr3,
                    (unsigned long long)service_cr3,
                    (unsigned long long)saved_cr3);
    }
    void *newp = mm_user_frame_alloc_avoid_va(pg, 0);
    if (!newp) {
        rc = -1;
        goto out;
    }
    if (syscall_pipe_watch_active) {
        static int cow_alloc_left = 12;
        if (cow_alloc_left-- > 0)
            devel_printf("cow-alloc: va=0x%llx new=0x%llx\n",
                    (unsigned long long)pg,
                    (unsigned long long)(uintptr_t)newp);
    }
    memcpy(newp, (void *)(uintptr_t)old_pa, (size_t)PAGE_SIZE_4K);
    int map_rc;
    if (share_cmp_mm && share_cmp_mm != mm && share_cmp_mm->pml4) {
        map_rc = mm_map_4k_sharedaware(mm, share_cmp_mm->pml4, pg,
                                        (uint64_t)(uintptr_t)newp,
                                        PG_RW | PG_US | PG_SOFT_OWNED);
    } else {
        map_rc = mm_map_4k_private_force(mm, pg, (uint64_t)(uintptr_t)newp,
                                         PG_RW | PG_US | PG_SOFT_OWNED);
    }
    if (map_rc != 0) {
        mm_user_frame_put(newp);
        rc = -1;
        goto out;
    }
    if (syscall_pipe_watch_active) {
        static int cow_map_left = 12;
        if (cow_map_left-- > 0)
            devel_printf("cow-map: va=0x%llx rc=%d\n",
                    (unsigned long long)pg, map_rc);
    }

    /* Validate by walking the target tables through the direct map. */
    asm volatile("mfence" ::: "memory");
    uint64_t new_pte = 0;
    uint64_t writable_pa = 0;
    if (mm_va_leaf_entry_direct(mm, pg, &new_pte) != 0) {
        rc = -3;
        goto out;
    }
    if (syscall_pipe_watch_active)
        devel_printf("cow-verify-pte: va=0x%llx pte=0x%llx\n",
                (unsigned long long)pg,
                (unsigned long long)new_pte);
    if ((new_pte & (PG_PRESENT | PG_RW)) != (PG_PRESENT | PG_RW)) {
        rc = -4;
        goto out;
    }
    if ((new_pte & PG_ADDR_MASK) == old_pa) {
        rc = -5;
        goto out;
    }
    if (new_pte & PG_SOFT_COW) {
        rc = -6;
        goto out;
    }
    if (!(new_pte & PG_SOFT_OWNED)) {
        rc = -7;
        goto out;
    }
    if (mm_user_leaf_pa_direct(mm, pg, 1, &writable_pa) != 0 ||
        (writable_pa & PG_ADDR_MASK) != (new_pte & PG_ADDR_MASK)) {
        rc = -8;
        goto out;
    }
    if (syscall_pipe_watch_active)
        devel_printf("cow-verify-pa: va=0x%llx pa=0x%llx old=0x%llx refs=%u owned=%d\n",
                (unsigned long long)pg,
                (unsigned long long)writable_pa,
                (unsigned long long)old_pa,
                frame_refcount(old_pa), old_owned);
    /* Identity Soft_COW leaves never took a frame ref — do not release PA==VA. */
    if (old_owned)
        frame_release(old_pa);
    if (syscall_pipe_watch_active)
        devel_printf("cow-release: va=0x%llx old=0x%llx refs=%u\n",
                (unsigned long long)pg,
                (unsigned long long)old_pa,
                frame_refcount(old_pa));
    rc = 0;
out:
    if (syscall_pipe_watch_active)
        devel_printf("cow-leave: va=0x%llx rc=%d active=0x%llx saved=0x%llx\n",
                (unsigned long long)pg, rc,
                (unsigned long long)paging_read_cr3(),
                (unsigned long long)saved_cr3);
    mm_leave_direct_map(dm);
    if (syscall_pipe_watch_active)
        devel_printf("cow-restored: va=0x%llx rc=%d cr3=0x%llx\n",
                (unsigned long long)pg, rc,
                (unsigned long long)paging_read_cr3());
    /* Reloading the caller CR3 above flushes its TLB. If it was already the
     * target mm, be explicit for implementations retaining global entries. */
    if (want_cr3 && (saved_cr3 & ~0xFFFULL) == (want_cr3 & ~0xFFFULL))
        invlpg((void *)(uintptr_t)pg);
    if (syscall_pipe_watch_active)
        devel_printf("cow-done: va=0x%llx rc=%d\n",
                (unsigned long long)pg, rc);
    return rc;
}

int mm_break_cow_range_for_write(mm_t *mm, mm_t *share_cmp_mm,
                                 uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4 || va_end < va_begin)
        return -1;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT)
        end = (uint64_t)MMIO_IDENTITY_LIMIT;
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_4K) {
        uint64_t pte = 0;
        if (mm_va_leaf_entry(mm, va, &pte) != 0)
            continue;
        if (!(pte & PG_SOFT_COW))
            continue;
        /* Soft_COW identity leaves have no Soft_OWNED — still break on write. */
        if (mm_cow_fault_page(mm, va, share_cmp_mm) != 0)
            return -1;
    }
    return 0;
}

/*
 * Linux do_wp_page for a present write fault on a private writable mapping
 * that is not Soft_COW (stale identity / demoted US leaf left RO). RELRO and
 * mprotect(PROT_READ) must keep vma_writable==0 so this returns -1 → SIGSEGV.
 */
int mm_wp_fault_writable(mm_t *mm, uint64_t va, mm_t *share_cmp_mm) {
    if (!mm || !mm->pml4)
        return -1;
    uint64_t pg = va & ~0xFFFULL;
    if (pg < 0x1000ULL || pg >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    if (mm_cow_fault_page(mm, va, share_cmp_mm) == 0)
        return 0;
    /* Copy-privatize identity (or remake a private RW leaf). */
    if (mm_privatize_identity_range(mm, pg, pg + 0x1000ULL) == 0) {
        uint64_t pte = 0;
        if (mm_va_leaf_entry(mm, pg, &pte) == 0 &&
            (pte & (PG_PRESENT | PG_RW | PG_US)) ==
                (PG_PRESENT | PG_RW | PG_US) &&
            !(pte & PG_SOFT_COW))
            return 0;
    }
    if (mm_make_private_range_noyield(mm, pg, pg + 0x1000ULL, 1,
                                      share_cmp_mm) == 0)
        return 0;
    /*
     * Never copy_old=0 here: zero-replacing a present stack/TLS leaf wiped
     * glibc canaries (TCGETS → isatty → "*** stack smashing detected ***").
     */
    return -1;
}

/* True when `mm` already owns a private 4K leaf at `va` (not still sharing
 * the baseline/identity leaf). copy_old=0 / bulk_zero must not replace these —
 * re-zeroing wiped a prior PT_LOAD (.text → 00 00 → #PF CR2=0). */
static int mm_va_has_private_4k(mm_t *mm, uint64_t *share_l4, uint64_t va) {
    if (!mm || !mm->pml4 || !share_l4) return 0;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t e4 = mm->pml4[l4i];
    if (!(e4 & PG_PRESENT) || (e4 & PG_PS_2M) || !pt_page_pa_ok(e4)) return 0;
    if ((e4 & ~0xFFFULL) == (share_l4[l4i] & ~0xFFFULL)) return 0;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[l3i];
    if (!(e3 & PG_PRESENT) || (e3 & PG_PS_2M) || !pt_page_pa_ok(e3)) return 0;
    uint64_t se4 = share_l4[l4i];
    if ((se4 & PG_PRESENT) && pt_page_pa_ok(se4) && !(se4 & PG_PS_2M)) {
        uint64_t *sl3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
        uint64_t se3 = sl3[l3i];
        if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) &&
            (e3 & ~0xFFFULL) == (se3 & ~0xFFFULL))
            return 0;
    }
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[l2i];
    if (!(e2 & PG_PRESENT) || (e2 & PG_PS_2M) || !pt_page_pa_ok(e2)) return 0;
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    uint64_t e1 = l1[l1i];
    if (!(e1 & PG_PRESENT) || !pt_page_pa_ok(e1)) return 0;
    /* Identity leaf still has pa == va; real private backing does not. */
    if ((e1 & PG_ADDR_MASK) == (va & ~0xFFFULL)) return 0;
    /*
     * Own page tables are not enough: after a shallow L1 dup the leaf PA can
     * still be the share/oldmm frame (vfork parent stack). Treating that as
     * private let exec tip bulk_zero skip and argv publish smash ash.
     */
    {
        uint64_t se4b = share_l4[l4i];
        if ((se4b & PG_PRESENT) && pt_page_pa_ok(se4b) && !(se4b & PG_PS_2M)) {
            uint64_t *sl3 = (uint64_t *)(uintptr_t)(se4b & ~0xFFFULL);
            uint64_t se3 = sl3[l3i];
            if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3)) {
                uint64_t *sl2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
                uint64_t se2 = sl2[l2i];
                if ((se2 & PG_PRESENT) && !(se2 & PG_PS_2M) && pt_page_pa_ok(se2)) {
                    uint64_t *sl1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
                    uint64_t se1 = sl1[l1i];
                    if ((se1 & PG_PRESENT) && pt_page_pa_ok(se1) &&
                        (se1 & PG_ADDR_MASK) == (e1 & PG_ADDR_MASK))
                        return 0;
                } else if ((se2 & PG_PRESENT) && (se2 & PG_PS_2M)) {
                    uint64_t spa = (se2 & PG_ADDR_MASK_2M) |
                                   (va & (PAGE_SIZE_2M - 1ULL));
                    if ((spa & PG_ADDR_MASK) == (e1 & PG_ADDR_MASK))
                        return 0;
                }
            }
        }
    }
    return 1;
}

/* Resolve the 4K leaf PA for va in mm's page tables (0 if unmapped/huge). */
int mm_va_leaf_pa(mm_t *mm, uint64_t va, uint64_t *pa_out) {
    if (!mm || !mm->pml4 || !pa_out) return -1;
    va &= ~0xFFFULL;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t e4 = mm->pml4[l4i];
    if (!(e4 & PG_PRESENT) || (e4 & PG_PS_2M) || !pt_page_pa_ok(e4)) return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[l3i];
    if (!(e3 & PG_PRESENT) || (e3 & PG_PS_2M) || !pt_page_pa_ok(e3)) {
        /* 2MiB/1GiB leaf: PA == aligned VA for identity. */
        if ((e3 & PG_PRESENT) && (e3 & PG_PS_2M)) {
            *pa_out = (e3 & PG_ADDR_MASK_1G) | (va & 0x3FFFFFULL);
            return 0;
        }
        return -1;
    }
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[l2i];
    if (!(e2 & PG_PRESENT) || !pt_page_pa_ok(e2)) return -1;
    if (e2 & PG_PS_2M) {
        *pa_out = (e2 & PG_ADDR_MASK_2M) |
                  (va & (PAGE_SIZE_2M - 1ULL));
        *pa_out &= ~0xFFFULL;
        return 0;
    }
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    uint64_t e1 = l1[l1i];
    if (!(e1 & PG_PRESENT) || !pt_page_pa_ok(e1)) return -1;
    *pa_out = e1 & PG_ADDR_MASK;
    return 0;
}

static int mm_va_leaf_entry_direct(mm_t *mm, uint64_t va,
                                   uint64_t *entry_out) {
    if (!mm || !mm->pml4 || !entry_out ||
        va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    uint64_t e4 = mm->pml4[(va >> 39) & 0x1FF];
    if (!(e4 & PG_PRESENT) || (e4 & PG_PS_2M) || !pt_page_pa_ok(e4))
        return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[(va >> 30) & 0x1FF];
    if (!(e3 & PG_PRESENT))
        return -1;
    if (e3 & PG_PS_2M) {
        *entry_out = e3;
        return 0;
    }
    if (!pt_page_pa_ok(e3))
        return -1;
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[(va >> 21) & 0x1FF];
    if (!(e2 & PG_PRESENT))
        return -1;
    if (e2 & PG_PS_2M) {
        *entry_out = e2;
        return 0;
    }
    if (!pt_page_pa_ok(e2))
        return -1;
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    uint64_t e1 = l1[(va >> 12) & 0x1FF];
    if (!(e1 & PG_PRESENT))
        return -1;
    *entry_out = e1;
    return 0;
}

static int mm_va_leaf_entry(mm_t *mm, uint64_t va, uint64_t *entry_out) {
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = mm_va_leaf_entry_direct(mm, va, entry_out);
    mm_leave_direct_map(dm);
    return rc;
}

static int mm_user_leaf_pa_direct(mm_t *mm, uint64_t va, int write,
                                  uint64_t *pa_out) {
    if (!mm || !mm->pml4 || !pa_out || va >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    uint64_t e4 = mm->pml4[(va >> 39) & 0x1FF];
    if ((e4 & (PG_PRESENT | PG_US)) != (PG_PRESENT | PG_US) ||
        (write && !(e4 & PG_RW)) || !pt_page_pa_ok(e4))
        return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[(va >> 30) & 0x1FF];
    if ((e3 & (PG_PRESENT | PG_US)) != (PG_PRESENT | PG_US) ||
        (write && !(e3 & PG_RW)))
        return -1;
    if (e3 & PG_PS_2M) {
        *pa_out = (e3 & PG_ADDR_MASK_1G) + (va & 0x3FFFFFFFULL);
        return 0;
    }
    if (!pt_page_pa_ok(e3))
        return -1;
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[(va >> 21) & 0x1FF];
    if ((e2 & (PG_PRESENT | PG_US)) != (PG_PRESENT | PG_US) ||
        (write && !(e2 & PG_RW)))
        return -1;
    if (e2 & PG_PS_2M) {
        *pa_out = (e2 & PG_ADDR_MASK_2M) +
                  (va & (PAGE_SIZE_2M - 1ULL));
        return 0;
    }
    if (!pt_page_pa_ok(e2))
        return -1;
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    uint64_t e1 = l1[(va >> 12) & 0x1FF];
    if ((e1 & (PG_PRESENT | PG_US)) != (PG_PRESENT | PG_US) ||
        (write && !(e1 & PG_RW)))
        return -1;
    *pa_out = (e1 & PG_ADDR_MASK) + (va & 0xFFFULL);
    return 0;
}

int mm_user_leaf_pa(mm_t *mm, uint64_t va, int write, uint64_t *pa_out) {
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = mm_user_leaf_pa_direct(mm, va, write, pa_out);
    mm_leave_direct_map(dm);
    return rc;
}

/*
 * Linux get_user_pages-ish: writable private Soft_OWNED leaf at `page`.
 * Identity leaves in the USER_MMAP window are often holes under swapper CR3
 * (demote / PROT_NONE) — never memcpy through PA==VA there (nasm read →
 * copy_to_user Oops CR2≈0x82xxxx). Always finish with a real frame PA.
 */
static int mm_ensure_soft_owned_writable(mm_t *mm, mm_t *share_cmp_mm,
                                         uint64_t page) {
    if (!mm || !mm->pml4 || page >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return -1;
    page &= ~0xFFFULL;
    mm_t *share = share_cmp_mm ? share_cmp_mm : mm_kernel();
    uint64_t existing = 0;
    if (mm_user_leaf_pa(mm, page, 0, &existing) == 0) {
        if ((existing & ~0xFFFULL) == page) {
            if (mm_privatize_identity_range(mm, page, page + 0x1000ULL) != 0)
                return -1;
        }
        int cow = mm_cow_fault_page(mm, page, share);
        if (cow != 0 && cow != -2)
            return -1;
        /*
         * Any present PG_US|PG_RW leaf is fine for kernel stores (wait4 status,
         * siginfo, …). Requiring Soft_OWNED (PA!=VA) rejected identity stack
         * pages → copy_to_user EFAULT → ash treated mountinfo/mount exit(0) as
         * failure → "Unable to mount tmpfs on /run" despite mount(2) ok.
         */
        if (mm_user_leaf_pa(mm, page, 1, &existing) == 0)
            return 0;
        /* Present but not writable — force private RW. */
        if (mm_wp_fault_writable(mm, page, share) == 0 &&
            mm_user_leaf_pa(mm, page, 1, &existing) == 0)
            return 0;
        /*
         * Present user leaf we could not make writable. Must not demand-zero:
         * that replaced stack tip Soft_OWNED pages under TCGETS and cleared
         * the canary at rsp+0x28 → ebegin "*** stack smashing detected ***".
         */
        return -1;
    }
    /*
     * Demand-fill lazy mmap / not-yet-touched anon VMA with a zero page.
     * Never invent zero pages inside an already-committed brk range: a hole
     * there means fork/COW missed the parent's heap, and blank-fill corrupts
     * musl malloc (a_crash → hlt → #GP in tmux: server @ ~0x801xxx).
     */
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        if (t && t->mm == mm) {
            uintptr_t brk_base = t->mm->brk_base ? t->mm->brk_base : t->user_brk_base;
            uintptr_t brk_cur = t->mm->brk_current ? t->mm->brk_current
                                                   : t->user_brk_cur;
            if (brk_base && page >= (uint64_t)brk_base && page < (uint64_t)brk_cur)
                return -1;
            if (!user_vma_allows_write(t, (uintptr_t)page))
                return -1;
        } else {
            return -1;
        }
    }
    if (mm_privatize_identity_range_blank(mm, page, page + 0x1000ULL) != 0)
        return -1;
    if (mm_make_private_range_noyield(mm, page, page + 0x1000ULL, 0, share) != 0)
        return -1;
    if (mm_user_leaf_pa(mm, page, 1, &existing) != 0)
        return -1;
    if ((existing & ~0xFFFULL) == page)
        return -1;
    return 0;
}

/* Copy through Soft_OWNED frame PA under swapper — never user VA / identity. */
static int mm_user_memcpy_via_pa(mm_t *mm, uint64_t va, void *kbuf, size_t n,
                                 int to_user) {
    if (!mm || !kbuf || n == 0)
        return -1;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    uint64_t pa = 0;
    int rc;
    if (to_user)
        rc = mm_user_leaf_pa_direct(mm, va, 1, &pa);
    else {
        rc = mm_user_leaf_pa_direct(mm, va, 0, &pa);
        if (rc != 0) {
            uint64_t ent = 0;
            if (mm_va_leaf_entry_direct(mm, va & ~0xFFFULL, &ent) == 0 &&
                (ent & PG_PRESENT)) {
                pa = (ent & PG_ADDR_MASK) + (va & 0xFFFULL);
                rc = 0;
            }
        }
    }
    if (rc == 0) {
        uint64_t pa_page = pa & ~0xFFFULL;
        uint64_t va_page = va & ~0xFFFULL;
        if (pa_page == va_page) {
            /*
             * Identity leaf (PA==VA): swapper may have a hole at that PA, so
             * bounce under the process CR3 via the user VA. Reads and writes
             * both need this — refusing to_user left wait4 status* stuck at
             * ash's ps_status=-1 while the kernel logged status=0x0, so
             * OpenRC `if ! mount` took the failure path.
             */
            uint64_t proc = (uint64_t)(uintptr_t)mm->pml4;
            paging_write_cr3(proc);
            if (to_user)
                memcpy((void *)(uintptr_t)va, kbuf, n);
            else
                memcpy(kbuf, (const void *)(uintptr_t)va, n);
            invlpg((void *)(uintptr_t)va);
            paging_write_cr3(mm_direct_map_cr3());
            rc = 0;
        } else if (to_user) {
            memcpy((void *)(uintptr_t)pa, kbuf, n);
            /*
             * Soft_OWNED store is via PA under swapper CR3. The task TLB may
             * still cache a prior leaf for this VA (COW break / privatize).
             * BusyBox ash then reads waitpid's *status through the stale TLB
             * entry while mm_copy_from_user (PA) already sees the new value —
             * OpenRC `if ! mount` fails despite wait4 logging status=0x0.
             */
            {
                uint64_t proc = mm->cr3 ? mm->cr3 : (uint64_t)(uintptr_t)mm->pml4;
                paging_write_cr3(proc);
                invlpg((void *)(uintptr_t)va);
                paging_write_cr3(mm_direct_map_cr3());
            }
        } else {
            memcpy(kbuf, (const void *)(uintptr_t)pa, n);
        }
    }
    mm_leave_direct_map(dm);
    return rc;
}

int mm_copy_to_user(mm_t *mm, mm_t *share_cmp_mm, uint64_t dst,
                    const void *src, size_t len) {
    if (!mm || !src || !len || dst >= (uint64_t)MMIO_IDENTITY_LIMIT ||
        len > (size_t)((uint64_t)MMIO_IDENTITY_LIMIT - dst))
        return -1;

    const uint8_t *in = (const uint8_t *)src;
    size_t done = 0;
    while (done < len) {
        uint64_t va = dst + done;
        uint64_t page = va & ~0xFFFULL;
        if (mm_ensure_soft_owned_writable(mm, share_cmp_mm, page) != 0)
            return -1;

        size_t chunk = 0x1000u - (size_t)(va & 0xFFFULL);
        if (chunk > len - done)
            chunk = len - done;

        if (mm_user_memcpy_via_pa(mm, va, (void *)(uintptr_t)(in + done), chunk, 1) != 0)
            return -1;
        done += chunk;
    }
    return 0;
}

int mm_copy_from_user(mm_t *mm, void *dst, uint64_t src, size_t len) {
    if (!mm || !dst || !len || src >= (uint64_t)MMIO_IDENTITY_LIMIT ||
        len > (size_t)((uint64_t)MMIO_IDENTITY_LIMIT - src))
        return -1;

    uint8_t *out = (uint8_t *)dst;
    size_t done = 0;
    while (done < len) {
        uint64_t va = src + done;
        uint64_t page = va & ~0xFFFULL;
        size_t chunk = 0x1000u - (size_t)(va & 0xFFFULL);
        if (chunk > len - done)
            chunk = len - done;
        /*
         * Prefer Soft_OWNED PA under swapper. If the leaf is still identity
         * (or !US after demote), bounce under the process L4 — reads only.
         */
        if (mm_user_memcpy_via_pa(mm, va, out + done, chunk, 0) == 0) {
            done += chunk;
            continue;
        }
        /*
         * Linux copy_from_user on a never-touched anonymous/file VMA
         * demand-fills (zeros). apt write(mmap, cache_size) hits pages that
         * RawAllocate reserved but never stored — without this, we returned
         * EFAULT ("Bad address") and "IO Error saving source cache".
         */
        if (user_vma_fault_lazy_anon(va) &&
            mm_user_memcpy_via_pa(mm, va, out + done, chunk, 0) == 0) {
            done += chunk;
            continue;
        }
        {
            mm_dm_ctx_t dm = mm_enter_direct_map();
            uint64_t ent = 0;
            int rc = -1;
            if (mm_va_leaf_entry_direct(mm, page, &ent) == 0 &&
                (ent & PG_PRESENT)) {
                uint64_t proc = (uint64_t)(uintptr_t)mm->pml4;
                paging_write_cr3(proc);
                memcpy(out + done, (const void *)(uintptr_t)va, chunk);
                paging_write_cr3(mm_direct_map_cr3());
                rc = 0;
            }
            mm_leave_direct_map(dm);
            if (rc != 0)
                return -1;
        }
        done += chunk;
    }
    return 0;
}

static int mm_make_private_range_impl(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                          mm_t *share_cmp_mm, int no_yield) {
    if (!mm || !mm->pml4) return -1;
    mm_dbg_ash_touch(copy_old ? "make-private-copy" : "make-private-zero",
                     mm, va_begin, va_end);
    /* Always restore the caller's CR3. PT software walks use the direct-map
     * (swapper) CR3 — Linux __va — so process PROT_NONE holes cannot Oops
     * while we cast share/parent PTE PAs to pointers. */
    uint64_t caller_cr3 = paging_read_cr3();
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;
    /* Baseline for dup/split decisions:
     * - fork setup usually runs with parent CR3 active, so live CR3 is valid;
     * - COW page fault runs with the child CR3 active, so use the retained
     *   parent/template mm when supplied. */
    uint64_t *share_l4 = NULL;
    uint64_t source_cr3 = 0;
    if (copy_old) {
        /* Prefer an explicit parent/template mm when provided (boot PID1 loads
         * into a disposable mm that is not the caller's thread->mm). Otherwise
         * use the caller's CR3 so fork still matches the parent even if pml4
         * is stale (must not use swapper after mm_enter_direct_map). */
        if (share_cmp_mm && share_cmp_mm->pml4) {
            share_l4 = share_cmp_mm->pml4;
            source_cr3 = share_cmp_mm->cr3 ? share_cmp_mm->cr3
                                           : (uint64_t)(uintptr_t)share_cmp_mm->pml4;
        } else {
            share_l4 = (uint64_t *)(uintptr_t)(caller_cr3 & ~0xFFFULL);
            source_cr3 = caller_cr3;
        }
    } else {
        mm_t *share = share_cmp_mm ? share_cmp_mm : mm_kernel();
        if (!share->pml4) goto out;
        share_l4 = share->pml4;
    }
    if (!share_l4) goto out;
    if (va_end <= va_begin) { rc = 0; goto out; }
    /* Never touch VA >= 4GB: identity map ends at MMIO_IDENTITY_LIMIT.
       Otherwise memcpy from (void*)va would page-fault at 0x100000000. */
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) { rc = 0; goto out; }
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t page_idx = 0;
    /*
     * Allocate refcounted user frames. For copy_old, never
     * read *(va) as content source — resolve the parent's leaf PA and copy
     * from that PA (identity VA under a foreign CR3 is the wrong phys).
     */
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        /* fork(copy_old): force private copy for the full requested range.
         * Skipping pages based on live CR3 probing can leave parent/child sharing
         * heap mappings, which later corrupts userspace malloc metadata. */
        /* exec(copy_old=0): keep pages already privatized in this mm so a later
         * PT_LOAD does not wipe earlier segments in the same 2MiB window. */
        if (!copy_old && mm_va_has_private_4k(mm, share_l4, va))
            continue;
        /*
         * Soft_COW leaves still carry parent content. Zero-replace would wipe
         * the shared frame if L1 were still aliased — skip; COW fault copies.
         */
        if (!copy_old) {
            int l4i = (int)((va >> 39) & 0x1FF);
            int l3i = (int)((va >> 30) & 0x1FF);
            int l2i = (int)((va >> 21) & 0x1FF);
            int l1i = (int)((va >> 12) & 0x1FF);
            uint64_t e4 = mm->pml4[l4i];
            if ((e4 & PG_PRESENT) && !(e4 & PG_PS_2M) && pt_page_pa_ok(e4)) {
                uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
                uint64_t e3 = l3[l3i];
                if ((e3 & PG_PRESENT) && !(e3 & PG_PS_2M) && pt_page_pa_ok(e3)) {
                    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
                    uint64_t e2 = l2[l2i];
                    if ((e2 & (PG_PRESENT | PG_PS_2M | PG_SOFT_COW)) ==
                        (PG_PRESENT | PG_PS_2M | PG_SOFT_COW))
                        continue;
                    if ((e2 & PG_PRESENT) && !(e2 & PG_PS_2M) && pt_page_pa_ok(e2)) {
                        uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
                        if (l1[l1i] & PG_SOFT_COW)
                            continue;
                    }
                }
            }
        }
        /* fork() can duplicate many 4K pages — yield periodically.
         * Drop direct-map CR3 + IF across yield; re-enter after. */
        if (copy_old && !no_yield && (++page_idx & 31u) == 0u) {
            mm_leave_direct_map(dm);
            thread_yield();
            dm = mm_enter_direct_map();
        }
        uint64_t replaced_pa = 0;
        uint64_t replaced_pte = 0;
        int had_replaced = (mm_va_leaf_pa(mm, va, &replaced_pa) == 0);
        if (had_replaced)
            (void)mm_va_leaf_entry(mm, va, &replaced_pte);
        void *newp = mm_user_frame_alloc_avoid_va(va, !copy_old);
        if (!newp) goto out;
        if (copy_old) {
            uint64_t spa = 0;
            mm_t *src_mm = share_cmp_mm;
            int got_pa = -1;
            if (src_mm && src_mm->pml4)
                got_pa = mm_va_leaf_pa(src_mm, va, &spa);
            if (got_pa != 0) {
                /* Parent has no leaf — skip (do not map identity garbage). */
                mm_user_frame_put(newp);
                continue;
            }
            spa &= ~0xFFFULL;
            if (spa >= (uint64_t)MMIO_IDENTITY_LIMIT) {
                mm_user_frame_put(newp);
                goto out;
            }
            memcpy(newp, (void *)(uintptr_t)spa, (size_t)PAGE_SIZE_4K);
        }
        (void)source_cr3;
        /*
         * The whole range is already processed under one direct-map context.
         * Calling the public wrapper here would switch CR3 and restore the
         * interrupt state once per 4K page, making exec PT_LOAD construction
         * take seconds on bare metal.
         */
        if (mm_map_4k_sharedaware_body(mm, share_l4, va,
                                      (uint64_t)(uintptr_t)newp,
                                      PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
            mm_user_frame_put(newp);
            goto out;
        }
        if (had_replaced &&
            (replaced_pa & ~0xFFFULL) !=
                ((uint64_t)(uintptr_t)newp & ~0xFFFULL) &&
            (replaced_pte & PG_SOFT_OWNED))
            frame_release(replaced_pa);
        /* Guard against sharedaware "success" that left an identity leaf. */
        {
            uint64_t got = 0;
            if (mm_va_leaf_pa(mm, va, &got) != 0 ||
                (got & ~0xFFFULL) == (va & ~0xFFFULL) ||
                (got & ~0xFFFULL) != ((uint64_t)(uintptr_t)newp & ~0xFFFULL)) {
                kprintf("priv-map-bug: va=0x%llx want=0x%llx got=0x%llx\n",
                    (unsigned long long)va,
                    (unsigned long long)(uintptr_t)newp,
                    (unsigned long long)got);
                goto out;
            }
        }
    }
    rc = 0;
out:
    mm_leave_direct_map(dm);
    return rc;
}

int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                          mm_t *share_cmp_mm) {
    return mm_make_private_range_impl(mm, va_begin, va_end, copy_old, share_cmp_mm, 0);
}

int mm_make_private_range_noyield(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                                  mm_t *share_cmp_mm) {
    return mm_make_private_range_impl(mm, va_begin, va_end, copy_old, share_cmp_mm, 1);
}

static int mm_make_private_range_bulk_zero_ex(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                             mm_t *share_cmp_mm, int force_replace) {
    if (!mm || !mm->pml4 || va_end <= va_begin)
        return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT)
        va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (begin >= end)
        return -1;

    mm_t *share = share_cmp_mm ? share_cmp_mm : mm_kernel();
    if (!share || !share->pml4)
        return -1;
    uint64_t *share_l4 = share->pml4;
    mm_dm_ctx_t dm = mm_enter_direct_map();
    int rc = -1;

    /*
     * Keep the historical API name, but allocate ordinary refcounted pages.
     * A contiguous kmalloc block tied backing lifetime to one mm and made fork
     * peers retain dangling PTEs after that owner execed.
     */
    for (uint64_t pg = begin; pg < end; pg += PAGE_SIZE_4K) {
        if (!force_replace && mm_va_has_private_4k(mm, share_l4, pg))
            continue;

        uint64_t replaced_pa = 0;
        uint64_t replaced_pte = 0;
        int had_replaced = (mm_va_leaf_pa(mm, pg, &replaced_pa) == 0);
        if (had_replaced)
            (void)mm_va_leaf_entry(mm, pg, &replaced_pte);
        void *page = mm_user_frame_alloc_avoid_va(pg, 1);
        if (!page)
            goto out;
        uint64_t want = (uint64_t)(uintptr_t)page;
        if (mm_map_4k_sharedaware_body(mm, share_l4, pg, want,
                                      PG_RW | PG_US | PG_SOFT_OWNED) != 0) {
            mm_user_frame_put(page);
            goto out;
        }
        if (had_replaced &&
            (replaced_pa & ~0xFFFULL) != (want & ~0xFFFULL) &&
            (replaced_pte & PG_SOFT_OWNED))
            frame_release(replaced_pa);

        uint64_t got = 0;
        if (mm_va_leaf_pa(mm, pg, &got) != 0 ||
            (got & ~0xFFFULL) == (pg & ~0xFFFULL) ||
            (got & ~0xFFFULL) != (want & ~0xFFFULL)) {
            kprintf("bulk-zero-bug: va=0x%llx want=0x%llx got=0x%llx\n",
                    (unsigned long long)pg,
                    (unsigned long long)want,
                    (unsigned long long)got);
            goto out;
        }
    }
    rc = 0;
out:
    mm_leave_direct_map(dm);
    return rc;
}

int mm_make_private_range_bulk_zero(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                    mm_t *share_cmp_mm) {
    return mm_make_private_range_bulk_zero_ex(mm, va_begin, va_end, share_cmp_mm, 0);
}

int mm_make_private_range_bulk_zero_force(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                          mm_t *share_cmp_mm) {
    return mm_make_private_range_bulk_zero_ex(mm, va_begin, va_end, share_cmp_mm, 1);
}

/* ---- ash watch: track smash of command-name slab @ 0x801738 ---- */

static const char *g_ash_last_touch = "?";
static uint64_t g_ash_last_touch_mm_cr3;
static uint64_t g_ash_last_touch_lo;
static uint64_t g_ash_last_touch_hi;
/* Per-mm snapshot so child exec does not false-CHANGED the parent watch. */
static uint64_t g_ash_snap_mm_cr3;
static uint64_t g_ash_snap_pa;
static uint8_t g_ash_snap_bytes[16];
static int g_ash_snap_valid;
/* Parent ash mm_cr3 + leaf PA captured at vfork-share for smash detection. */
static uint64_t g_ash_parent_mm_cr3;
static uint64_t g_ash_parent_pa;

int mm_dbg_ash_overlaps(uint64_t lo, uint64_t hi) {
#if !DEVEL_DEBUG
    (void)lo;
    (void)hi;
    return 0;
#else
    if (hi <= lo)
        return 0;
    return (lo < MM_ASH_WATCH_HI && hi > MM_ASH_WATCH_LO) ? 1 : 0;
#endif
}

static int mm_dbg_ash_leaf_flags(mm_t *mm, uint64_t va, uint64_t *pa_out,
                                 uint64_t *pte_out, int *is_2m_out) {
    if (!mm || !mm->pml4 || !pa_out)
        return -1;
    va &= ~0xFFFULL;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t e4 = mm->pml4[l4i];
    if (!(e4 & PG_PRESENT) || (e4 & PG_PS_2M) || !pt_page_pa_ok(e4))
        return -1;
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & ~0xFFFULL);
    uint64_t e3 = l3[l3i];
    if (!(e3 & PG_PRESENT) || !pt_page_pa_ok(e3))
        return -1;
    if (e3 & PG_PS_2M) {
        *pa_out = (e3 & PG_ADDR_MASK_1G) |
                  (va & ((1ULL << 30) - 1ULL));
        *pa_out &= PG_ADDR_MASK;
        if (pte_out) *pte_out = e3;
        if (is_2m_out) *is_2m_out = 1;
        return 0;
    }
    uint64_t *l2 = (uint64_t *)(uintptr_t)(e3 & ~0xFFFULL);
    uint64_t e2 = l2[l2i];
    if (!(e2 & PG_PRESENT) || !pt_page_pa_ok(e2))
        return -1;
    if (e2 & PG_PS_2M) {
        *pa_out = (e2 & PG_ADDR_MASK_2M) |
                  (va & (PAGE_SIZE_2M - 1ULL));
        *pa_out &= PG_ADDR_MASK;
        if (pte_out) *pte_out = e2;
        if (is_2m_out) *is_2m_out = 1;
        return 0;
    }
    uint64_t *l1 = (uint64_t *)(uintptr_t)(e2 & ~0xFFFULL);
    uint64_t e1 = l1[l1i];
    if (!(e1 & PG_PRESENT) || !pt_page_pa_ok(e1))
        return -1;
    *pa_out = e1 & PG_ADDR_MASK;
    if (pte_out) *pte_out = e1;
    if (is_2m_out) *is_2m_out = 0;
    return 0;
}

void mm_dbg_ash_watch(const char *tag, mm_t *mm) {
#if !DEVEL_DEBUG
    (void)tag;
    (void)mm;
    return;
#else
    if (!tag)
        tag = "?";
    if (!mm || !mm->pml4) {
        devel_printf("ash-watch: %s mm=NULL\n", tag);
        return;
    }
    uint64_t va = MM_ASH_WATCH_VA;
    uint64_t pa = 0, pte = 0;
    int is2m = 0;
    int rc = mm_dbg_ash_leaf_flags(mm, va, &pa, &pte, &is2m);
    uint64_t mm_cr3 = mm->cr3 ? (mm->cr3 & ~0xFFFULL) : ((uint64_t)(uintptr_t)mm->pml4 & ~0xFFFULL);
    uint64_t live = paging_read_cr3() & ~0xFFFULL;
    if (rc != 0) {
        devel_printf("ash-watch: %s mm_cr3=0x%llx live=0x%llx va=0x%llx NO_LEAF ref=%d\n",
                tag, (unsigned long long)mm_cr3, (unsigned long long)live,
                (unsigned long long)va, mm->refcount);
        return;
    }
    int ident = (pa == (va & ~0xFFFULL)) ? 1 : 0;
    uint64_t off = va & 0xFFFULL;
    const uint8_t *bytes = (const uint8_t *)(uintptr_t)(pa + off);
    devel_printf("ash-watch: %s mm_cr3=0x%llx live=0x%llx va=0x%llx pa=0x%llx ident=%d 2m=%d "
            "P=%d W=%d U=%d COW=%d ref=%d bytes=%02x %02x %02x %02x %02x %02x %02x %02x "
            "last=%s@0x%llx\n",
            tag,
            (unsigned long long)mm_cr3,
            (unsigned long long)live,
            (unsigned long long)va,
            (unsigned long long)pa,
            ident, is2m,
            (int)!!(pte & PG_PRESENT),
            (int)!!(pte & PG_RW),
            (int)!!(pte & PG_US),
            (int)!!(pte & PG_SOFT_COW),
            mm->refcount,
            (unsigned)bytes[0], (unsigned)bytes[1], (unsigned)bytes[2], (unsigned)bytes[3],
            (unsigned)bytes[4], (unsigned)bytes[5], (unsigned)bytes[6], (unsigned)bytes[7],
            g_ash_last_touch,
            (unsigned long long)g_ash_last_touch_mm_cr3);
    if (g_ash_snap_valid && g_ash_snap_mm_cr3 == mm_cr3 &&
        (g_ash_snap_pa != pa ||
         memcmp(g_ash_snap_bytes, bytes, 8) != 0)) {
        devel_printf("ash-watch: %s CHANGED was_pa=0x%llx was=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                tag,
                (unsigned long long)g_ash_snap_pa,
                (unsigned)g_ash_snap_bytes[0], (unsigned)g_ash_snap_bytes[1],
                (unsigned)g_ash_snap_bytes[2], (unsigned)g_ash_snap_bytes[3],
                (unsigned)g_ash_snap_bytes[4], (unsigned)g_ash_snap_bytes[5],
                (unsigned)g_ash_snap_bytes[6], (unsigned)g_ash_snap_bytes[7]);
    }
    if (g_ash_parent_mm_cr3 && mm_cr3 == g_ash_parent_mm_cr3 &&
        g_ash_parent_pa && (pa & ~0xFFFULL) != (g_ash_parent_pa & ~0xFFFULL)) {
        devel_printf("ash-watch: %s PARENT_SMASH expect_pa=0x%llx now_pa=0x%llx\n",
                tag,
                (unsigned long long)g_ash_parent_pa,
                (unsigned long long)pa);
    }
    g_ash_snap_mm_cr3 = mm_cr3;
    g_ash_snap_pa = pa;
    memcpy(g_ash_snap_bytes, bytes, 16);
    g_ash_snap_valid = 1;
#endif
}

void mm_dbg_ash_watch_thread(const char *tag, thread_t *t) {
#if !DEVEL_DEBUG
    (void)tag;
    (void)t;
#else
    if (!t) {
        devel_printf("ash-watch: %s thread=NULL\n", tag ? tag : "?");
        return;
    }
    devel_printf("ash-watch: %s tid=%d name=%s fs=0x%llx brk=0x%llx-0x%llx vfork_wait=%d tmpl=%d\n",
            tag ? tag : "?",
            (int)(t->tid ? t->tid : 1),
            t->name[0] ? t->name : "?",
            (unsigned long long)t->user_fs_base,
            (unsigned long long)(t->mm && t->mm->brk_base ? t->mm->brk_base : t->user_brk_base),
            (unsigned long long)(t->mm && t->mm->brk_current ? t->mm->brk_current : t->user_brk_cur),
            t->vfork_waiting ? 1 : 0,
            t->mm_ptemplate ? 1 : 0);
    if (tag && strstr(tag, "vfork-share-parent") && t->mm && t->mm->pml4) {
        uint64_t ppa = 0;
        if (mm_va_leaf_pa(t->mm, MM_ASH_WATCH_VA, &ppa) == 0) {
            g_ash_parent_mm_cr3 = t->mm->cr3 ? (t->mm->cr3 & ~0xFFFULL)
                : ((uint64_t)(uintptr_t)t->mm->pml4 & ~0xFFFULL);
            g_ash_parent_pa = ppa & ~0xFFFULL;
            devel_printf("ash-watch: pin-parent mm_cr3=0x%llx pa=0x%llx\n",
                    (unsigned long long)g_ash_parent_mm_cr3,
                    (unsigned long long)g_ash_parent_pa);
        }
    }
    mm_dbg_ash_watch(tag, t->mm);
    if (t->mm_ptemplate && t->mm_ptemplate != t->mm)
        mm_dbg_ash_watch("tmpl", t->mm_ptemplate);
#endif
}

void mm_dbg_ash_touch(const char *tag, mm_t *mm, uint64_t lo, uint64_t hi) {
#if !DEVEL_DEBUG
    (void)tag;
    (void)mm;
    (void)lo;
    (void)hi;
#else
    if (!mm_dbg_ash_overlaps(lo, hi))
        return;
    g_ash_last_touch = tag ? tag : "?";
    g_ash_last_touch_mm_cr3 = (mm && mm->cr3) ? (mm->cr3 & ~0xFFFULL) :
        (mm && mm->pml4) ? ((uint64_t)(uintptr_t)mm->pml4 & ~0xFFFULL) : 0;
    g_ash_last_touch_lo = lo;
    g_ash_last_touch_hi = hi;
#endif
}
