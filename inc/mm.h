#pragma once

#include <stdint.h>
#include <spinlock.h>

struct thread;
typedef struct thread thread_t;

typedef struct mm_struct {
    /* Top-level page table (virtual pointer to identity-mapped physical page).
     * Linux separates mm_struct (page tables, refcount) from the VMA rb_tree in
     * struct mm_struct; AxonOS keeps user VMAs in mm/user_vma.c and mmap/brk cursors
     * in mm/user_as.c (per-thread fields + CLONE_VM publish). */
    uint64_t *pml4;
    /* CR3 value used for this address space. */
    uint64_t cr3;
    /* Backing allocation for aligned pml4 (used for release). */
    void *pml4_alloc_raw;
    /* Backing allocations for page-table pages and private user pages created via kmalloc_aligned().
       Each entry is the original `raw` pointer that must be freed (aligned pointer is interior). */
    struct mm_alloc_node *allocs;
    int refcount;
    spinlock_t page_table_lock;
    void *vma_storage;
    uintptr_t brk_base;
    uintptr_t brk_current;
    uintptr_t mmap_cursor;
} mm_t;

/* Initialize mm subsystem and capture the bootstrap kernel address space. */
void mm_init(void);

/* Get kernel/default address space descriptor. */
mm_t *mm_kernel(void);

/* Retain/release references to mm. */
mm_t *mm_retain(mm_t *mm);
void mm_release(mm_t *mm);

/* Create a new mm by cloning current L4 entries. */
mm_t *mm_clone_current(void);
/* Clone L4 from an explicit mm (preferred for fork; ignores stale live CR3). */
mm_t *mm_clone_from(mm_t *src);
/* Linux kernel/fork.c mm_alloc() + init_new_context(): nascent mm from swapper
 * (g_kernel_mm). map_page_2m keeps swapper coherent with kernel mappings. */
mm_t *mm_alloc(void);
/* Duplicate one userspace address space. Private VMAs get private frames;
 * shared VMAs retain their backing frames. Parent page tables are unchanged. */
mm_t *mm_dup_user(mm_t *parent, uint64_t owner_tid);
/*
 * After cloning swapper: strip PG_US on user-window identity (keep PRESENT
 * for kernel phys / stack VA pokes under process CR3). Unmap identity only
 * in the brk slab [MM_ASH_WATCH_LO, MM_ASH_WATCH_HI). Stack stays present
 * (~US); vfork-exec isolation is split_2m drop-ident-siblings + tip check.
 * Unmapping the stack slot oopses boot (memcpy to tip, CR2=0x3fffxxxx).
 */
int mm_demote_user_identity(mm_t *mm);

/* Switch CPU CR3 to provided mm (or kernel mm when NULL). */
int mm_switch(mm_t *mm);
/* Leave `dead` before releasing it — never loads stale g_kernel_mm. */
int mm_switch_away_from(mm_t *dead);

/* Ensure [va_begin, va_end) is mapped to private pages in mm.
   If copy_old != 0, old page contents are copied before remap.
 * share_cmp_mm: page tables to compare against when copy_old==0 (exec); if NULL, mm_kernel().
 * When copy_old!=0 (fork), the live parent root is taken from paging_read_cr3(); share_cmp_mm
 * is ignored for split/dup decisions (callers may still pass parent mm for API symmetry). */
int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                          mm_t *share_cmp_mm);
/* Same as mm_make_private_range but never thread_yield (safe inside syscall_do). */
int mm_make_private_range_noyield(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                                  mm_t *share_cmp_mm);
/* Zero-backed private mapping optimized for ELF exec: allocate backing in
 * bounded contiguous blocks while still installing ordinary 4 KiB PTEs.
 * force_replace: tip setup must never skip "already private" leaves — a shallow
 * L1 dup can still share the vfork parent's stack PA (ret→heap after exec). */
int mm_make_private_range_bulk_zero(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                    mm_t *share_cmp_mm);
int mm_make_private_range_bulk_zero_force(mm_t *mm, uint64_t va_begin, uint64_t va_end,
                                          mm_t *share_cmp_mm);
/* Leaf physical address for va in mm (handles 4K and identity huge leaves). */
int mm_va_leaf_pa(mm_t *mm, uint64_t va, uint64_t *pa_out);
/* Resolve a present user leaf and enforce effective read/write permission. */
int mm_user_leaf_pa(mm_t *mm, uint64_t va, int write, uint64_t *pa_out);

/* COW up to max_pages present user-writable 4KiB pages (splits 2MiB when needed).
 * share_l4: parent page table root (NOT paging_read_cr3() — CR3 may differ mid-fork). */
int mm_cow_fork_pages(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out);
/* Same as mm_cow_fork_pages but walks low->high (covers _rtld_global / _IO_list_all). */
int mm_cow_fork_pages_forward(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out);

/* Fork COW: copy only present user-writable pages in [va_begin, va_end). */
int mm_cow_private_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end);
/* Like mm_cow_private_writable but explicit parent pml4, full range, splits 2MiB leaves. */
int mm_cow_private_writable_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end);
/* Like mm_cow_private_writable_l4, but ignores supervisor-only identity pages. */
int mm_cow_private_user_writable_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end);
/* Fork setup: mark child user-writable mappings read-only so write faults COW-copy lazily. */
int mm_cow_mark_user_readonly_l4(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end);
/* Fork setup: mark both parent and child user-writable mappings read-only for Linux-style COW. */
int mm_cow_mark_user_readonly_pair_l4(mm_t *child, mm_t *parent, uint64_t *parent_l4,
                                      uint64_t va_begin, uint64_t va_end);
/* After linuxrc exclusive privatize: drop SOFT_COW and restore PG_RW on parent. */
int mm_cow_restore_user_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end);
/* Fork setup for the complete user address space. This is the correctness
 * baseline; range-specific calls are optional optimizations only. */
int mm_cow_mark_all_user_writable_pair_l4(mm_t *child, mm_t *parent,
                                          uint64_t *parent_l4, uint64_t owner_tid);
/* Vfork-with-clone: Soft_COW mark child only — never write-protect parent PTEs. */
int mm_cow_mark_all_user_writable_child_l4(mm_t *child, uint64_t *parent_l4,
                                           uint64_t owner_tid);
/* Linux-style COW on first user write after fork (single 4K page at cr2). */
int mm_cow_fault_page(mm_t *mm, uint64_t va, mm_t *share_cmp_mm);
int mm_break_cow_range_for_write(mm_t *mm, mm_t *share_cmp_mm,
                                 uint64_t va_begin, uint64_t va_end);

/* Fork child entry: copy up to max_pages live parent pages into child when parent
 * has diverged from shared read-only COW (parent writable or child already private).
 * force_all: copy every present user page in range (not only diverged PTEs).
 * parent_mm must be switched in before call; returns with child_mm active. */
int mm_fork_sync_from_parent(mm_t *child_mm, mm_t *parent_mm, uint64_t va_begin, uint64_t va_end,
                             unsigned max_pages, int force_all);
/* Single-page variant for futex stale-COW recovery. */
int mm_fork_sync_page_from_parent(mm_t *child_mm, mm_t *parent_mm, uint64_t va);

/* Clear [va_begin, va_end) in child mm without touching parent share_l4 mappings.
   Duplicates shared page-table pages one level at a time before clearing PTEs. */
int mm_clear_range_private(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end);
/* Linux munmap: detach user PTEs from one mm and release tracked leaf frames.
 * share_l4 is the fork/exec baseline used to break shared page-table paths. */
int mm_unmap_user_range(mm_t *mm, uint64_t *share_l4,
                        uint64_t va_begin, uint64_t va_end);

/* Replace identity leaves (pa==va) with private frames; copy old contents.
 * Prefer mm_privatize_identity_range_blank for user anon (do_brk_flags). */
int mm_privatize_identity_range(mm_t *mm, uint64_t va_begin, uint64_t va_end);
/* Linux do_brk_flags / anon fault: identity→private with zero pages. */
int mm_privatize_identity_range_blank(mm_t *mm, uint64_t va_begin, uint64_t va_end);

/* ---- ash GPF watch (RIP=="ls" @ 0x801738): DEVEL_DEBUG probes only ---- */
#define MM_ASH_WATCH_VA     0x801738ULL
#define MM_ASH_WATCH_LO     0x800000ULL
#define MM_ASH_WATCH_HI     0xA00000ULL
/* Dump leaf PA / PTE flags / 16 bytes at watch VA for mm (or t->mm). */
void mm_dbg_ash_watch(const char *tag, mm_t *mm);
/* Same, using thread's mm + tid/name/cr3 context. */
void mm_dbg_ash_watch_thread(const char *tag, thread_t *t);
/* Log if [lo,hi) overlaps watch band; records last touch tag. */
void mm_dbg_ash_touch(const char *tag, mm_t *mm, uint64_t lo, uint64_t hi);
/* 1 if [lo,hi) overlaps the watch band. */
int mm_dbg_ash_overlaps(uint64_t lo, uint64_t hi);
