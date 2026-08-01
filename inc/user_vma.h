#pragma once

#include <stdint.h>
#include <stddef.h>
#include <thread.h>

#define USER_VMA_MAX 4096

enum {
    USER_VMA_KIND_MMAP = 1,
    USER_VMA_KIND_SHM = 2,
    USER_VMA_KIND_MMAP_LAZY = 3,
    USER_VMA_KIND_ELF_LOAD = 4,
};

struct fs_file;

typedef struct {
    int used;
    uint64_t tid;
    uintptr_t addr;
    size_t len;
    int prot;
    int kind;
    /* File-backed MAP_PRIVATE (lazy): page at addr+i ← file at file_off+i. */
    struct fs_file *file;
    uint64_t file_off;
} user_vma_t;

/* Register a file-backed lazy VMA (retains file). kind: MMAP_LAZY or ELF_LOAD. */
int user_vma_add_file(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind,
                      struct fs_file *file, uint64_t file_off);

void user_vma_remove_all_for_tid(uint64_t tid);
/* Unmap page tables for all VMAs in runner's address space and drop metadata. */
void user_vma_teardown_unmap_for_exec(thread_t *runner);
int user_vma_clone_for_tid(uint64_t from_tid, uint64_t to_tid);

/* Mark all writable private VMAs as parent/child COW at fork. */
int user_vma_fork_privatize_mapped(mm_t *child_mm, mm_t *parent_mm,
                                   uint64_t *parent_l4, uint64_t from_tid);
/* True if VA falls in a MAP_SHARED / SysV SHM VMA for this tid (must not COW). */
int user_vma_is_shared_page(uint64_t tid, uintptr_t va);
/* True if runner's address space has a VMA covering va with PROT_WRITE. */
int user_vma_allows_write(thread_t *runner, uintptr_t va);
/* True if tid has any VMA covering va (ELF/mmap). Used by fork to not skip
 * identity-mapped image pages that lack Soft_OWNED. */
int user_vma_covers_page(uint64_t tid, uintptr_t va);
/*
 * True if va is in a file-backed MMAP_LAZY / ELF_LOAD VMA.  Fork must not
 * memcpy identity phys there — those bytes are not the file image.
 */
int user_vma_is_lazy_file_page(uint64_t tid, uintptr_t va);

int user_vma_add(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind);
int user_vma_add_mm(mm_t *mm, uintptr_t addr, size_t len, int prot, int kind);
int user_vma_is_shared_page_mm(mm_t *mm, uintptr_t va);
int user_vma_clone_mm(mm_t *dst, mm_t *src);
int user_vma_can_unmap_range(uint64_t tid, uintptr_t addr, size_t len);
int user_vma_unmap_range(uint64_t tid, uintptr_t addr, size_t len);
int user_vma_set_prot(uint64_t tid, uintptr_t addr, size_t len, int prot);
int user_vma_is_fully_mapped(uint64_t tid, uintptr_t addr, size_t len);

size_t user_vma_total_size_for_mm(thread_t *runner);
uintptr_t user_vma_max_mmap_like_end(uint64_t tid);
uintptr_t user_vma_max_mmap_like_end_for_mm(thread_t *runner);
uintptr_t user_vma_min_mmap_like_for_thread(thread_t *tcur, uintptr_t brk_base);
/* True if [addr,addr+len) intersects any VMA tracked for runner's address space. */
int user_vma_overlaps_thread_range(thread_t *runner, uintptr_t addr, size_t len);
int user_vma_mmap_range_overlaps(thread_t *runner, uintptr_t addr, size_t len);
/*
 * Linux get_unmapped_area (bottom-up): first free [floor,ceil) gap of len,
 * aligned to `align` (power of two). Soft `hint` preferred when free.
 * Returns 0 if no gap fits.
 */
uintptr_t user_vma_find_unmapped(thread_t *runner, uintptr_t floor, uintptr_t ceil,
                                 uint64_t len, uintptr_t hint, uintptr_t align);
/*
 * Top-down gap search (Linux arch_get_unmapped_area_topdown style).
 * Used for large Go PROT_NONE arenas so low VA stays free for glibc brk/mmap.
 */
uintptr_t user_vma_find_unmapped_topdown(thread_t *runner, uintptr_t floor,
                                         uintptr_t ceil, uint64_t len,
                                         uintptr_t align);

int user_vma_fault_lazy_anon(uint64_t cr2);
int user_vma_fault_nonpresent(uint64_t cr2, uint64_t err);
