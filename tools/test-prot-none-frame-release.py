#!/usr/bin/env python3
"""PROT_NONE must not leak owned frames on munmap or mm teardown."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
mapping = (root / "mm/user_map.c").read_text()


def function(source, signature):
    start = source.index(signature)
    end = source.index("\n}\n", start) + 2
    return source[start:end]


program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#define PAGE_SIZE_4K 4096ULL
#define PAGE_SIZE_2M (2ULL * 1024 * 1024)
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_DATA_REGION_LO 0x200000ULL
#define USER_DATA_REGION_HI 0x10000000ULL
#define PG_PRESENT 1ULL
#define PG_RW 2ULL
#define PG_US 4ULL
#define PG_PS_2M 128ULL
#define PG_SOFT_COW (1ULL << 10)
#define PG_SOFT_OWNED (1ULL << 11)
#define PG_NX (1ULL << 63)
#define PG_ADDR_MASK 0x000ffffffffff000ULL
#define PG_ADDR_MASK_2M 0x000fffffffe00000ULL
#define PG_ADDR_MASK_1G 0x000fffffc0000000ULL
typedef struct { uint64_t *pml4; uint64_t cr3; } mm_t;
typedef struct { mm_t *mm; } thread_t;
typedef int mm_dm_ctx_t;
static mm_t kernel, task;
#define g_kernel_mm kernel
static thread_t thread = { &task };
static int releases;
static uint64_t released_pa;
static int path_fails;
static mm_t *mm_kernel(void) { return &kernel; }
static thread_t *thread_get_current_user(void) { return &thread; }
static thread_t *thread_current(void) { return &thread; }
static uint64_t paging_read_cr3(void) { return task.cr3; }
static void paging_write_cr3(uint64_t cr3) { (void)cr3; }
static uint64_t mm_direct_map_cr3(void) { return kernel.cr3; }
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t dm) { (void)dm; }
static void invlpg(void *va) { (void)va; }
static int pt_page_pa_ok(uint64_t e) { return (e & PG_ADDR_MASK) < MMIO_IDENTITY_LIMIT; }
static int mm_owns_pt_page(mm_t *mm, const uint64_t *pt) { (void)mm; (void)pt; return 0; }
static void frame_release(uint64_t pa) { releases++; released_pa = pa; }
static int split_2m_to_4k(mm_t *mm, uint64_t *l2, int i, uint64_t va) {
    (void)mm; (void)l2; (void)i; (void)va; assert(0); return -1;
}
static int mm_fork_private_pt_path(mm_t *mm, uint64_t *share, uint64_t va,
                                   uint64_t **l2out, int *index, uint64_t **l1out) {
    (void)share;
    if (path_fails) return -1;
    uint64_t *l3 = (void *)(uintptr_t)(mm->pml4[0] & PG_ADDR_MASK);
    uint64_t *l2 = (void *)(uintptr_t)(l3[(va >> 30) & 511] & PG_ADDR_MASK);
    *index = (va >> 21) & 511;
    *l2out = l2;
    *l1out = (void *)(uintptr_t)(l2[*index] & PG_ADDR_MASK);
    return 0;
}
''' + function(mm, 'int mm_va_leaf_pa(') + '\n' + function(mm, 'static int mm_va_leaf_entry_direct(mm_t *mm, uint64_t va,\n') + '\n' + function(mm, 'static uint64_t *mm_leaf_pte_direct(') + '\n' + function(mm, 'int mm_unmap_user_range(') + '\n' + function(mm, 'static void mm_release_user_frames(') + '\n' + function(mapping, 'int user_map_mprotect_range(') + r'''
static uint64_t *page(void) {
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(p != MAP_FAILED && (uintptr_t)p < MMIO_IDENTITY_LIMIT);
    return p;
}
int main(void) {
    const uint64_t va = 0x20000000, pa = 0x12345000;
    uint64_t *l4 = page(), *l3 = page(), *l2 = page(), *l1 = page();
    task.pml4 = l4; task.cr3 = (uintptr_t)l4;
    kernel.pml4 = page(); kernel.cr3 = (uintptr_t)kernel.pml4;
    l4[0] = (uintptr_t)l3 | PG_PRESENT | PG_RW | PG_US;
    l3[0] = (uintptr_t)l2 | PG_PRESENT | PG_RW | PG_US;
    l2[va >> 21] = (uintptr_t)l1 | PG_PRESENT | PG_RW | PG_US;
    l1[0] = pa | PG_PRESENT | PG_RW | PG_US | PG_SOFT_OWNED;
    uint64_t entry;
    assert(mm_va_leaf_entry_direct(&task, va, &entry) == 0);
    assert(user_map_mprotect_range(va, va + 4096, 0) == 0);
    assert(l1[0] == (pa | PG_SOFT_OWNED));
    /* A failed preparation must leave the protected mapping and ref intact. */
    path_fails = 1;
    assert(mm_unmap_user_range(&task, kernel.pml4, va, va + 4096) == -1);
    assert(releases == 0 && l1[0] == (pa | PG_SOFT_OWNED));
    path_fails = 0;
    assert(user_map_mprotect_range(va, va + 4096, 3) == 0);
    assert((l1[0] & PG_ADDR_MASK) == pa);
    assert((l1[0] & (PG_PRESENT | PG_US | PG_RW | PG_SOFT_OWNED)) ==
           (PG_PRESENT | PG_US | PG_RW | PG_SOFT_OWNED));
    assert(user_map_mprotect_range(va, va + 4096, 0) == 0);
    assert(mm_unmap_user_range(&task, kernel.pml4, va, va + 4096) == 0);
    assert(releases == 1 && released_pa == pa && l1[0] == 0);
    assert(mm_unmap_user_range(&task, kernel.pml4, va, va + 4096) == 0);
    assert(user_map_mprotect_range(va, va + 4096, 3) == 0 && l1[0] == 0);
    assert(releases == 1);
    l1[0] = pa | PG_PRESENT | PG_RW | PG_US | PG_SOFT_OWNED;
    assert(user_map_mprotect_range(va, va + 4096, 0) == 0);
    l1[1] = (pa + 4096) | PG_SOFT_OWNED | PG_SOFT_COW;
    assert(user_map_mprotect_range(va + 4096, va + 8192, 3) == 0);
    assert((l1[1] & (PG_PRESENT | PG_US | PG_RW | PG_SOFT_COW)) ==
           (PG_PRESENT | PG_US | PG_SOFT_COW));
    assert(user_map_mprotect_range(va + 4096, va + 8192, 0) == 0);
    mm_release_user_frames(&task);
    assert(releases == 3 && released_pa == pa + 4096);
    puts("PASS: PROT_NONE restore, munmap and mm teardown");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-prot-none-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
