#!/usr/bin/env python3
"""Inherited mm-only VMAs must reserve address space for new mappings."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_vma.c").read_text()
def section(start, end):
    i = source.index(start)
    return source[i:source.index(end, i)]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define USER_VMA_MAX 16
#define USER_VMA_KIND_MMAP 1
#define USER_VMA_KIND_SHM 2
#define USER_VMA_KIND_MMAP_LAZY 3
#define USER_VMA_KIND_ELF_LOAD 4
typedef struct { int used, kind; uint64_t tid; uintptr_t addr; size_t len; } user_vma_t;
typedef struct { user_vma_t *vmas; } mm_t;
typedef struct { int tid; mm_t *mm; } thread_t;
typedef struct { int locked; } spinlock_t;
static user_vma_t g_user_vmas[USER_VMA_MAX], mm_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;
static mm_t mm = {mm_vmas};
static thread_t child = {2, &mm};
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->locked); l->locked=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->locked); l->locked=0; }
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) { (void)create; return m ? m->vmas : NULL; }
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t tid) { return t && (uint64_t)t->tid == tid; }
static uintptr_t user_mm_align_up(uintptr_t x, uintptr_t a) { return (x + a - 1) & ~(a - 1); }
static uintptr_t user_mm_align_down(uintptr_t x, uintptr_t a) { return x & ~(a - 1); }
''' + section("static int user_vma_kind_is_mmap_like(", "/* File-backed mapping") + section(
    "uintptr_t user_vma_max_mmap_like_end_for_mm_nolock(", "size_t user_vma_total_size_for_mm(") + section(
    "int user_vma_overlaps_thread_range(", "void user_vma_remove_all_for_tid(") + r'''
int main(void) {
    /* Inherited library exists only in the child mm, not g_user_vmas. */
    mm_vmas[0] = (user_vma_t){.used=1, .kind=USER_VMA_KIND_MMAP_LAZY,
        .addr=0x8009000, .len=0x57000};
    assert(user_vma_max_mmap_like_end_for_mm(&child) == 0x8060000);
    assert(user_vma_overlaps_thread_range(&child, 0x8018810, 1));
    assert(user_vma_mmap_range_overlaps(&child, 0x8009000, 0x1000));
    assert(!user_vma_mmap_range_overlaps(&child, 0x8060000, 0x1000));
    /* Reusing a loader hint over the inherited image must choose a free gap. */
    assert(user_vma_find_unmapped(&child, 0x8000000, 0x8100000,
                                  0x1000, 0x8009000, 0x1000) == 0x8000000);
    assert(user_vma_find_unmapped(&child, 0x8009000, 0x8100000,
                                  0x1000, 0, 0x1000) == 0x8060000);
    assert(user_vma_find_unmapped_topdown(&child, 0x8000000, 0x8060000,
                                          0x1000, 0x1000) == 0x8008000);
    /* A global-only reservation must still be considered alongside mm VMAs. */
    g_user_vmas[0] = (user_vma_t){.used=1, .tid=2, .kind=USER_VMA_KIND_MMAP,
        .addr=0x8060000, .len=0x2000};
    assert(user_vma_find_unmapped(&child, 0x8009000, 0x8100000,
                                  0x1000, 0, 0x1000) == 0x8062000);
    puts("PASS: mmap gap search and NOREPLACE respect mm-only inherited VMAs");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-mm-gaps-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
