#!/usr/bin/env python3
"""Unmap must not index the smaller mm table with the global table bound."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_vma.c").read_text()
start = source.index("int user_vma_unmap_range(")
end = source.index("\nint user_vma_set_prot(", start)
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define USER_VMA_MAX 16
#define USER_VMA_MM_MAX 4
typedef struct { int used; uint64_t tid; uintptr_t addr; size_t len; } user_vma_t;
typedef struct { int dummy; } mm_t;
typedef struct { mm_t *mm; } thread_t;
typedef int spinlock_t;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static user_vma_t mm_vmas[USER_VMA_MM_MAX];
static spinlock_t g_user_vma_lock;
static mm_t mm;
static thread_t thread = {&mm};
static thread_t *thread_get(int tid) { return tid == 1 ? &thread : NULL; }
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { (void)l; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)l; (void)f; }
static int user_vma_unmap_capacity_nolock(thread_t *t, uintptr_t a, uintptr_t b) { (void)t; (void)a; (void)b; return 0; }
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) { (void)m; (void)create; return mm_vmas; }
static int user_vma_split_runner_at_nolock(thread_t *t, uintptr_t a) { (void)t; (void)a; return 0; }
static int user_vma_split_mm_at_nolock(user_vma_t *v, uintptr_t a) { (void)v; (void)a; return 0; }
static int user_vma_split_at_nolock(uint64_t t, uintptr_t a) { (void)t; (void)a; return 0; }
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t tid) { (void)t; return tid == 1; }
static void user_vma_clear_nolock(user_vma_t *v) { v->used=0; }
''' + source[start:end] + r'''
int main(void) {
    g_user_vmas[15] = (user_vma_t){1,1,0x1000,0x1000};
    mm_vmas[3] = (user_vma_t){1,1,0x1000,0x1000};
    assert(user_vma_unmap_range(1,0x1000,0x1000)==0);
    assert(!g_user_vmas[15].used && !mm_vmas[3].used);
    puts("PASS: unmap respects independent global and per-mm VMA bounds");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-unmap-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
