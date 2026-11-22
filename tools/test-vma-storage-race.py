#!/usr/bin/env python3
"""Interleave two initial VMA table allocations for a shared mm."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_vma.c").read_text()
start = source.index("static user_vma_t *user_vma_mm_storage(")
end = source.index("\n}\n", start) + 3
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define USER_VMA_MAX 4
#define USER_VMA_MM_MAX USER_VMA_MAX
typedef struct { int used; } user_vma_t;
typedef struct { void *vma_storage; } mm_t;
typedef int spinlock_t;
static spinlock_t g_user_vma_lock;
static mm_t shared;
static int nested, frees;
static user_vma_t *user_vma_mm_storage(mm_t *, int);
static void *kmalloc(size_t n) {
    void *p = malloc(n);
    assert(p);
    if (!nested++) {
        user_vma_t *v = user_vma_mm_storage(&shared, 1);
        assert(v);
        v[0].used = 42;
    }
    return p;
}
static void kfree(void *p) { ++frees; free(p); }
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!*l); *l=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(*l); *l=0; }
''' + source[start:end] + r'''
int main(void) {
    user_vma_t *v = user_vma_mm_storage(&shared, 1);
    assert(v == shared.vma_storage && v[0].used == 42 && frees == 1);
    free(shared.vma_storage);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-storage-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: shared mm publishes one VMA table and frees the losing allocation")
