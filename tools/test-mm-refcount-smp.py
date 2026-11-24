#!/usr/bin/env python3
"""Concurrent mm references must not be lost or destroyed prematurely."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/mm.c").read_text()

def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]

program = r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
typedef struct mm_alloc_node { void *raw; struct mm_alloc_node *next; } mm_alloc_node_t;
typedef struct mm { int refcount; void *allocs, *vma_storage, *pml4_alloc_raw; } mm_t;
static mm_t g_kernel_mm = {.refcount=1}, shared = {.refcount=1};
static atomic_int frees;
static mm_t *mm_kernel(void) { return &g_kernel_mm; }
static void mm_release_user_frames(mm_t *m) { (void)m; }
static void user_vma_release_mm(mm_t *m) { (void)m; }
static void kfree(void *p) { if (p == &shared) atomic_fetch_add(&frees, 1); }
''' + function("mm_t *mm_retain(") + function("void mm_release(") + r'''
static void *work(void *unused) {
    (void)unused;
    for (int i=0; i<100000; ++i) {
        assert(mm_retain(&shared) == &shared);
        mm_release(&shared);
    }
    mm_release(&shared); /* worker's initial reference */
    return NULL;
}
int main(void) {
    pthread_t t[8];
    for (int i=0; i<8; ++i) {
        assert(mm_retain(&shared));
        assert(pthread_create(&t[i], NULL, work, NULL) == 0);
    }
    for (int i=0; i<8; ++i) assert(pthread_join(t[i], NULL) == 0);
    assert(shared.refcount == 1 && atomic_load(&frees) == 0);
    mm_release(&shared);
    assert(shared.refcount == 0 && atomic_load(&frees) == 1);
    assert(mm_retain(&shared) == NULL); /* no resurrection */
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mm-ref-smp-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: concurrent mm reference accounting")
