#!/usr/bin/env python3
"""Destroying an mm releases its independently owned file references."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_vma.c").read_text()
mm_source = (root / "core/mm.c").read_text()
start = source.index("void user_vma_release_mm(")
end = source.index("\n}\n", start) + 3
release = mm_source[mm_source.index("void mm_release(mm_t *mm)"):mm_source.index("mm_t *mm_clone_current", mm_source.index("void mm_release(mm_t *mm)"))]
assert release.index("user_vma_release_mm(mm);") < release.index("kfree(mm->vma_storage);")
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#define USER_VMA_MAX 4
typedef struct { int used; int *refs; } user_vma_t;
typedef struct { void *vma_storage; } mm_t;
typedef struct { int locked; } spinlock_t;
static spinlock_t g_user_vma_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->locked); l->locked=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->locked); l->locked=0; }
static void user_vma_clear_nolock(user_vma_t *v) { if (v->refs) --*v->refs; v->used=0; }
''' + source[start:end] + r'''
int main(void) {
    int refs=3;
    user_vma_t entries[USER_VMA_MAX]={{1,&refs},{1,&refs},{0,&refs},{0,0}};
    mm_t mm={entries};
    user_vma_release_mm(&mm);
    assert(refs==1 && !entries[0].used && !entries[1].used);
    user_vma_release_mm(&mm); assert(refs==1);
    user_vma_release_mm(NULL);
    puts("PASS: mm teardown drops each mm-owned VMA file reference once");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-release-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
