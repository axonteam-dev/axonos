#!/usr/bin/env python3
"""Cloning overlapping VMAs must preserve each mapping's file and offset."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_vma.c").read_text()
def extract(start, end):
    i = source.index(start)
    return source[i:source.index(end, i)]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define USER_VMA_MAX 16
struct fs_file { int refs; };
typedef struct { int used, prot, kind; uint64_t tid, file_off; uintptr_t addr;
                 size_t len; struct fs_file *file; } user_vma_t;
typedef struct { int held; } spinlock_t;
static spinlock_t g_user_vma_lock;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->held); l->held=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->held); l->held=0; }
static void fs_file_get(struct fs_file *f) { ++f->refs; }
static void user_vma_drop_file_nolock(user_vma_t *v) { --v->file->refs; v->file=0; }
static void user_vma_clear_nolock(user_vma_t *v) { if (v->file) user_vma_drop_file_nolock(v); v->used=0; }
''' + extract('static int user_vma_add_nolock(', 'static int user_vma_split_at_nolock(') + \
    extract('int user_vma_clone_for_tid(', 'int user_vma_lookup_after(') + r'''
int main(void) {
    struct fs_file small={1}, large={1};
    g_user_vmas[0]=(user_vma_t){.used=1,.tid=1,.addr=0x1000,.len=0x1000,.kind=3,.file=&small,.file_off=0x5000};
    g_user_vmas[1]=(user_vma_t){.used=1,.tid=1,.addr=0x1000,.len=0x4000,.kind=3,.file=&large,.file_off=0x9000};
    assert(user_vma_clone_for_tid(1, 2)==0);
    int found_small=0, found_large=0;
    for (int i=0; i<USER_VMA_MAX; ++i) if (g_user_vmas[i].used && g_user_vmas[i].tid==2) {
        if (g_user_vmas[i].len==0x1000) { assert(g_user_vmas[i].file==&small && g_user_vmas[i].file_off==0x5000); found_small++; }
        if (g_user_vmas[i].len==0x4000) { assert(g_user_vmas[i].file==&large && g_user_vmas[i].file_off==0x9000); found_large++; }
    }
    assert(found_small==1 && found_large==1 && small.refs==2 && large.refs==2);
    puts("PASS: fork clones overlapping VMA backing by exact identity");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-clone-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
