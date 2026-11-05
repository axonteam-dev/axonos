#!/usr/bin/env python3
"""A recycled tid's stale VMA must not override a live mm's mappings."""
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
#define USER_VMA_MAX 8
struct fs_file { int id; };
typedef struct { int used; uint64_t tid; uintptr_t addr; size_t len;
                 struct fs_file *file; } user_vma_t;
typedef struct { user_vma_t *vmas; } mm_t;
typedef struct { mm_t *mm; } thread_t;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static user_vma_t *user_vma_mm_storage(mm_t *mm, int create) { (void)create; return mm ? mm->vmas : NULL; }
/* Simulate tid 26 reused by a thread now pointing at this mm. */
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t tid) { (void)t; return tid==19 || tid==26; }
''' + extract('static int user_vma_is_better_containing(', 'static user_vma_t *user_vma_find_containing_nolock(') + \
    extract('static user_vma_t *user_vma_find_fault_nolock(', 'static int user_vma_split_runner_at_nolock(') + r'''
int main(void) {
    struct fs_file xfce={1}, dbus={2};
    user_vma_t mm_vmas[USER_VMA_MAX]={0};
    mm_t mm={mm_vmas}; thread_t runner={&mm};
    g_user_vmas[0]=(user_vma_t){.used=1,.tid=19,.addr=0x8013000,.len=0xe000,.file=&xfce};
    g_user_vmas[1]=(user_vma_t){.used=1,.tid=26,.addr=0x8017000,.len=0x31000,.file=&dbus};
    mm_vmas[0]=g_user_vmas[0];
    assert(user_vma_find_fault_nolock(&runner,0x8018810)->file==&xfce);
    assert(!user_vma_find_fault_nolock(&runner,0x8040000));
    mm.vmas=NULL;
    assert(user_vma_find_fault_nolock(&runner,0x8018810)->file==&dbus);
    puts("PASS: mm VMAs override stale recycled-tid mirrors, including mm holes");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-authority-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
