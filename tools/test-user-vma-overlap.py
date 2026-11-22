#!/usr/bin/env python3
"""Check file text VMAs win over stale anonymous ELF reservations."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_vma.c").read_text()
def snippet(begin, end):
    return source[source.index(begin):source.index(end, source.index(begin))]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define USER_VMA_MAX 16
#define USER_VMA_MM_MAX USER_VMA_MAX
#define USER_VMA_KIND_MMAP 1
#define USER_VMA_KIND_SHM 2
#define USER_VMA_KIND_MMAP_LAZY 3
#define USER_VMA_KIND_ELF_LOAD 4
typedef struct { int lock; } spinlock_t;
typedef struct fs_file { const char *path; int refs; } fs_file;
typedef struct user_vma {
    int used, prot, kind;
    uint64_t tid, file_off;
    uintptr_t addr;
    size_t len;
    fs_file *file;
} user_vma_t;
typedef struct mm { user_vma_t *vma_storage; } mm_t;
typedef struct thread { int tid, ring; mm_t *mm; } thread_t;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;
static mm_t mm;
static user_vma_t mm_vmas[USER_VMA_MAX];
static thread_t runner = {.tid=1, .ring=3, .mm=&mm};
static void acquire_irqsave(spinlock_t *l, unsigned long *flags) {
    assert(!l->lock); l->lock=1; *flags=0;
}
static void release_irqrestore(spinlock_t *l, unsigned long flags) {
    (void)flags; assert(l->lock); l->lock=0;
}
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) {
    (void)create; return m ? m->vma_storage : NULL;
}
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t tid) {
    (void)t; return tid == 1;
}
static thread_t *thread_get(int tid) { return tid == 1 ? &runner : NULL; }
static void fs_file_get(fs_file *f) { f->refs++; }
static void fs_file_free(fs_file *f) { f->refs--; }
static void user_vma_drop_file_nolock(user_vma_t *v) {
    if (v->file) fs_file_free(v->file);
    v->file = NULL;
}
static int user_vma_add_mm(mm_t *m, uintptr_t addr, size_t len, int prot, int kind) {
    for (int i=0; i<USER_VMA_MAX; i++)
        if (!m->vma_storage[i].used) {
            m->vma_storage[i] = (user_vma_t) {
                .used=1,.addr=addr,.len=len,.prot=prot,.kind=kind
            };
            return 0;
        }
    return -1;
}
''' + snippet("static int user_vma_is_better_containing(",
               "static int user_vma_add_nolock(") + snippet(
                   "static int user_vma_add_nolock(",
                   "static int user_vma_split_at_nolock(") + snippet(
                       "static user_vma_t *user_vma_find_fault_nolock(",
                       "static int user_vma_split_runner_at_nolock(") + snippet(
                           "int user_vma_lookup_after(",
                           "int user_vma_grow(") + snippet(
                               "int user_vma_add_file(",
                               "/*\n * Linux filemap_fault") + r'''
int main(void) {
    mm.vma_storage = mm_vmas;
    /* A long anonymous reservation precedes the real executable segment. */
    g_user_vmas[0] = (user_vma_t) {
        .used=1, .tid=1, .addr=0x82e5000, .len=0x288000,
        .prot=5, .kind=USER_VMA_KIND_MMAP_LAZY
    };
    mm_vmas[0] = g_user_vmas[0];
    fs_file lib = {.path="libsystemd-shared-257.so"};
    assert(user_vma_add_file(1, 0x8390000, 0x80000, 5,
        USER_VMA_KIND_MMAP_LAZY, &lib, 0x145000) == 0);
    assert(g_user_vmas[0].file == NULL); /* no attachment to reservation */
    assert(user_vma_find_containing_nolock(1, 0x83a0010) &&
           user_vma_find_containing_nolock(1, 0x83a0010)->file == &lib);
    user_vma_t *hit = user_vma_find_fault_nolock(&runner, 0x83a0010);
    assert(hit && hit->file == &lib && hit->file_off == 0x145000);
    uintptr_t start=0,end=0;
    int kind=0,prot=0;
    fs_file *out=NULL;
    uint64_t off=0;
    assert(user_vma_lookup_after(&runner, 0x83a0010, &start, &end,
                                  &kind, &prot, &out, &off) == 0);
    assert(start == 0x8390000 && off == 0x145000 && out == &lib);
    fs_file_free(out);
    assert(user_vma_find_fault_nolock(&runner, 0x82e5000)->file == NULL);
    /* An mm-scoped file mapping takes precedence over the stale global one. */
    g_user_vmas[1].used = 0;
    assert(user_vma_find_fault_nolock(&runner, 0x83a0010)->file == &lib);
    puts("PASS: overlapping ELF text uses exact file VMA, not zero-filled reservation");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-vma-overlap-", dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
