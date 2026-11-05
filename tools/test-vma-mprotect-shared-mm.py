#!/usr/bin/env python3
"""mprotect must recognize and update file VMAs shared between threads."""
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
typedef struct fs_file { int refs; } fs_file;
typedef struct user_vma {
    int used, prot, kind; uint64_t tid, file_off; uintptr_t addr; size_t len;
    fs_file *file;
} user_vma_t;
#define USER_VMA_MAX 16
typedef struct { user_vma_t *vmas; } mm_t;
typedef struct { int tid, ring; mm_t *mm; } thread_t;
typedef struct { int locked; } spinlock_t;
static user_vma_t g_user_vmas[USER_VMA_MAX], mm_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;
static mm_t shared = {mm_vmas};
static thread_t threads[] = {{1,3,&shared}, {2,3,&shared}};
static void acquire_irqsave(spinlock_t *l, unsigned long *flags) {
    assert(!l->locked); l->locked=1; *flags=0;
}
static void release_irqrestore(spinlock_t *l, unsigned long flags) {
    (void)flags; assert(l->locked); l->locked=0;
}
static int thread_get_count(void) { return 2; }
static thread_t *thread_get_by_index(int i) { return &threads[i]; }
static thread_t *thread_get(int tid) { return tid == 1 ? &threads[0] : tid == 2 ? &threads[1] : NULL; }
static user_vma_t *user_vma_mm_storage(mm_t *mm, int create) {
    (void)create; return mm ? mm->vmas : NULL;
}
static void fs_file_get(fs_file *file) { file->refs++; }
''' + section("static int user_vma_is_better_containing(", "int user_vma_add(") + section(
    "int user_vma_set_prot(", "uintptr_t user_vma_max_mmap_like_end_nolock(") + r'''
int main(void) {
    fs_file file = {2};
    g_user_vmas[0] = (user_vma_t){.used=1, .tid=1, .addr=0x8000000,
        .len=0x4000, .prot=5, .kind=3, .file=&file, .file_off=0xdd000};
    mm_vmas[0] = g_user_vmas[0];
    assert(user_vma_is_fully_mapped(2, 0x8001000, 0x2000));
    assert(!user_vma_is_fully_mapped(2, 0x8001000, 0x4000));
    assert(!user_vma_is_fully_mapped(2, UINTPTR_MAX-2, 8));
    assert(user_vma_set_prot(2, 0x8001000, 0x2000, 3) == 0);
    user_vma_t *g = user_vma_find_containing_nolock(1, 0x8001000);
    user_vma_t *m = user_vma_find_fault_nolock(&threads[1], 0x8001000);
    assert(g && m && g->prot == 3 && m->prot == 3);
    assert(g->file == &file && m->file == &file);
    assert(g->file_off == 0xde000 && m->file_off == 0xde000);
    assert(user_vma_find_containing_nolock(1, 0x8000000)->prot == 5);
    assert(user_vma_find_containing_nolock(1, 0x8003000)->prot == 5);
    /* mm-only inherited file mappings must also be recognized and updated. */
    for (int i=0; i<USER_VMA_MAX; i++) g_user_vmas[i].used=0;
    assert(user_vma_is_fully_mapped(2, 0x8001000, 0x2000));
    assert(user_vma_set_prot(2, 0x8001000, 0x2000, 1) == 0);
    m = user_vma_find_fault_nolock(&threads[1], 0x8001000);
    assert(m && m->file == &file && m->prot == 1 && m->file_off == 0xde000);
    puts("PASS: shared-mm mprotect preserves file VMAs, offsets and protections");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-mprotect-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
