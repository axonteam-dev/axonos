#!/usr/bin/env python3
"""File backing must attach to the VMA kind that mmap just registered."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_vma.c").read_text()
i = source.index("int user_vma_add_file(")
helper = source[i:source.index("\n}\n", i) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define USER_VMA_MAX 4
#define USER_VMA_KIND_MMAP 1
#define USER_VMA_KIND_SHM 2
#define USER_VMA_KIND_MMAP_LAZY 3
#define USER_VMA_KIND_ELF_LOAD 4
struct fs_file { int refs; };
typedef struct { int used, kind, prot; uint64_t tid, file_off; uintptr_t addr;
                 size_t len; struct fs_file *file; } user_vma_t;
typedef struct { user_vma_t *vmas; } mm_t;
typedef struct { mm_t *mm; } thread_t;
typedef struct { int held; } spinlock_t;
static user_vma_t g_user_vmas[USER_VMA_MAX], mm_vmas[USER_VMA_MAX];
static mm_t mm = {mm_vmas};
static thread_t thread = {&mm};
static spinlock_t g_user_vma_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->held); l->held=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->held); l->held=0; }
static thread_t *thread_get(int tid) { return tid == 1 ? &thread : NULL; }
static void fs_file_get(struct fs_file *f) { f->refs++; }
static void user_vma_drop_file_nolock(user_vma_t *v) { v->file->refs--; v->file=NULL; }
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) { (void)create; return m->vmas; }
static int user_vma_add_nolock(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind) {
    for (int i=0; i<USER_VMA_MAX; i++) if (!g_user_vmas[i].used) {
        g_user_vmas[i] = (user_vma_t){.used=1,.tid=tid,.addr=addr,.len=len,.prot=prot,.kind=kind}; return 0;
    } return -1;
}
static int user_vma_add_mm(mm_t *m, uintptr_t addr, size_t len, int prot, int kind) {
    for (int i=0; i<USER_VMA_MAX; i++) if (!m->vmas[i].used) {
        m->vmas[i] = (user_vma_t){.used=1,.addr=addr,.len=len,.prot=prot,.kind=kind}; return 0;
    } return -1;
}
''' + helper + r'''
int main(void) {
    struct fs_file old={1}, file={0};
    mm_vmas[0] = (user_vma_t){.used=1,.addr=0x8009000,.len=0x2000,
        .kind=USER_VMA_KIND_SHM,.file=&old};
    assert(user_vma_add_file(1,0x8009000,0x2000,5,USER_VMA_KIND_MMAP_LAZY,&file,0xa000)==0);
    assert(mm_vmas[0].file==&old && old.refs==1);
    assert(mm_vmas[1].file==&file && mm_vmas[1].file_off==0xa000);
    assert(g_user_vmas[0].file==&file && file.refs==2);
    puts("PASS: file VMA attaches to its exact kind in mm storage");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-file-kind-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
