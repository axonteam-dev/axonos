#!/usr/bin/env python3
"""Host regression for the real lazy VMA file-fill path at an x86 fetch boundary.

Page tables, filesystem and locking are modeled; the VMA selection, page read,
file fill and lazy-fault functions are extracted from the kernel source.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
vma = (root / "mm/user_vma.c").read_text()
idt = (root / "cpu/ints/idt.c").read_text()

def part(source, begin, end):
    start = source.index(begin)
    return source[start:source.index(end, start)]

# Exercise the actual demand-dispatch statement rather than a RIP-based model.
dispatch = part(idt, '        /* Demand-fill only for !present', '        pfdbg("demand"')
dispatch = dispatch.replace('return;', 'return 1;')

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_STACK_TOP 0x40000000ULL
#define PAGE_SIZE_2M 0x200000ULL
#define USER_VMA_MAX 2
#define USER_VMA_MM_MAX USER_VMA_MAX
#define USER_VMA_KIND_MMAP 1
#define USER_VMA_KIND_SHM 2
#define USER_VMA_KIND_MMAP_LAZY 3
#define USER_VMA_KIND_ELF_LOAD 4
#define PG_PRESENT 1
#define PG_RW 2
#define PG_US 4
typedef struct fs_file { int64_t size; const char *path; } fs_file;
typedef struct user_vma { int used, kind, prot; uint64_t tid, file_off; uintptr_t addr; size_t len; fs_file *file; } user_vma_t;
typedef struct mm { void *pml4; uint64_t cr3; } mm_t;
typedef struct thread { int ring, tid, linux_tgid; char name[16]; mm_t *mm, *mm_ptemplate; } thread_t;
static mm_t kernel = {.pml4=(void *)1}, process = {.pml4=(void *)2};
static thread_t thread = {.ring=3,.tid=1,.mm=&process};
static user_vma_t vmas[USER_VMA_MAX], g_user_vmas[USER_VMA_MAX];
static int g_user_vma_lock;
static uint8_t file_bytes[65536], mapped[4096];
static size_t read_limit = 4096, stop_at = (size_t)-1;
static uint64_t mapped_va; static int mapped_prot;
static thread_t *thread_current(void) { return &thread; }
static thread_t *thread_get_current_user(void) { return &thread; }
static mm_t *mm_kernel(void) { return &kernel; }
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) { (void)m; (void)create; return vmas; }
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t id) { (void)t; return id==1; }
static void acquire_irqsave(int *l, unsigned long *f) { (void)l; *f=0; }
static void release_irqrestore(int *l, unsigned long f) { (void)l; (void)f; }
static uintptr_t user_as_mmap_brk_top_limit(thread_t *t) { (void)t; return USER_STACK_TOP; }
static int uv_is_libcom_err_file(const user_vma_t *v) { (void)v; return 0; }
static int uv_is_pg_file(const user_vma_t *v) { (void)v; return 0; }
static void uv_trace_one(const char *s, ...) { (void)s; }
static void klogprintf(const char *s, ...) { (void)s; }
static uint64_t paging_read_cr3(void) { return 0; }
static ssize_t fs_read(fs_file *f, void *out, size_t n, size_t off) {
    (void)f; if (off >= stop_at || off >= sizeof(file_bytes)) return 0;
    if (n > sizeof(file_bytes)-off) n=sizeof(file_bytes)-off;
    if (n > stop_at-off) n=stop_at-off;
    if (n > read_limit) n=read_limit;
    memcpy(out,file_bytes+off,n); return (ssize_t)n;
}
static int mm_va_leaf_pa(mm_t *m, uint64_t va, uint64_t *pa) { (void)m;(void)va;(void)pa;return -1; }
static int mm_copy_to_user(mm_t *m, mm_t *s, uint64_t va, const void *buf, size_t n) {
    (void)m;(void)s; assert(va==mapped_va && n==4096); memcpy(mapped,buf,n); return 0;
}
static int mm_privatize_identity_range_blank(mm_t *m, uint64_t lo, uint64_t hi) {
    (void)m; assert(hi==lo+4096); mapped_va=lo; memset(mapped,0,4096); return 0;
}
static int mm_make_private_range_noyield(mm_t *m,uint64_t lo,uint64_t hi,int z,mm_t *s) {
    (void)m;(void)lo;(void)hi;(void)z;(void)s;return 0;
}
static int user_map_mprotect_range(uint64_t lo,uint64_t hi,int prot) {
    assert(lo==mapped_va && hi==lo+4096); mapped_prot=prot; return 0;
}
static int user_vma_map_shared_file_page(thread_t *t,const user_vma_t *v,uint64_t lo) { (void)t;(void)v;(void)lo;return 0; }
static int map_page_2m(uint64_t a,uint64_t b,int f) { (void)a;(void)b;(void)f;return -1; }
''' + part(vma, 'static int user_vma_is_filemap(', '/* MAP_FIXED file segments') + part(
    vma, 'static int user_vma_is_better_containing(', 'static user_vma_t *user_vma_find_containing_nolock(') + part(
    vma, 'static user_vma_t *user_vma_find_fault_nolock(', 'static int user_vma_split_runner_at_nolock(') + part(
    vma, 'static int user_vma_read_file_page(', 'int user_vma_fault_nonpresent(') + r'''
static int fault_try_mmap_lazy_anon(uint64_t cr2) { return user_vma_fault_lazy_anon(cr2); }
typedef struct { uint64_t rip, error_code; } cpu_registers_t;
static int dispatch_fetch(cpu_registers_t *regs, uint64_t cr2) {
    int user = 1;
''' + dispatch + r'''
    return 0;
}
int main(void) {
    fs_file file = {.size=sizeof(file_bytes), .path="/lib/libXi.so.6"};
    const uint64_t base=0x805f000, cr2=0x806a000;
    cpu_registers_t regs={.rip=0x8069ffe,.error_code=0x14};
    vmas[0]=(user_vma_t){.used=1,.kind=3,.prot=5,.addr=base,.len=0xc000,.file=&file,.file_off=0};
    const size_t off=0xb000;
    for (size_t i=0;i<sizeof(file_bytes);i++) file_bytes[i]=(uint8_t)(i*31+7);
    file_bytes[off-2]=0xb8; file_bytes[off-1]=0x78;
    file_bytes[off]=0x56; file_bytes[off+1]=0x34; file_bytes[off+2]=0x12;
    read_limit=127;
    assert(dispatch_fetch(&regs,cr2)==1);
    assert(regs.rip==cr2-2 && mapped_va==cr2 && mapped_prot==5);
    assert(memcmp(mapped,file_bytes+off,4096)==0);
    assert(file_bytes[off-2]==0xb8 && mapped[0]==0x56 && mapped[2]==0x12);
    file.size=off+3; mapped_prot=0;
    assert(dispatch_fetch(&regs,cr2)==1 && mapped_prot==5);
    assert(memcmp(mapped,file_bytes+off,3)==0);
    for (size_t i=3;i<4096;i++) assert(mapped[i]==0);
    file.size=off; assert(dispatch_fetch(&regs,cr2)==0);
    file.size=off+4096; stop_at=off+200; assert(dispatch_fetch(&regs,cr2)==0);
    puts("PASS: cross-page CR2 dispatch, partial reads, EOF tail and failed reads");
}
'''

with tempfile.TemporaryDirectory(prefix="fetch-boundary-", dir="/tmp/opencode") as tmp:
    src = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    src.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-variable",
                    "-fsanitize=undefined", str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
