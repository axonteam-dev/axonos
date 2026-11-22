#!/usr/bin/env python3
"""Exercise the real anonymous fault and MM walkers with host page tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / 'core/mm.c').read_text()
vma = (root / 'mm/user_vma.c').read_text()

def function(src, name):
    start = src.index(name)
    brace = src.index('{', start)
    depth = 1
    pos = brace + 1
    while depth:
        depth += (src[pos] == '{') - (src[pos] == '}')
        pos += 1
    return src[start:pos] + '\n'

program = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#define PG_PRESENT 1ULL
#define PG_RW 2ULL
#define PG_US 4ULL
#define PG_PWT 8ULL
#define PG_PCD 16ULL
#define PG_PS_2M 128ULL
#define PG_GLOBAL 256ULL
#define PG_SOFT_COW 512ULL
#define PG_SOFT_OWNED 1024ULL
#define PG_NX (1ULL<<63)
#define PG_ADDR_MASK 0x000ffffffffff000ULL
#define PG_ADDR_MASK_2M 0x000fffffffe00000ULL
#define PG_ADDR_MASK_1G 0x000fffffc0000000ULL
#define PAGE_SIZE_4K 4096ULL
#define PAGE_SIZE_2M 0x200000ULL
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_VMA_KIND_SHM 7
#define USER_VMA_KIND_ELF_LOAD 8
#define USER_VMA_KIND_MMAP_LAZY 9
typedef struct mm { uint64_t *pml4; uint64_t cr3; } mm_t;
typedef struct thread { int ring; mm_t *mm, *mm_ptemplate; } thread_t;
typedef struct vma { uintptr_t addr; size_t len; int kind, prot; void *file; uint64_t file_off; } user_vma_t;
typedef int mm_dm_ctx_t;
static mm_t g_kernel_mm, proc;
static int g_mm_ready=1, fail_alloc, nalloc, releases;
static thread_t thread;
static user_vma_t vma;
static int g_user_vma_lock;
static uint64_t *allocated[64]; static int allocated_n;
static void *page(void) { if (fail_alloc && ++nalloc == fail_alloc) return NULL; void *p=aligned_alloc(4096,4096); assert(p); memset(p,0,4096); allocated[allocated_n++]=p; return p; }
static uint64_t *alloc_pt_page(mm_t *m) { (void)m; return page(); }
static uint64_t *dup_pt_page(mm_t *m, uint64_t *src) { uint64_t *p=alloc_pt_page(m); if(p) memcpy(p,src,4096); return p; }
static int mm_owns_pt_page(mm_t *m, const uint64_t *p) { (void)m; for(int i=0;i<allocated_n;i++) if(allocated[i]==p) return 1; return 0; }
static int pt_page_pa_ok(uint64_t e) { return (e & PG_ADDR_MASK)!=0; }
static void invlpg(void *p) { (void)p; }
static void kprintf(const char *fmt, ...) { (void)fmt; }
static void klogprintf(const char *fmt, ...) { (void)fmt; }
static mm_t *mm_kernel(void) { return &g_kernel_mm; }
static thread_t *thread_current(void) { return &thread; }
static thread_t *thread_get_current_user(void) { return &thread; }
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t x) { (void)x; }
static uint64_t paging_read_cr3(void) { return 0; }
static void paging_write_cr3(uint64_t x) { (void)x; }
static uint64_t mm_direct_map_cr3(void) { return 0; }
static void mm_dbg_ash_touch(const char *s, mm_t *m, uint64_t a, uint64_t b) { (void)s;(void)m;(void)a;(void)b; }
static void thread_yield(void) {}
static void *mm_user_frame_alloc_avoid_va(uint64_t va,int zero) { (void)va;(void)zero; return page(); }
static void *mm_user_frame_alloc(int zero) { (void)zero; return page(); }
static void mm_user_frame_put(void *p) { (void)p; releases++; }
static void frame_release(uint64_t p) { (void)p; releases++; }
static int mm_va_leaf_pa(mm_t *,uint64_t,uint64_t *);
static int mm_va_leaf_entry(mm_t *m,uint64_t a,uint64_t *p) { (void)m;(void)a;(void)p; return -1; }
static void acquire_irqsave(int *l,unsigned long *f) { (void)l;(void)f; }
static void release_irqrestore(int *l,unsigned long f) { (void)l;(void)f; }
static user_vma_t *user_vma_find_fault_nolock(thread_t *t,uintptr_t va) { (void)t; return va>=vma.addr && va-vma.addr<vma.len ? &vma:NULL; }
static int uv_is_libcom_err_file(user_vma_t *v) { (void)v; return 0; }
static int user_vma_map_shared_file_page(thread_t *t,user_vma_t *v,uint64_t a) { (void)t;(void)v;(void)a; return 0; }
static int mm_clear_range_private(mm_t *m,uint64_t *p,uint64_t a,uint64_t b) { (void)m;(void)p;(void)a;(void)b; return -1; }
static int map_page_2m(uint64_t a,uint64_t b,uint64_t f) { (void)a;(void)b;(void)f; return -1; }
static int user_map_mark_identity_2m(uint64_t a,uint64_t b) { (void)a;(void)b; return -1; }
static int user_vma_fill_file_page(thread_t *t,user_vma_t *v,uint64_t a) { (void)t;(void)a; return v->file == NULL; }
static int user_map_mprotect_range(uint64_t a,uint64_t b,int p) { (void)a;(void)b;(void)p; return 0; }
'''
for name in ('static int split_2m_to_4k(', 'static int split_l3_1g_to_l2(',
             'static int mm_pte_same_pt_page(', 'int mm_va_leaf_pa(',
             'static int mm_map_4k_sharedaware_body(', 'static int mm_va_has_private_4k(',
             'static int mm_pte_is_present_cow(', 'static int mm_make_private_range_impl('):
    program += function(mm, name).replace('int mm_va_leaf_pa(', 'static int mm_va_leaf_pa(') if name == 'int mm_va_leaf_pa(' else function(mm, name)
program += r'''
static int mm_make_private_range_noyield(mm_t *m,uint64_t a,uint64_t b,int c,mm_t *s) { return mm_make_private_range_impl(m,a,b,c,s,1,0); }
static int mm_map_4k_sharedaware(mm_t *m,uint64_t *s,uint64_t a,uint64_t p,uint64_t f) { return mm_map_4k_sharedaware_body(m,s,a,p,f); }
'''
program += function(mm, 'static int mm_privatize_identity_range_ex(')
program += function(mm, 'int mm_privatize_identity_range_blank(')
program += function(vma, 'int user_vma_fault_nonpresent(')
program += r'''
int main(void) {
    const uint64_t va=0xc17d008;
    g_kernel_mm.pml4=page(); proc.pml4=page();
    thread=(thread_t){3,&proc,&g_kernel_mm};
    vma=(user_vma_t){0xc17d000,0x1000000,1,3,NULL,0};
    /* Baseline L4 exists, but its L3 slot is a hole: valid for an mmap. */
    uint64_t *baseline_l3=page(); g_kernel_mm.pml4[0]=(uintptr_t)baseline_l3|7;
    assert(user_vma_fault_nonpresent(va,6)==1);
    uint64_t pa=0; assert(mm_va_leaf_pa(&proc,va,&pa)==0);
    for(int i=0;i<4096;i++) assert(((unsigned char *)(uintptr_t)pa)[i]==0);
    assert(baseline_l3[0]==0);
    assert(user_vma_fault_nonpresent(va,7)==0);
    /* Each frame/PT allocation failure must be reported and release the frame. */
    for (int fail=1;fail<=4;fail++) {
        fail_alloc=0; proc.pml4=page(); nalloc=0; releases=0; fail_alloc=fail;
        assert(user_vma_fault_nonpresent(va,6)==0);
        assert(mm_va_leaf_pa(&proc,va,&pa)!=0);
        assert(releases==(fail>1));
    }
    /* Missing baseline L4 is also a hole, not a reason to reject the fault. */
    fail_alloc=0; proc.pml4=page(); g_kernel_mm.pml4[0]=0;
    assert(user_vma_fault_nonpresent(va,6)==1);
    assert(mm_va_leaf_pa(&proc,va,&pa)==0);
    assert(g_kernel_mm.pml4[0]==0);
    /* A real zero PTE below shared baseline tables must be privately populated. */
    uint64_t *l3=page(), *l2=page(), *l1=page();
    g_kernel_mm.pml4[0]=(uintptr_t)l3|7;
    l3[0]=(uintptr_t)l2|7;
    l2[(va>>21)&511]=(uintptr_t)l1|7;
    proc.pml4=page(); proc.pml4[0]=g_kernel_mm.pml4[0];
    assert(user_vma_fault_nonpresent(va,6)==1);
    assert(mm_va_leaf_pa(&proc,va,&pa)==0);
    assert(l1[(va>>12)&511]==0);
    for(int i=0;i<4096;i++) assert(((unsigned char *)(uintptr_t)pa)[i]==0);
    puts("PASS: anonymous zero-PTE demand fault and allocation failure");
}
'''
with tempfile.TemporaryDirectory(prefix='anon-fault-', dir='/tmp/opencode') as tmp:
    src = Path(tmp) / 'test.c'
    exe = Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
