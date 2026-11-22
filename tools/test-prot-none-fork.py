#!/usr/bin/env python3
"""Exercise the real PROT_NONE fork leaf logic with host page tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()


def function(signature):
    start = mm.index(signature)
    end = mm.index("\n}\n", start) + 2
    return mm[start:end]


# The page-table walk must pass non-present owned leaves to the copy routine.
walk = function("static int mm_cow_mark_all_user_writable_walk(")
assert "(e1 & (PG_PRESENT | PG_SOFT_OWNED)) != PG_SOFT_OWNED" in walk

program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#define PAGE_SIZE_4K 4096ULL
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define PG_PRESENT 1ULL
#define PG_RW 2ULL
#define PG_US 4ULL
#define PG_PWT 8ULL
#define PG_PCD 16ULL
#define PG_PS_2M 128ULL
#define PG_GLOBAL 256ULL
#define PG_SOFT_COW (1ULL << 10)
#define PG_SOFT_OWNED (1ULL << 11)
#define PG_NX (1ULL << 63)
#define PG_ADDR_MASK 0x000ffffffffff000ULL
typedef struct { uint64_t *pml4; uint64_t cr3; } mm_t;
static int refs, retain_fail, map_fail;
static uint64_t expected_pa;
static int pt_page_pa_ok(uint64_t e) { return (e & PG_ADDR_MASK) < MMIO_IDENTITY_LIMIT; }
static int frame_retain(uint64_t pa) {
    assert(pa == expected_pa);
    if (retain_fail) return -1;
    refs++; return 0;
}
static void frame_release(uint64_t pa) { assert(pa == expected_pa); refs--; }
static unsigned frame_refcount(uint64_t pa) { (void)pa; return (unsigned)refs; }
static void *mm_user_frame_alloc_avoid_va(uint64_t va, int zero) { (void)va; (void)zero; return NULL; }
static int mm_fork_va_is_primary_stack(uint64_t va) { (void)va; return 0; }
static uint64_t paging_read_cr3(void) { return 0; }
static void paging_write_cr3(uint64_t p) { (void)p; }
static void devel_printf(const char *fmt, ...) { (void)fmt; }
static int mm_mark_share_user_readonly_page(mm_t *m, uint64_t *l, uint64_t v, int i) {
    (void)m; (void)l; (void)v; (void)i; return 0;
}
''' + function("static uint64_t *mm_leaf_pte_direct(") + r'''
/* Match mm_map_user_page's contract: it installs PRESENT|US. */
static int mm_map_user_page(mm_t *mm, uint64_t va, uint64_t pa, uint64_t flags) {
    if (map_fail) return -1;
    uint64_t *pte = mm_leaf_pte_direct(mm->pml4, va);
    assert(pte);
    *pte = pa | flags | PG_PRESENT | PG_US;
    return 0;
}
''' + function("static int mm_fork_copy_user_leaf(") + r'''
static uint64_t *page(void) {
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(p != MAP_FAILED && (uintptr_t)p < MMIO_IDENTITY_LIMIT);
    return p;
}
static void setup(mm_t *m, uint64_t va) {
    uint64_t *l3 = page(), *l2 = page(), *l1 = page();
    m->pml4 = page(); m->cr3 = (uintptr_t)m->pml4;
    m->pml4[0] = (uintptr_t)l3 | PG_PRESENT;
    l3[0] = (uintptr_t)l2 | PG_PRESENT;
    l2[va >> 21] = (uintptr_t)l1 | PG_PRESENT;
}
int main(void) {
    const uint64_t va = 0x20000000, pa = 0x12345000;
    mm_t parent, child;
    setup(&parent, va); setup(&child, va);
    uint64_t *pp = mm_leaf_pte_direct(parent.pml4, va);
    uint64_t *cp = mm_leaf_pte_direct(child.pml4, va);
    expected_pa = pa; refs = 1;
    *pp = pa | PG_SOFT_OWNED;
    retain_fail = 1;
    assert(mm_fork_copy_user_leaf(&child, &parent, parent.pml4, 1, va, pa, *pp, 1, 0, 1) == -1);
    assert(refs == 1 && *cp == 0 && *pp == (pa | PG_SOFT_OWNED));
    retain_fail = 0; map_fail = 1;
    assert(mm_fork_copy_user_leaf(&child, &parent, parent.pml4, 1, va, pa, *pp, 1, 0, 1) == -1);
    assert(refs == 1 && *cp == 0 && *pp == (pa | PG_SOFT_OWNED));
    map_fail = 0;
    assert(mm_fork_copy_user_leaf(&child, &parent, parent.pml4, 1, va, pa, *pp, 1, 0, 1) == 0);
    assert(refs == 2 && *pp == (pa | PG_SOFT_OWNED | PG_SOFT_COW) && *cp == *pp);
    frame_release(pa); frame_release(pa);
    /* MAP_SHARED retains the backing but must not turn it into COW. */
    refs = 1; *pp = pa | PG_SOFT_OWNED; *cp = 0;
    assert(mm_fork_copy_user_leaf(&child, &parent, parent.pml4, 1, va, pa, *pp, 1, 1, 1) == 0);
    assert(refs == 2 && *pp == (pa | PG_SOFT_OWNED) && *cp == *pp);
    /* The child-only/vfork pass must not change the frozen parent. */
    refs = 1; *pp = pa | PG_SOFT_OWNED; *cp = 0;
    assert(mm_fork_copy_user_leaf(&child, NULL, parent.pml4, 1, va, pa, *pp, 0, 0, 1) == 0);
    assert(refs == 2 && *pp == (pa | PG_SOFT_OWNED));
    assert(*cp == (pa | PG_SOFT_OWNED | PG_SOFT_COW));
    puts("PASS: PROT_NONE private/shared fork ownership and failure rollback");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-prot-fork-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
