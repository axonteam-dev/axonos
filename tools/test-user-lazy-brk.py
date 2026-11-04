#!/usr/bin/env python3
"""Test that exec's unused anonymous brk gap is populated on demand."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_as.c").read_text()


def function(text, signature):
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


helper = function(source, "static int user_as_lazy_anon_range_for_exec(")
brk_setup = function(source, "void user_as_set_brk_after_load(")
assert "mm_unmap_user_range" in helper
assert "user_vma_add" in helper
assert "USER_VMA_KIND_MMAP_LAZY" in helper
assert "user_as_lazy_anon_range_for_exec(tcur, gap_lo, brk)" in brk_setup
assert "user_as_ensure_range_for_exec(tcur, brk, hi)" in brk_setup

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_VMA_KIND_MMAP_LAZY 3
typedef struct mm { uint64_t *pml4; } mm_t;
typedef struct thread {
    mm_t *mm;
    mm_t *mm_ptemplate;
    int tid;
} thread_t;

static mm_t kernel_mm, private_mm;
static int unmap_rc, vma_rc, eager_calls, unmap_calls, vma_calls;
static uint64_t last_lo, last_hi;
static uintptr_t last_vma_addr;
static size_t last_vma_len;

static uintptr_t user_mm_align_down(uintptr_t v, uintptr_t a) {
    return v & ~(a - 1u);
}
static uintptr_t user_mm_align_up(uintptr_t v, uintptr_t a) {
    return (v + a - 1u) & ~(a - 1u);
}
static mm_t *mm_kernel(void) { return &kernel_mm; }
static int user_as_has_private_mm(thread_t *t) {
    return t && t->mm && t->mm->pml4 && kernel_mm.pml4 &&
           t->mm->pml4 != kernel_mm.pml4;
}
static int mm_unmap_user_range(mm_t *mm, uint64_t *share_l4,
                               uint64_t lo, uint64_t hi) {
    assert(mm == &private_mm && share_l4 == kernel_mm.pml4);
    unmap_calls++;
    last_lo = lo;
    last_hi = hi;
    return unmap_rc;
}
static int user_vma_add(uint64_t tid, uintptr_t addr, size_t len,
                        int prot, int kind) {
    assert(tid == 7 && prot == 3 && kind == USER_VMA_KIND_MMAP_LAZY);
    vma_calls++;
    last_vma_addr = addr;
    last_vma_len = len;
    return vma_rc;
}
static int mm_make_private_range(mm_t *mm, uint64_t lo, uint64_t hi,
                                 int copy_old, mm_t *share) {
    assert(mm == &private_mm && copy_old == 0 && share == &kernel_mm);
    assert(lo == last_lo && hi == last_hi);
    eager_calls++;
    return 0;
}
''' + helper + r'''
int main(void) {
    thread_t t = { .mm = &private_mm, .mm_ptemplate = NULL, .tid = 7 };
    kernel_mm.pml4 = (uint64_t *)0x1000;
    private_mm.pml4 = (uint64_t *)0x2000;

    /* Success: page-align and punch the range, then register a lazy VMA. */
    assert(user_as_lazy_anon_range_for_exec(&t, 0x423123, 0x800000) == 0);
    assert(unmap_calls == 1 && last_lo == 0x423000 && last_hi == 0x800000);
    assert(vma_calls == 1 && last_vma_addr == last_lo &&
           last_vma_len == last_hi - last_lo);
    assert(eager_calls == 0);

    /* If VMA metadata is exhausted, eagerly restore safe private backing. */
    unmap_rc = 0;
    vma_rc = -1;
    assert(user_as_lazy_anon_range_for_exec(&t, 0x500000, 0x501000) == 0);
    assert(eager_calls == 1 && last_lo == 0x500000 && last_hi == 0x501000);

    /* If page-table unmap fails, use the same eager fallback. */
    unmap_rc = -1;
    vma_rc = 0;
    assert(user_as_lazy_anon_range_for_exec(&t, 0x600000, 0x602000) == 0);
    assert(eager_calls == 2 && last_lo == 0x600000 && last_hi == 0x602000);

    puts("PASS: exec brk gap is lazy with safe eager fallbacks");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-lazy-brk-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
