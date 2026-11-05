#!/usr/bin/env python3
"""Clone must not replace a missing executable page with blank memory."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int clone_ensure_user_va(")
end = source.index("\n}\n", start) + 3
helper = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define PAGE_SIZE_2M 0x200000ULL
#define PG_PRESENT 1
#define PG_RW 2
#define PG_US 4
typedef struct { void *pml4; } mm_t;
static mm_t kernel, user;
static int mapped, lazy_result, fault_result, blank_calls;
static int mm_user_leaf_pa(mm_t *mm, uint64_t va, int write, uint64_t *pa) {
    (void)mm; (void)va; (void)write; *pa = 0xdead000;
    return mapped ? 0 : -1;
}
static int user_vma_fault_lazy_anon(uint64_t va) {
    (void)va; if (lazy_result) mapped = 1; return lazy_result;
}
static int user_vma_fault_nonpresent(uint64_t va, uint64_t err) {
    (void)va; (void)err; if (fault_result) mapped = 1; return fault_result;
}
static mm_t *mm_kernel(void) { return &kernel; }
static int mm_privatize_identity_range_blank(mm_t *mm, uint64_t lo, uint64_t hi) {
    (void)mm; (void)lo; (void)hi; blank_calls++; return 0;
}
static int mm_make_private_range_noyield(mm_t *mm, uint64_t lo, uint64_t hi,
                                         int flags, mm_t *share) {
    (void)mm; (void)lo; (void)hi; (void)flags; (void)share; mapped = 1; return 0;
}
static int map_page_2m(uint64_t va, uint64_t pa, int flags) {
    (void)va; (void)pa; (void)flags; mapped = 1; return 0;
}
''' + helper + r'''
int main(void) {
    user.pml4 = (void *)1; kernel.pml4 = (void *)2;
    fault_result = 1;
    assert(clone_ensure_user_va(&user, 0x8235b50, 0) == 0);
    assert(blank_calls == 0);
    mapped = 0; fault_result = 0;
    assert(clone_ensure_user_va(&user, 0x8235b50, 0) == -1);
    assert(blank_calls == 0);
    mapped = 0; lazy_result = 1;
    assert(clone_ensure_user_va(&user, 0x8235b50, 0) == 0);
    assert(blank_calls == 0);
    puts("PASS: clone prefault never fabricates blank executable pages");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-clone-prefault-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
