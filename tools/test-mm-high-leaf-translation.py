#!/usr/bin/env python3
"""Exercise the actual leaf walker with high physical and low table pages."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("int mm_va_leaf_pa(")
end = mm.index("\nstatic int mm_va_leaf_entry_direct(", start)
private_start = mm.index("static int mm_va_has_private_4k(")
private_end = mm.index("\n/* Resolve the page-aligned PA", private_start)
debug_start = mm.index("static int mm_dbg_ash_leaf_flags(")
debug_end = mm.index("\nvoid mm_dbg_ash_watch(", debug_start)
source = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <paging.h>
#include <mmio.h>
typedef struct { uint64_t *pml4; } mm_t;
static int pt_page_pa_ok(uint64_t e) {
    return !(e & PG_PRESENT) || (e & PG_ADDR_MASK) < MMIO_IDENTITY_LIMIT;
}
''' + mm[start:end] + "\n" + mm[private_start:private_end] + "\n" + mm[debug_start:debug_end] + r'''
int main(void) {
    uint64_t *p = mmap(NULL, 8 * 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(p != MAP_FAILED);
    memset(p, 0, 8 * 4096);
    uint64_t *l4 = p, *l3 = p + 512, *l2 = p + 1024, *l1 = p + 1536;
    mm_t m = {l4};
    uint64_t result = 0;
    l4[0] = (uintptr_t)l3 | PG_PRESENT;
    l3[0] = (uintptr_t)l2 | PG_PRESENT;
    l2[0] = (uintptr_t)l1 | PG_PRESENT;
    l1[1] = 0x100001000ULL | PG_PRESENT;
    assert(mm_va_leaf_pa(&m, 0x1123, &result) == 0 && result == 0x100001000ULL);
    assert(mm_dbg_ash_leaf_flags(&m, 0x1123, &result, NULL, NULL) == 0 &&
           result == 0x100001000ULL);
    l2[0] = 0x140000000ULL | PG_PRESENT | PG_PS_2M;
    assert(mm_va_leaf_pa(&m, 0x1ab123, &result) == 0 && result == 0x1401ab000ULL);
    assert(mm_dbg_ash_leaf_flags(&m, 0x1ab123, &result, NULL, NULL) == 0 &&
           result == 0x1401ab000ULL);
    l3[0] = 0x140000000ULL | PG_PRESENT | PG_PS_2M;
    assert(mm_va_leaf_pa(&m, 0x23456123, &result) == 0 && result == 0x163456000ULL);
    assert(mm_dbg_ash_leaf_flags(&m, 0x23456123, &result, NULL, NULL) == 0 &&
           result == 0x163456000ULL);
    l3[0] = 0x100001000ULL | PG_PRESENT; /* high table is not dereferenceable */
    assert(mm_va_leaf_pa(&m, 0x1000, &result) != 0);
    uint64_t *s4 = p + 2048, *s3 = p + 2560;
    uint64_t *s2 = p + 3072, *s1 = p + 3584;
    l3[0] = (uintptr_t)l2 | PG_PRESENT;
    l2[0] = (uintptr_t)l1 | PG_PRESENT;
    l1[1] = 0x100001000ULL | PG_PRESENT;
    s4[0] = (uintptr_t)s3 | PG_PRESENT;
    s3[0] = (uintptr_t)s2 | PG_PRESENT;
    s2[0] = (uintptr_t)s1 | PG_PRESENT;
    s1[1] = 0x100001000ULL | PG_PRESENT;
    assert(mm_va_has_private_4k(&m, s4, 0x1000) == 0);
    s1[1] = 0x100002000ULL | PG_PRESENT;
    assert(mm_va_has_private_4k(&m, s4, 0x1000) == 1);
    munmap(p, 8 * 4096);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "inc"), str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: high physical leaf and 1 GiB translation")
