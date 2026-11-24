#!/usr/bin/env python3
"""Host test of high-PA uaccess routing; not a page-table or SMP test."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static int mm_user_memcpy_via_pa(")
end = mm.index("\nint mm_copy_to_user(", start)
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define PG_PRESENT 1
#define PG_ADDR_MASK 0x000ffffffffff000ULL
typedef struct { uint64_t *pml4; uint64_t cr3; } mm_t;
typedef int mm_dm_ctx_t;
static unsigned char high[4096];
static uint64_t phys = 0x100002023ULL;
static int available = 1, flushes;
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t x) { (void)x; }
static uint64_t mm_direct_map_cr3(void) { return 0x1000; }
static void paging_write_cr3(uint64_t x) { (void)x; }
static void invlpg(void *p) { (void)p; flushes++; }
static int mm_user_leaf_pa_direct(mm_t *m, uint64_t v, int w, uint64_t *out) {
    (void)m; (void)v; (void)w; *out = phys; return 0;
}
static int mm_va_leaf_entry_direct(mm_t *m, uint64_t v, uint64_t *out) {
    (void)m; (void)v; (void)out; return -1;
}
static void *frame_kva(uint64_t p) {
    if (!available || p != phys) return NULL;
    return high + (p & 4095);
}
''' + mm[start:end] + r'''
int main(void) {
    mm_t mm = {0};
    unsigned char src[] = {1, 2, 3, 4};
    unsigned char dst[sizeof src] = {0};
    assert(mm_user_memcpy_via_pa(&mm, 0x400000, src, sizeof src, 1) == 0);
    assert(!memcmp(high + 0x23, src, sizeof src) && flushes == 1);
    assert(mm_user_memcpy_via_pa(&mm, 0x400000, dst, sizeof dst, 0) == 0);
    assert(!memcmp(dst, src, sizeof src) && flushes == 1);
    available = 0;
    assert(mm_user_memcpy_via_pa(&mm, 0x400000, src, sizeof src, 1) != 0);
    assert(flushes == 1);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(code)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: high physical user-copy uses tracked kernel mapping")
