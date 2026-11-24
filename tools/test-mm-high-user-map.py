#!/usr/bin/env python3
"""Host-only: user PTEs accept high owned frames only when tracked."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static int mm_map_user_page_locked(")
end = mm.index("\nint mm_map_user_page(", start)
source = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <paging.h>
#include <mmio.h>
typedef struct { uint64_t *pml4; } mm_t;
static mm_t g_kernel_mm;
static int tracked;
static int pt_page_pa_ok(uint64_t e) {
    return !(e & PG_PRESENT) || (e & PG_ADDR_MASK) < MMIO_IDENTITY_LIMIT;
}
static uint64_t *alloc_pt_page(mm_t *m) { (void)m; return NULL; }
static int mm_owns_pt_page(mm_t *m, uint64_t *p) { (void)m; (void)p; return 1; }
static uint64_t *dup_pt_page(mm_t *m, uint64_t *p) { (void)m; (void)p; return NULL; }
static int split_l3_1g_to_l2(mm_t *m, uint64_t *p, int i) {
    (void)m; (void)p; (void)i; return -1;
}
static int split_2m_to_4k(mm_t *m, uint64_t *p, int i, uint64_t v) {
    (void)m; (void)p; (void)i; (void)v; return -1;
}
static void frame_release(uint64_t p) { (void)p; assert(0); }
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
static void *frame_kva(uint64_t p) {
    return tracked && p == 0x100001000ULL ? (void *)0x1000 : NULL;
}
#endif
#define devel_printf(...) ((void)0)
''' + mm[start:end] + r'''
int main(void) {
    uint64_t *p = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(p != MAP_FAILED);
    memset(p, 0, 4 * 4096);
    uint64_t *l4 = p, *l3 = p + 512, *l2 = p + 1024, *l1 = p + 1536;
    mm_t m = {l4};
    l4[0] = (uintptr_t)l3 | PG_PRESENT | PG_RW | PG_US;
    l3[0] = (uintptr_t)l2 | PG_PRESENT | PG_RW | PG_US;
    l2[0] = (uintptr_t)l1 | PG_PRESENT | PG_RW | PG_US;
    assert(mm_map_user_page_locked(&m, 0x1000, 0x100001000ULL,
                                   PG_RW | PG_SOFT_OWNED) == -2);
    assert(l1[1] == 0);
    tracked = 1;
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    assert(mm_map_user_page_locked(&m, 0x1000, 0x100001000ULL,
                                   PG_RW | PG_SOFT_OWNED) == 0);
    assert((l1[1] & PG_ADDR_MASK) == 0x100001000ULL);
    assert(l1[1] & PG_SOFT_OWNED);
#else
    assert(mm_map_user_page_locked(&m, 0x1000, 0x100001000ULL,
                                   PG_RW | PG_SOFT_OWNED) == -2);
#endif
    munmap(p, 4 * 4096);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    for flags in ([], ["-DAXON_EXPERIMENTAL_DIRECT_MAP=1"]):
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        *flags, "-I", str(root / "inc"),
                        str(src), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
print("PASS: high user PTEs require a tracked experimental frame")
