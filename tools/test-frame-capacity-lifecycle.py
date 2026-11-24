#!/usr/bin/env python3
"""Host regressions for PMM-sized frame metadata and protected mm teardown."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static void mm_release_user_frames(")
end = mm.index("\nvoid mm_release(", start)
walker = mm[start:end]

frame_test = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <frame.h>
#include <spinlock.h>

#define PAGES (262144u + 4096u)
static unsigned next_page, returned;
static int fail_large;
void *kmalloc(size_t n) {
    if (fail_large && n > (PAGES / 2u) * 24u) return NULL;
    return malloc(n);
}
void kfree(void *p) { free(p); }
void acquire_irqsave(spinlock_t *l, unsigned long *f) { (void)l; *f = 0; }
void release_irqrestore(spinlock_t *l, unsigned long f) { (void)l; (void)f; }
int pmm_ready(void) { return 1; }
size_t pmm_total_pages(void) { return PAGES; }
size_t pmm_free_pages(void) { return PAGES - next_page; }
void kprintf(const char *fmt, ...) { (void)fmt; }
void *pmm_alloc_page(void) {
    if (next_page == PAGES) return NULL;
    return (void *)(uintptr_t)((uint64_t)(++next_page) * 4096);
}
void pmm_free_page(void *p) { assert(p); returned++; }
int main(int argc, char **argv) {
    (void)argv;
    fail_large = argc > 1;
    unsigned capacity = fail_large ? PAGES / 2u : PAGES;
    frame_init();
    assert(frame_free_slots() == capacity);
    for (unsigned i = 0; i < capacity; i++)
        assert(frame_alloc() == (void *)(uintptr_t)((uint64_t)(i + 1) * 4096));
    assert(frame_free_slots() == 0);
    assert(frame_alloc() == NULL);
    for (unsigned i = 0; i < capacity; i++) {
        uint64_t pa = (uint64_t)(i + 1) * 4096;
        assert(frame_refcount(pa) == 1);
        frame_release(pa);
    }
    assert(returned == capacity + (fail_large ? 1u : 0u));
    assert(frame_free_slots() == capacity);
    return 0;
}
'''

walker_test = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <paging.h>
typedef struct { uint64_t *pml4; } mm_t;
typedef int mm_dm_ctx_t;
static mm_t g_kernel_mm;
static uint64_t released[8];
static int nr;
static int pt_page_pa_ok(uint64_t e) { return (e & PG_ADDR_MASK) != 0; }
static int mm_owns_pt_page(mm_t *m, const uint64_t *p) { (void)m; (void)p; return 0; }
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t dm) { (void)dm; }
static void frame_release(uint64_t pa) { released[nr++] = pa; }
''' + walker + r'''
static uint64_t *page(void) {
    uint64_t *p = aligned_alloc(4096, 4096);
    assert(p); memset(p, 0, 4096); return p;
}
int main(void) {
    mm_t m; uint64_t *l3 = page(), *l2 = page(), *l1 = page();
    m.pml4 = page();
    m.pml4[0] = (uintptr_t)l3 | PG_PRESENT;
    l3[0] = (uintptr_t)l2 | PG_PRESENT;
    l2[1] = (uintptr_t)l1 | PG_PRESENT;
    l1[0] = 0x1000 | PG_PRESENT | PG_US | PG_SOFT_OWNED;
    l1[1] = 0x2000 | PG_SOFT_OWNED; /* mprotect(PROT_NONE) */
    l1[2] = 0x3000 | PG_PRESENT | PG_SOFT_OWNED; /* supervisor-only */
    l1[3] = 0x4000 | PG_PRESENT | PG_US; /* not frame-owned */
    mm_release_user_frames(&m);
    assert(nr == 3 && released[0] == 0x1000 && released[1] == 0x2000 && released[2] == 0x3000);
    free(m.pml4); free(l3); free(l2); free(l1);
    return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for name, program, sources in (
        ("frame", frame_test, [root / "mm/frame.c"]),
        ("walker", walker_test, []),
    ):
        src = tmp / (name + ".c")
        exe = tmp / name
        src.write_text(program)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(root / "inc"), str(src),
                        *(str(s) for s in sources), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        if name == "frame":
            subprocess.run([str(exe), "fallback"], check=True)
print("frame capacity and protected-mm teardown regressions passed")
