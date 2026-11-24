#!/usr/bin/env python3
"""Host-only test for physical/direct-map address and frame ownership."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <frame.h>
#include <ram_page_pool.h>
#include <spinlock.h>
static unsigned char *backing;
static uint64_t generation;
static int allocated, freed, growth_budget = -1;
void *kmalloc(size_t n) {
    if (growth_budget == 0) return NULL;
    if (growth_budget > 0) growth_budget--;
    return malloc(n);
}
void kfree(void *p) { free(p); }
void acquire_irqsave(spinlock_t *l, unsigned long *f) { (void)l; *f = 0; }
void release_irqrestore(spinlock_t *l, unsigned long f) { (void)l; (void)f; }
void kprintf(const char *fmt, ...) { (void)fmt; }
int pmm_ready(void) { return 1; }
size_t pmm_total_pages(void) { return 1; }
size_t pmm_free_pages(void) { return 1; }
void *pmm_alloc_page(void) { return NULL; }
void pmm_free_page(void *p) { (void)p; assert(0); }
int ramfs_high_page_alloc(struct ram_page *out) {
    if (allocated) return -1;
    allocated = 1;
    generation += 2;
    *out = (struct ram_page){0x100001000ULL, backing, generation - 1};
    return 0;
}
int ramfs_high_page_free(struct ram_page p) {
    assert(allocated && p.pa == 0x100001000ULL && p.va == backing);
    assert(p.generation == generation - 1);
    allocated = 0; freed++; return 0;
}
int main(void) {
    backing = aligned_alloc(4096, 4096);
    assert(backing);
    memset(backing, 0xaa, 4096);
    frame_init();
    size_t initial_free = frame_free_slots();
    assert(frame_adopt(0x200001000ULL) != 0);
    struct frame_page p = {0};
    assert(frame_alloc_high(&p, 1) == 0);
    assert(frame_free_slots() == initial_free - 1);
    assert(p.pa == 0x100001000ULL && p.kva == backing);
    assert(frame_kva(p.pa + 17) == backing + 17);
    assert(frame_kva(0x100002000ULL) == NULL);
    growth_budget = 0;
    assert(frame_reserve_capacity(262146) != 0);
    assert(frame_refcount(p.pa) == 1 && frame_kva(p.pa) == backing);
    growth_budget = -1;
    assert(frame_reserve_capacity(262146) == 0);
    growth_budget = 1;
    assert(frame_reserve_capacity(262144 + 2 * 16384 + 1) != 0);
    assert(frame_refcount(p.pa) == 1 && frame_kva(p.pa) == backing);
    growth_budget = -1;
    assert(frame_reserve_capacity(262144 + 2 * 16384 + 1) == 0);
    assert(frame_free_slots() == frame_capacity_pages() - 1);
    assert(frame_reserve_capacity((size_t)-1) != 0);
    assert(frame_refcount(p.pa) == 1 && frame_kva(p.pa) == backing);
    for (int i = 0; i < 4096; i++) assert(backing[i] == 0);
    assert(frame_refcount(p.pa) == 1);
    assert(frame_retain(p.pa) == 0 && frame_refcount(p.pa) == 2);
    frame_release(p.pa);
    assert(allocated && !freed && frame_refcount(p.pa) == 1);
    frame_release(p.pa);
    assert(!allocated && freed == 1 && frame_refcount(p.pa) == 0);
    assert(frame_free_slots() == frame_capacity_pages());
    assert(frame_kva(p.pa) == NULL);
    frame_release(p.pa);
    assert(freed == 1);
    memset(backing, 0xbb, 4096);
    assert(frame_alloc_high(&p, 0) == 0 && backing[0] == 0xbb);
    frame_release(p.pa);
    assert(freed == 2);
    free(backing);
}
'''

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-DAXON_EXPERIMENTAL_DIRECT_MAP=1", "-I", str(root / "inc"),
                    str(src), str(root / "mm/frame.c"), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: high frames preserve physical/virtual addresses and lifetime")
