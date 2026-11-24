#!/usr/bin/env python3
"""High frame metadata must be backed by permanently reserved high pages."""
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
static unsigned char *pages;
static unsigned high_allocs, high_frees, heap_allocs;
void *kmalloc(size_t n) { heap_allocs++; return malloc(n); }
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
    assert(high_allocs < 4);
    unsigned i = high_allocs++;
    *out = (struct ram_page){0x100000000ULL + i * 4096, pages + i * 4096, 1};
    return 0;
}
int ramfs_high_page_free(struct ram_page p) {
    assert(p.pa == 0x100002000ULL && p.va == pages + 8192);
    assert(p.generation == 1);
    high_frees++; return 0;
}
int main(void) {
    pages = aligned_alloc(4096, 4 * 4096);
    assert(pages);
    memset(pages, 0xaa, 4 * 4096);
    frame_init();
    unsigned before = heap_allocs;
    assert(frame_reserve_capacity(262144 + 128) == 0);
    assert(frame_capacity_pages() >= 262144 + 128);
    assert(high_allocs == 2 && heap_allocs == before + 2); /* directory + hash */
    struct frame_page p;
    assert(frame_alloc_high(&p, 1) == 0);
    assert(p.pa == 0x100002000ULL && p.kva == pages + 8192);
    assert(frame_retain(p.pa) == 0);
    frame_release(p.pa);
    assert(high_frees == 0);
    frame_release(p.pa);
    assert(high_frees == 1); /* metadata pages remain permanently reserved */
    free(pages);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-DAXON_EXPERIMENTAL_DIRECT_MAP=1",
                    "-DAXON_EXPERIMENTAL_HIGH_USER_FRAMES=1",
                    "-I", str(root / "inc"), str(src), str(root / "mm/frame.c"),
                    "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: frame metadata consumes reserved high pages, not the low heap")
