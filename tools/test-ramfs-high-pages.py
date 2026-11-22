#!/usr/bin/env python3
"""Exercise experimental high-page RAMFS ownership and allocator fallback."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ramfs.c").read_text()


def function(name):
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if not depth:
            return source[start:i + 1]
    raise AssertionError(name)


fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define AXON_EXPERIMENTAL_DIRECT_MAP 1
#define RAMFS_DATA_CHUNK_SIZE 4096u
struct ram_page { uint64_t pa; void *va; uint64_t generation; };
struct ramfs_data_chunk {
    size_t index; char *data; int from_pmm;
    struct ram_page high_page; struct ramfs_data_chunk *next;
};
static int use_high = 1, high_freed, pmm_freed;
static int ramfs_high_page_alloc(struct ram_page *page) {
    if (!use_high) return -1;
    page->va = malloc(4096); assert(page->va);
    memset(page->va, 0xa5, 4096);
    page->pa = 0x100000000ULL; page->generation = 1;
    return 0;
}
static int ramfs_high_page_free(struct ram_page page) {
    assert(page.pa == 0x100000000ULL && page.generation == 1);
    free(page.va); high_freed++; return 0;
}
static int pmm_ready(void) { return 1; }
static void *pmm_alloc_page(void) { return malloc(4096); }
static void pmm_free_page(void *p) { free(p); pmm_freed++; }
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
''' + function("static int ramfs_chunk_alloc_data(") + "\n" + \
    function("static void ramfs_chunk_list_free(") + r'''
int main(void) {
    struct ramfs_data_chunk *a = calloc(1, sizeof(*a));
    struct ramfs_data_chunk *b = calloc(1, sizeof(*b));
    assert(a && b);
    assert(ramfs_chunk_alloc_data(a) == 0 && a->from_pmm == 2);
    for (size_t i = 0; i < 4096; i++) assert(a->data[i] == 0);
    use_high = 0;
    assert(ramfs_chunk_alloc_data(b) == 0 && b->from_pmm == 1);
    a->next = b;
    ramfs_chunk_list_free(a);
    assert(high_freed == 1 && pmm_freed == 1);
    puts("PASS: experimental RAMFS pages zero, fall back and free through their owner");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-high-ramfs-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
