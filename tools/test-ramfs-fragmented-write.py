#!/usr/bin/env python3
"""Run RAMFS write with a fragmented-heap allocator and verify data survives."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ramfs.c").read_text()


def function(signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        depth += (source[pos] == "{") - (source[pos] == "}")
        if depth == 0:
            return source[start:pos + 1]
    raise AssertionError(signature)


fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#define RAMFS_DATA_CHUNK_SIZE 4096u
#define RAMFS_CHUNKIFY_THRESHOLD (1u * 1024u * 1024u)
typedef struct { int unused; } lock_t;
struct ramfs_data_chunk { size_t index; char *data; int from_pmm; struct ramfs_data_chunk *next; };
struct ramfs_node {
    int is_dir, chunked, data_borrowed;
    char *data;
    size_t size, capacity;
    struct ramfs_data_chunk *chunks, *chunks_tail, *chunks_cursor;
    lock_t io_lock;
    unsigned long generation;
    unsigned uid;
    const char *name;
    unsigned long ino;
    time_t mtime, ctime;
};
struct ramfs_file_handle { struct ramfs_node *node; };
struct fs_file { void *driver_private; const char *path; size_t size; unsigned long backing_gen; };
static size_t alloc_limit = (size_t)-1;
static void *kmalloc(size_t n) { return n > alloc_limit ? NULL : malloc(n); }
static void *krealloc(void *p, size_t n) { return n > alloc_limit ? NULL : realloc(p, n); }
static void kfree(void *p) { free(p); }
static int pmm_enabled;
static int page_allocs, page_frees, page_limit = -1;
static int pmm_ready(void) { return pmm_enabled; }
static void *pmm_alloc_page(void) {
    if (page_limit >= 0 && page_allocs >= page_limit) return NULL;
    page_allocs++;
    return malloc(4096);
}
static void pmm_free_page(void *p) { page_frees++; free(p); }
static int heap_ptr_is_kmalloc(void *p) { (void)p; return 1; }
static void acquire(lock_t *l) { (void)l; }
static void release(lock_t *l) { (void)l; }
static void ramfs_inode_changed(struct ramfs_node *n) { n->generation++; }
typedef struct { unsigned euid; unsigned long linux_tgid; } thread_t;
static thread_t *ramfs_cred(void) { return NULL; }
static int ramfs_capable(thread_t *t, int cap) { (void)t; (void)cap; return 0; }
#define AXON_CAP_FOWNER 3
static int ramfs_diag_left;
static int ramfs_diag_pg(const char *path, const char *name) { (void)path; (void)name; return 0; }
static thread_t *thread_current(void) { return NULL; }
static time_t ramfs_now(void) { return 0; }
#define klogprintf_logonly(...) ((void)fprintf(stderr, __VA_ARGS__))
static unsigned long long heap_used_bytes(void) { return 0; }
static unsigned long long heap_total_bytes(void) { return 0; }
#define kprintf(...) ((void)fprintf(stderr, __VA_ARGS__))
'''
helpers = "\n".join(function(name) for name in (
    "static int ramfs_chunk_alloc_data(",
    "static void ramfs_chunk_list_free(",
    "static struct ramfs_data_chunk *ramfs_chunk_find(",
    "static struct ramfs_data_chunk *ramfs_chunk_get(",
    "static ssize_t ramfs_chunked_read_locked(",
    "static ssize_t ramfs_chunked_write_locked(",
    "static int ramfs_chunkify_locked(",
    "static void ramfs_free_data_owned(",
    "static int ramfs_materialize_node_locked(",
    "static int ramfs_ensure_heap_data_locked(",
    "int ramfs_ftruncate(",
    "static ssize_t ramfs_write(",
))
test = r'''
int main(void) {
    struct ramfs_node node = {0};
    struct ramfs_file_handle handle = { .node = &node };
    struct fs_file file = { .driver_private = &handle, .path = "/test" };
    const size_t first = 256 * 1024, extra = 128 * 1024;
    char *input = malloc(first + extra), *output = malloc(first + extra);
    assert(input && output);
    for (size_t i = 0; i < first + extra; i++) input[i] = (char)(i * 31);
    assert(ramfs_write(&file, input, first, 0) == (ssize_t)first);
    assert(!node.chunked);
    /* Fragmentation rejects contiguous growth; file pages use PMM, not heap. */
    alloc_limit = 4096;
    pmm_enabled = 1;
    assert(ramfs_write(&file, input + first, extra, first) == (ssize_t)extra);
    assert(node.chunked && node.size == first + extra);
    assert(ramfs_chunked_read_locked(&node, output, first + extra, 0) == (ssize_t)(first + extra));
    assert(memcmp(input, output, first + extra) == 0);
    ramfs_chunk_list_free(node.chunks);
    assert(page_allocs > 0 && page_allocs == page_frees);
    struct ramfs_node borrowed = { .data = input, .data_borrowed = 1,
                                   .size = first, .capacity = first };
    assert(ramfs_materialize_node_locked(&borrowed) == 0);
    assert(borrowed.chunked);
    assert(ramfs_chunked_read_locked(&borrowed, output, first, 0) == (ssize_t)first);
    assert(memcmp(input, output, first) == 0);
    ramfs_chunk_list_free(borrowed.chunks);
    assert(page_allocs == page_frees);
    struct ramfs_node partial = { .chunked = 1 };
    struct ramfs_file_handle partial_handle = { .node = &partial };
    struct fs_file partial_file = { .driver_private = &partial_handle };
    page_limit = page_allocs + 2;
    alloc_limit = 512; /* metadata fits; the heap cannot supply a data page */
    assert(ramfs_write(&partial_file, input, 3 * 4096, 0) == 2 * 4096);
    assert(partial_file.size == 2 * 4096);
    ramfs_chunk_list_free(partial.chunks);
    assert(page_allocs == page_frees);
    /* Exhaustion of PMM does not hide free space in the separate object heap. */
    struct ramfs_node heap_fallback = { .chunked = 1 };
    alloc_limit = 4096;
    page_limit = page_allocs;
    assert(ramfs_chunked_write_locked(&heap_fallback, input, 4096, 0) == 4096);
    assert(heap_fallback.chunks && !heap_fallback.chunks->from_pmm);
    ramfs_chunk_list_free(heap_fallback.chunks);
    assert(page_allocs == page_frees);
    /* Check sequential access to thousands of page-backed chunks, including
     * backwards reads that must restart the lookup cursor. */
    alloc_limit = 4096;
    page_limit = -1;
    struct ramfs_node large = { .chunked = 1 };
    size_t large_size = 16u * 1024u * 1024u;
    char *large_input = malloc(large_size), *large_output = malloc(large_size);
    assert(large_input && large_output);
    for (size_t i = 0; i < large_size; i++) large_input[i] = (char)(i ^ (i >> 8));
    assert(ramfs_chunked_write_locked(&large, large_input, large_size, 0) == (ssize_t)large_size);
    assert(ramfs_chunked_read_locked(&large, large_output, large_size, 0) == (ssize_t)large_size);
    assert(memcmp(large_input, large_output, large_size) == 0);
    assert(ramfs_chunked_read_locked(&large, large_output, 4096, 0) == 4096);
    assert(memcmp(large_input, large_output, 4096) == 0);
    ramfs_chunk_list_free(large.chunks);
    assert(page_allocs == page_frees);
    free(large_input);
    free(large_output);
    /* Shrinking a large borrowed file materializes it as PMM pages first.
     * The shrink must then truncate those pages, not realloc NULL. */
    size_t borrowed_size = 2u * 1024u * 1024u;
    char *borrowed_data = malloc(borrowed_size);
    assert(borrowed_data);
    memset(borrowed_data, 0x5a, borrowed_size);
    struct ramfs_node borrowed_large = { .data = borrowed_data, .data_borrowed = 1,
        .size = borrowed_size, .capacity = borrowed_size };
    struct ramfs_file_handle borrowed_handle = { .node = &borrowed_large };
    struct fs_file borrowed_file = { .driver_private = &borrowed_handle };
    assert(ramfs_ftruncate(&borrowed_file, 128 * 1024) == 0);
    assert(borrowed_large.chunked && !borrowed_large.data);
    assert(borrowed_large.size == 128 * 1024);
    assert(ramfs_chunked_read_locked(&borrowed_large, output, 4096, 0) == 4096);
    assert(output[0] == 0x5a && output[4095] == 0x5a);
    assert(ramfs_ftruncate(&borrowed_file, 0) == 0);
    assert(page_allocs == page_frees);
    free(borrowed_data);
    free(input);
    free(output);
    puts("PASS: fragmented heap falls back to chunked RAMFS without data loss");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ramfs-fragment-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + helpers + test)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
