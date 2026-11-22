#!/usr/bin/env python3
"""Exercise the chunked RAMFS backing used for large files."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/ramfs.c").read_text()


def function(name):
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError(f"unterminated function {name}")


helpers = "\n\n".join(function(name) for name in (
    "static int ramfs_chunk_alloc_data(",
    "static struct ramfs_data_chunk *ramfs_chunk_find(",
    "static struct ramfs_data_chunk *ramfs_chunk_get(",
    "static ssize_t ramfs_chunked_read_locked(",
    "static ssize_t ramfs_chunked_write_locked(",
))
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define RAMFS_DATA_CHUNK_SIZE 4096u
#define EINVAL 22
#define ENOMEM 12
#define kmalloc malloc
#define kfree free
struct ramfs_data_chunk {
    size_t index;
    char *data;
    int from_pmm;
    struct ramfs_data_chunk *next;
};
static int pmm_ready(void) { return 0; }
static void *pmm_alloc_page(void) { return NULL; }
struct ramfs_node {
    size_t size;
    int chunked;
    struct ramfs_data_chunk *chunks;
    struct ramfs_data_chunk *chunks_tail;
    struct ramfs_data_chunk *chunks_cursor;
};
'''
tests = r'''
int main(void) {
    struct ramfs_node node = { .chunked = 1 };
    const size_t first_len = 2u * RAMFS_DATA_CHUNK_SIZE + 37u;
    char *input = malloc(first_len);
    char *output = malloc(first_len + 16u);
    assert(input && output);
    for (size_t i = 0; i < first_len; i++) input[i] = (char)(i * 31u);
    assert(ramfs_chunked_write_locked(&node, input, first_len, 0) == (ssize_t)first_len);
    assert(node.size == first_len);
    memset(output, 0xcc, first_len + 16u);
    assert(ramfs_chunked_read_locked(&node, output, first_len, 0) == (ssize_t)first_len);
    assert(memcmp(input, output, first_len) == 0);

    const char tail[] = "xyz";
    size_t tail_offset = 5u * RAMFS_DATA_CHUNK_SIZE + 7u;
    assert(ramfs_chunked_write_locked(&node, tail, sizeof(tail) - 1, tail_offset) == 3);
    assert(node.size == tail_offset + 3);
    node.size = tail_offset + 16; /* sparse extension reads as zeroes */
    memset(output, 0xcc, 16);
    assert(ramfs_chunked_read_locked(&node, output, 16, tail_offset - 5) == 16);
    for (int i = 0; i < 5; i++) assert(output[i] == 0);
    assert(memcmp(output + 5, tail, 3) == 0);
    for (int i = 8; i < 16; i++) assert(output[i] == 0);

    while (node.chunks) {
        struct ramfs_data_chunk *next = node.chunks->next;
        free(node.chunks->data);
        free(node.chunks);
        node.chunks = next;
    }
    free(input);
    free(output);
    puts("PASS: large and sparse RAMFS files use non-contiguous chunks");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-ramfs-chunks-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + helpers + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
