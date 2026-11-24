#!/usr/bin/env python3
"""Block allocator must wrap within its starting group."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static uint32_t e2_alloc_block(struct ext2_mount *m) {")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct ext2_group_desc { uint32_t bg_block_bitmap; unsigned bg_free_blocks_count; };
struct ext2_mount { uint32_t block_size, last_alloc_block, blocks_per_group, groups;
    struct { uint32_t s_first_data_block, s_blocks_count, s_free_blocks_count; } sb; };
static unsigned char bitmap;
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
static int e2_read_gd(struct ext2_mount *m, uint32_t g, struct ext2_group_desc *gd) {
    (void)m; assert(g == 0); gd->bg_block_bitmap = 1; gd->bg_free_blocks_count = 1; return 0;
}
static int e2_write_gd(struct ext2_mount *m, uint32_t g, struct ext2_group_desc *gd) {
    (void)m; (void)g; (void)gd; return 0;
}
static int e2_bread(struct ext2_mount *m, uint32_t b, void *p) {
    (void)m; (void)b; *(unsigned char *)p = bitmap; return 0;
}
static int e2_bwrite(struct ext2_mount *m, uint32_t b, const void *p) {
    (void)m; (void)b; bitmap = *(const unsigned char *)p; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    struct ext2_mount m = { .block_size=1, .last_alloc_block=5,
        .blocks_per_group=8, .groups=1, .sb={1, 9, 1} };
    bitmap = 0xfd; /* block 2 is the sole free block, before the cursor */
    assert(e2_alloc_block(&m) == 2);
    assert(bitmap == 0xff && m.sb.s_free_blocks_count == 0);
    assert(e2_alloc_block(&m) == 0);
    puts("PASS: ext2 allocation revisits free blocks before the cursor");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-wrap-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
