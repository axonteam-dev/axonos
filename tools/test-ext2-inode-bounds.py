#!/usr/bin/env python3
"""Invalid inode numbers must not address another on-disk structure."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int e2_read_inode(")
end = source.index("\nstatic uint32_t e2_alloc_block(", start)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct ext2_inode { uint32_t value; };
struct ext2_group_desc { uint32_t bg_inode_table; };
struct ext2_mount { uint32_t inodes_per_group, inode_size, block_size;
    struct { uint32_t s_inodes_count; } sb; };
static unsigned reads, writes;
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
static int e2_read_gd(struct ext2_mount *m, uint32_t g, struct ext2_group_desc *gd) {
    (void)m; (void)g; gd->bg_inode_table = 1; reads++; return 0;
}
static int e2_bread(struct ext2_mount *m, uint32_t b, void *p) {
    (void)b; memset(p, 0, m->block_size); return 0;
}
static int e2_bwrite(struct ext2_mount *m, uint32_t b, const void *p) {
    (void)m; (void)b; (void)p; writes++; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    struct ext2_mount m = {8, 128, 1024, {8}};
    struct ext2_inode inode = {42};
    assert(e2_read_inode(&m, 0, &inode) != 0);
    assert(e2_read_inode(&m, 9, &inode) != 0);
    assert(e2_write_inode(&m, 0, &inode) != 0);
    assert(e2_write_inode(&m, 9, &inode) != 0);
    assert(reads == 0 && writes == 0);
    assert(e2_read_inode(&m, 8, &inode) == 0);
    assert(e2_write_inode(&m, 8, &inode) == 0);
    assert(reads == 2 && writes == 1);
    puts("PASS: ext2 rejects inode numbers outside the filesystem");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-inode-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
