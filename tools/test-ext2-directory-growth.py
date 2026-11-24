#!/usr/bin/env python3
"""A full ext2 directory can grow without altering an HTree index."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
vstart = source.index("static int e2_valid_dirent(")
vend = source.index("\n}\n", vstart) + 2
start = source.index("static int e2_dir_add(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct ext2_dir_entry { uint32_t inode; uint16_t rec_len; uint8_t name_len, file_type; };
struct ext2_inode { uint32_t i_size, i_blocks, i_flags, blocks[12]; };
struct ext2_mount { uint32_t block_size; };
static unsigned char blocks[3][512];
static unsigned allocs, writes, inodes;
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
static uint32_t e2_get_block(struct ext2_mount *m, struct ext2_inode *i, uint32_t b) {
    (void)m; return i->blocks[b];
}
static int e2_set_block(struct ext2_mount *m, struct ext2_inode *i, uint32_t b, uint32_t p) {
    (void)m; i->blocks[b] = p; return 0;
}
static uint32_t e2_alloc_block(struct ext2_mount *m) { (void)m; allocs++; return 2; }
static int e2_bread(struct ext2_mount *m, uint32_t b, void *out) {
    (void)m; memcpy(out, blocks[b], 512); return 0;
}
static int e2_bwrite(struct ext2_mount *m, uint32_t b, const void *in) {
    (void)m; writes++; memcpy(blocks[b], in, 512); return 0;
}
static int e2_write_inode(struct ext2_mount *m, uint32_t n, struct ext2_inode *i) {
    (void)m; (void)n; (void)i; inodes++; return 0;
}
''' + source[vstart:vend] + "\n" + source[start:end] + r'''
int main(void) {
    struct ext2_mount m = {512};
    struct ext2_inode dir = {.i_size=512, .i_blocks=1, .blocks={1}};
    struct ext2_dir_entry *first = (void *)blocks[1];
    char name[256]; memset(name, 'a', 255); name[255] = 0;
    first->inode=3; first->rec_len=512; first->name_len=255;
    assert(e2_dir_add(&m, 7, &dir, name, 8, 1) == 0);
    struct ext2_dir_entry *second = (void *)blocks[2];
    assert(dir.i_size == 1024 && dir.i_blocks == 2 && dir.blocks[1] == 2);
    assert(second->inode == 8 && second->rec_len == 512 && second->name_len == 255);
    assert(allocs == 1 && writes == 1 && inodes == 1);
    dir.i_flags = 0x1000;
    assert(e2_dir_add(&m, 7, &dir, "x", 9, 1) != 0);
    assert(allocs == 1 && writes == 1 && inodes == 1);
    puts("PASS: ext2 grows full linear directories and rejects HTree writes");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-dir-growth-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
