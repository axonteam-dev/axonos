#!/usr/bin/env python3
"""Sequential opens must refresh inode size and block pointers."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int ext2_refresh_file(")
end = source.index("\nstatic void ext2_release(", start)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#define S_IFREG 0100000
#define S_IFLNK 0120000
struct ext2_inode { uint32_t i_size, i_blocks, i_mode, i_block[15], i_dir_acl; };
struct ext2_mount { uint32_t block_size;
    struct { uint32_t s_first_data_block, s_blocks_count; } sb; };
struct ext2_file_handle { uint32_t inode_no; struct ext2_inode inode; };
struct fs_file { void *driver_private; size_t size; };
static struct ext2_mount mount = {.block_size=512, .sb={1, 4}}, *g_ext2 = &mount;
static struct ext2_inode disk_inode;
static unsigned char blocks[4][512];
static uint32_t next_block = 1;
static int fail_write_block;
static int e2_read_inode(struct ext2_mount *m, uint32_t n, struct ext2_inode *out) {
    (void)m; assert(n == 7); *out = disk_inode; return 0;
}
static int e2_write_inode(struct ext2_mount *m, uint32_t n, const struct ext2_inode *in) {
    (void)m; assert(n == 7); disk_inode = *in; return 0;
}
static uint32_t e2_get_block(struct ext2_mount *m, struct ext2_inode *i, uint32_t b) {
    (void)m; assert(b < 2); return i->i_block[b];
}
static int e2_set_block(struct ext2_mount *m, struct ext2_inode *i, uint32_t b, uint32_t p) {
    (void)m; assert(b < 2); i->i_block[b] = p; return 0;
}
static uint32_t e2_alloc_block(struct ext2_mount *m) { (void)m; return next_block++; }
static int e2_bread(struct ext2_mount *m, uint32_t b, void *out) {
    (void)m; memcpy(out, blocks[b], 512); return 0;
}
static int e2_bwrite(struct ext2_mount *m, uint32_t b, const void *in) {
    (void)m; if ((int)b == fail_write_block) return -1;
    memcpy(blocks[b], in, 512); return 0;
}
static int e2_free_data_block(struct ext2_mount *m, uint32_t b) {
    (void)m; (void)b; return 0;
}
static uint32_t e2_le32(const void *p) {
    const unsigned char *b = p;
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 |
           (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
''' + source[start:end] + r'''
int main(void) {
    struct ext2_file_handle h1 = {.inode_no=7}, h2 = {.inode_no=7};
    struct fs_file a = {.driver_private=&h1}, b = {.driver_private=&h2};
    char out[4] = {0};
    disk_inode.i_mode = S_IFREG;
    assert(ext2_write(&a, "ab", 2, 0) == 2);
    assert(ext2_read(&b, out, 2, 0) == 2 && !memcmp(out, "ab", 2));
    assert(ext2_write(&b, "c", 1, 2) == 1);
    assert(ext2_read(&a, out, 3, 0) == 3 && !memcmp(out, "abc", 3));
    assert(disk_inode.i_block[0] == 1 && next_block == 2 && a.size == 3);
    assert(ext2_write(&a, "x", 1, UINT32_MAX) == -1);
    {
        char data[1024]; memset(data, 'q', sizeof data);
        fail_write_block = 2;
        assert(ext2_write(&a, data, sizeof data, 0) == 512);
        assert(disk_inode.i_size == 512);
        assert(ext2_read(&b, out, 3, 0) == 3 && !memcmp(out, "qqq", 3));
    }
    fail_write_block = 0;
    disk_inode.i_size = 3; disk_inode.i_mode = S_IFREG;
    memset(blocks[1], 'x', sizeof blocks[1]);
    assert(ext2_ftruncate(&a, 7) == 0 && disk_inode.i_size == 7);
    assert(blocks[1][2] == 'x' && blocks[1][3] == 0 && blocks[1][511] == 0);
    assert(ext2_ftruncate(&a, 2) == -95 && disk_inode.i_size == 7);
    assert(ext2_ftruncate(&a, -1) == -22);
    disk_inode.i_dir_acl = 1;
    assert(ext2_read(&a, out, 1, 0) == -1);
    assert(ext2_write(&a, "x", 1, 0) == -1);
    memset(&disk_inode, 0, sizeof disk_inode);
    disk_inode.i_mode = S_IFLNK; disk_inode.i_size = 3;
    memcpy(disk_inode.i_block, "abc", 3);
    assert(ext2_read(&a, out, 2, 1) == 2 && !memcmp(out, "bc", 2));
    assert(ext2_write(&a, "x", 1, 0) == -1);
    puts("PASS: sequential ext2 handles refresh inode size and block pointers");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-handles-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
