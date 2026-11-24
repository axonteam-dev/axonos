#!/usr/bin/env python3
"""Unsupported ext3/ext4 features must never reach the ext2 writer."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/ext2.c").read_text()
header = (root / "inc/ext2.h").read_text()
sb_start = header.index("struct ext2_super_block {")
sb_end = header.index("\n};", sb_start) + 3
helpers_start = source.index("static uint32_t e2_le32(")
helpers_end = source.index("\nstatic int e2_block_lba(", helpers_start)
read_start = source.index("static int e2_read_sb(")
read_end = source.index("\n}\n", read_start) + 2
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define EXT2_SUPER_MAGIC 0xEF53
''' + header[sb_start:sb_end] + r'''
struct ext2_mount {
    void *image; size_t img_size; int device_id; uint32_t start_lba, part_sectors;
    struct ext2_super_block sb;
    uint32_t block_size, inode_size, inodes_per_group, blocks_per_group;
    uint32_t groups, first_ino;
};
static int disk_read_sectors(int id, uint32_t lba, void *buf, int n) {
    (void)id; (void)lba; (void)buf; (void)n; return -1;
}
''' + source[helpers_start:helpers_end] + "\n" + source[read_start:read_end] + r'''
static void set32(unsigned char *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
int main(void) {
    static unsigned char image[1024 * 1024] = {0};
    (void)e2_le16;
    unsigned char *raw = image + 1024;
    struct ext2_super_block sb = {0};
    struct ext2_mount m = {0};
    sb.s_magic = EXT2_SUPER_MAGIC;
    sb.s_rev_level = 1; sb.s_inode_size = 256;
    sb.s_blocks_count = 1024; sb.s_blocks_per_group = 8192;
    sb.s_inodes_per_group = 1024; sb.s_inodes_count = 1024;
    memcpy(raw, &sb, sizeof sb);
    m.image = image; m.img_size = sizeof image;
    set32(raw + 92, 0x38); /* common ext2 compatible features */
    set32(raw + 96, 2); set32(raw + 100, 3);
    assert(e2_read_sb(&m) == 0);
    set32(raw + 92, 0x3c); /* ext3 journal */
    assert(e2_read_sb(&m) != 0);
    set32(raw + 92, 0x38);
    set32(raw + 96, 0x42); /* ext4 extents */
    assert(e2_read_sb(&m) != 0);
    set32(raw + 96, 2); set32(raw + 100, 0x403); /* metadata checksums */
    assert(e2_read_sb(&m) != 0);
    set32(raw + 100, 3); set32(raw + 24, 32); /* invalid shift */
    assert(e2_read_sb(&m) != 0);
    set32(raw + 24, 0); set32(raw + 40, 8193); /* inode bitmap overflow */
    assert(e2_read_sb(&m) != 0);
    set32(raw + 40, 1024); raw[88] = 129; raw[89] = 0;
    assert(e2_read_sb(&m) != 0); /* unsupported inode size */
    raw[88] = 0; raw[89] = 1;
    m.img_size = sizeof image - 1;
    assert(e2_read_sb(&m) != 0); /* filesystem exceeds backing image */
    puts("PASS: ext2 accepts supported features and rejects ext3/ext4 and invalid block sizes");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-features-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
