#!/usr/bin/env python3
"""Exercise ext2 feature probing against real e2fsprogs-created images."""
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
program = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
int main(int argc, char **argv) {
    (void)e2_le16;
    if (argc != 3) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    if (fseek(f, 0, SEEK_END)) return 2;
    long len = ftell(f); if (len < 2048 || fseek(f, 0, SEEK_SET)) return 2;
    void *data = malloc((size_t)len); if (!data) return 2;
    if (fread(data, 1, (size_t)len, f) != (size_t)len) return 2;
    fclose(f);
    struct ext2_mount m = {.image=data, .img_size=(size_t)len};
    int accepted = e2_read_sb(&m) == 0;
    free(data);
    return accepted != (argv[2][0] == '1');
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-images-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    for fs, accepted in (("ext2", "1"), ("ext3", "0"), ("ext4", "0")):
        image = path / (fs + ".img")
        with image.open("wb") as f:
            f.truncate(32 * 1024 * 1024)
        subprocess.run(["mke2fs", "-q", "-F", "-t", fs, str(image)], check=True)
        subprocess.run([str(path / "test"), str(image), accepted], check=True)
        print(f"PASS: real {fs} image {'accepted' if accepted == '1' else 'rejected'}")
