#!/usr/bin/env python3
"""Unmount must preserve unmodelled ext2 superblock fields."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("void ext2_unmount_cleanup(void)")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct ext2_super_block { unsigned char modelled[84]; };
struct ext2_mount { void *image; size_t img_size; int device_id; uint32_t start_lba;
    struct ext2_super_block sb; };
static struct ext2_mount *g_ext2;
static struct { void *driver_data; } ext2_driver;
static unsigned char disk[1024], original[1024];
static int fail_read, writes;
static int disk_read_sectors(int id, uint32_t lba, void *buf, int n) {
    assert(id == 7 && lba == 102 && n == 2);
    if (fail_read) return -1;
    memcpy(buf, disk, sizeof disk); return 0;
}
static int disk_write_sectors(int id, uint32_t lba, const void *buf, int n) {
    assert(id == 7 && lba == 102 && n == 2);
    memcpy(disk, buf, sizeof disk); writes++; return 0;
}
static void kfree(void *p) { free(p); }
#define klogprintf(...) ((void)0)
''' + source[start:end] + r'''
static void setup(void) {
    g_ext2 = calloc(1, sizeof *g_ext2); assert(g_ext2);
    g_ext2->device_id = 7; g_ext2->start_lba = 100;
    memset(g_ext2->sb.modelled, 0x5a, sizeof g_ext2->sb.modelled);
    ext2_driver.driver_data = g_ext2;
}
int main(void) {
    for (size_t i = 0; i < sizeof disk; i++) disk[i] = (unsigned char)i;
    memcpy(original, disk, sizeof disk);
    setup(); ext2_unmount_cleanup();
    assert(writes == 1 && !g_ext2 && !ext2_driver.driver_data);
    for (size_t i = 0; i < sizeof disk; i++)
        assert(disk[i] == (i < sizeof(struct ext2_super_block) ? 0x5a : original[i]));
    memcpy(disk, original, sizeof disk);
    setup(); fail_read = 1; ext2_unmount_cleanup();
    assert(writes == 1 && !memcmp(disk, original, sizeof disk));
    unsigned char image[2048]; memset(image, 0x34, sizeof image);
    setup(); g_ext2->image = image; g_ext2->img_size = sizeof image;
    ext2_unmount_cleanup();
    for (size_t i = 0; i < 1024; i++)
        assert(image[1024 + i] == (i < sizeof(struct ext2_super_block) ? 0x5a : 0x34));
    puts("PASS: ext2 unmount preserves superblock fields and skips write after read failure");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-sb-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
