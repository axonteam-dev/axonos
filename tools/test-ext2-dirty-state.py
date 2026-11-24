#!/usr/bin/env python3
"""A failed dirty-state write must prevent the subsequent filesystem write."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int e2_block_lba(")
end = source.index("\nstatic int e2_read_sb(", start)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct ext2_mount {
    void *image; size_t img_size; int device_id;
    uint32_t start_lba, part_sectors, block_size;
    struct { uint32_t s_blocks_count; uint16_t s_state; } sb;
    int write_started;
};
static unsigned char disk[8192];
static int fail_read, fail_write, writes;
static int disk_read_sectors(int id, uint32_t lba, void *out, uint32_t n) {
    (void)id; if (fail_read || (uint64_t)(lba+n)*512 > sizeof disk) return -1;
    memcpy(out, disk + lba*512, n*512); return 0;
}
static int disk_write_sectors(int id, uint32_t lba, const void *in, uint32_t n) {
    (void)id; if (fail_write || (uint64_t)(lba+n)*512 > sizeof disk) return -1;
    memcpy(disk + lba*512, in, n*512); writes++; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    unsigned char data[1024]; memset(data, 0x3c, sizeof data);
    struct ext2_mount m = {.part_sectors=16, .block_size=1024,
                            .sb={.s_blocks_count=8, .s_state=3}};
    disk[1024+58] = 3; disk[1024+59] = 0x12; disk[1024+200] = 0x5a;
    assert(e2_bread(&m, 4, data) == 0);
    memset(data, 0x3c, sizeof data);
    fail_read = 1;
    assert(e2_bwrite(&m, 4, data) < 0 && !writes && !m.write_started);
    fail_read = 0; fail_write = 1;
    assert(e2_bwrite(&m, 4, data) < 0 && !writes && !m.write_started);
    assert(disk[1024+58] == 3 && disk[4096] == 0);
    fail_write = 0;
    assert(e2_bwrite(&m, 4, data) == 0 && writes == 2 && m.write_started);
    assert(disk[1024+58] == 2 && disk[1024+59] == 0x12);
    assert(disk[1024+200] == 0x5a && m.sb.s_state == 2);
    assert(disk[4096] == 0x3c);
    assert(e2_bwrite(&m, 5, data) == 0 && writes == 3);
    unsigned char image[8192] = {0};
    struct ext2_mount mem = {.image=image, .img_size=sizeof image,
        .block_size=1024, .sb={.s_blocks_count=8, .s_state=1}};
    image[1024+58] = 1;
    assert(e2_bwrite(&mem, 4, data) == 0);
    assert(image[1024+58] == 0 && image[4096] == 0x3c);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-dirty-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: ext2 marks dirty before writing and propagates marker I/O errors")
