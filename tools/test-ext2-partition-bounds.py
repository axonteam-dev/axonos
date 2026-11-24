#!/usr/bin/env python3
"""Block I/O must not cross the partition or wrap the device LBA."""
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
#include <stdio.h>
struct ext2_mount { void *image; size_t img_size; int device_id;
    uint32_t start_lba, part_sectors, block_size; int write_started;
    struct { uint32_t s_blocks_count; uint16_t s_state; } sb; };
static int reads, writes;
static int disk_read_sectors(int id, uint32_t lba, void *buf, uint32_t n) {
    (void)id; (void)lba; (void)buf; (void)n; reads++; return 0;
}
static int disk_write_sectors(int id, uint32_t lba, const void *buf, uint32_t n) {
    (void)id; (void)lba; (void)buf; (void)n; writes++; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    struct ext2_mount m = {.start_lba=100, .part_sectors=16, .block_size=4096,
                           .write_started=1, .sb={.s_blocks_count=2}};
    char data[4096] = {0};
    assert(e2_bread(&m, 1, data) == 0 && reads == 1);
    assert(e2_bwrite(&m, 1, data) == 0 && writes == 1);
    assert(e2_bread(&m, 2, data) != 0 && reads == 1);
    assert(e2_bwrite(&m, 2, data) != 0 && writes == 1);
    m.part_sectors = 64;
    assert(e2_bwrite(&m, 2, data) != 0 && writes == 1);
    m.start_lba = UINT32_MAX - 5; m.part_sectors = 0;
    assert(e2_bwrite(&m, 0, data) != 0 && writes == 1);
    m.start_lba = UINT32_MAX - 7;
    assert(e2_bwrite(&m, 0, data) == 0 && writes == 2);
    puts("PASS: ext2 block I/O respects partition and LBA bounds");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-bounds-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
