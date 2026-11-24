#!/usr/bin/env python3
"""A second ext2 mount must not replace the first mount's live backing."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int ext2_bind(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
struct ext2_mount { struct { uint32_t s_blocks_count; } sb;
    uint32_t block_size, inode_size, groups; };
static struct ext2_mount *g_ext2;
static struct { void *driver_data; } ext2_driver;
static int reads, read_result;
static int e2_read_sb(struct ext2_mount *m) { (void)m; reads++; return read_result; }
#define klogprintf(...) ((void)0)
''' + source[start:end] + r'''
int main(void) {
    struct ext2_mount first = {0}, second = {0};
    read_result = -1;
    assert(ext2_bind(&first) == -1 && !g_ext2);
    read_result = 0;
    assert(ext2_bind(&first) == 0 && g_ext2 == &first);
    assert(ext2_bind(&second) == -1 && g_ext2 == &first);
    assert(ext2_driver.driver_data == &first && reads == 2);
    puts("PASS: a second ext2 mount cannot replace active backing");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-singleton-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
