#!/usr/bin/env python3
"""An unreadable indirect block is an error, not a sparse hole."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static uint32_t e2_get_block(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
struct ext2_mount { uint32_t block_size; };
struct ext2_inode { uint32_t i_block[15]; };
static int fail, calls;
static int e2_ptr_get(struct ext2_mount *m, uint32_t table, uint32_t idx, uint32_t *out) {
    (void)m; (void)table; (void)idx; calls++;
    if (fail) return -1;
    *out = 0; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    struct ext2_mount m = {1024}; struct ext2_inode i = {{0}};
    assert(e2_get_block(&m, &i, 12) == 0 && !calls);
    i.i_block[12] = 2; fail = 1;
    assert(e2_get_block(&m, &i, 12) == UINT32_MAX && calls == 1);
    fail = 0;
    assert(e2_get_block(&m, &i, 12) == 0 && calls == 2);
    i.i_block[13] = 3; fail = 1;
    assert(e2_get_block(&m, &i, 12 + 256) == UINT32_MAX);
    assert(e2_get_block(&m, &i, 12 + 256 + 256 * 256) == UINT32_MAX);
    puts("PASS: ext2 indirect-block I/O failures are not treated as holes");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-lookup-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
