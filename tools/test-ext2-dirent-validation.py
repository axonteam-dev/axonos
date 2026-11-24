#!/usr/bin/env python3
"""Malformed on-disk directory entries must not escape their block."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int e2_valid_dirent(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
struct ext2_dir_entry {
    uint32_t inode; uint16_t rec_len; uint8_t name_len, file_type;
};
''' + source[start:end] + r'''
int main(void) {
    struct ext2_dir_entry de = {1, 12, 3, 1};
    assert(e2_valid_dirent(&de, 12));
    assert(!e2_valid_dirent(&de, 11));
    assert(!e2_valid_dirent(&de, 7));
    de.rec_len = 0; assert(!e2_valid_dirent(&de, 4096));
    de.rec_len = 10; assert(!e2_valid_dirent(&de, 4096));
    de.rec_len = 12; de.name_len = 5;
    assert(!e2_valid_dirent(&de, 4096));
    de.rec_len = 4096; de.name_len = 255;
    assert(e2_valid_dirent(&de, 4096));
    puts("PASS: ext2 validates directory entry length and name bounds");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-dirent-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
