#!/usr/bin/env python3
"""fastfetch's Colors module needs distinct dark/bright VGA palette halves."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/devfs.c").read_text()
start = source.index("static uint8_t devfs_sgr_fg_to_vga(")
end = source.index("static ssize_t devfs_tty_write_stream(", start)
helpers = source[start:end]

assert "devfs_sgr_bg_to_vga(code - 40, 0)" in source
assert "devfs_sgr_bg_to_vga(code - 100, 1)" in source
assert "devfs_sgr_fg_to_vga(code - 30, bright)" in source
assert "devfs_sgr_fg_to_vga(code - 90, 1)" in source

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
''' + helpers + r'''
int main(void) {
    static const uint8_t dark[]  = { 0, 4, 2, 6, 1, 5, 3, 7 };
    static const uint8_t bright[] = { 8, 12, 10, 14, 9, 13, 11, 15 };
    for (int i = 0; i < 8; i++) {
        assert(devfs_sgr_fg_to_vga(i, 0) == dark[i]);
        assert(devfs_sgr_fg_to_vga(i, 1) == bright[i]);
        assert(devfs_sgr_bg_to_vga(i, 0) == dark[i]);
        assert(devfs_sgr_bg_to_vga(i, 1) == bright[i]);
        assert(devfs_sgr_bg_to_vga(i, 1) == (uint8_t)(devfs_sgr_bg_to_vga(i, 0) | 8));
    }
    puts("PASS: fastfetch palette uses 8 dark + 8 bright VGA colors");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-fastfetch-colors-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
