#!/usr/bin/env python3
"""TTY text output must not draw over an active graphics framebuffer."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/devfs.c").read_text()
start = source.index("static ssize_t devfs_tty_write_stream(struct devfs_tty *t, const char *s,\n")
end = source.index("    unsigned long out_flags", start)
prefix = source[start:end]
assert "tty_on_vga_batch = (idx == devfs_active && !video_kd_graphics())" in prefix
assert "const int tty_on_vga = tty_on_vga_batch;" in source[end:]
assert "tty_cell_store(tty->screen" in source
expr = prefix[prefix.index("(idx == devfs_active"):prefix.index(";", prefix.index("(idx == devfs_active"))]
program = r'''
#include <assert.h>
#include <stdio.h>
static int devfs_active=2, graphics;
static int video_kd_graphics(void) { return graphics; }
static int visible(int idx) { return ''' + expr + r'''; }
int main(void) {
    assert(visible(2) && !visible(1));
    graphics=1; assert(!visible(2) && !visible(1));
    graphics=0; assert(visible(2));
    puts("PASS: graphics mode suppresses active TTY framebuffer painting");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-tty-graphics-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
