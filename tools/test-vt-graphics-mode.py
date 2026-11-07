#!/usr/bin/env python3
"""Exercise the video registry's actual per-VT graphics-mode projection."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "drv/video/vidcard_core.c").read_text()
body = source[source.index("static int g_kd_graphics["):]
devfs = (root / "fs/virt/devfs.c").read_text()
assert 'if (!tty || !tty->screen || video_kd_graphics()) return;' in devfs
assert devfs.count('if (!video_kd_graphics()) devfs_tty_snapshot_visible(') == 3
program = r'''
#include <assert.h>
#define DEVFS_TTY_COUNT 6
static int active;
static int devfs_get_active(void) { return active; }
''' + body + r'''
int main(void) {
    assert(!video_kd_graphics());
    assert(video_set_vt_graphics(1, 1) == 0);
    assert(!video_kd_graphics() && video_vt_graphics(1));
    active = 1; assert(video_kd_graphics());
    active = 0; assert(!video_kd_graphics());
    assert(video_set_vt_graphics(1, 0) == 0);
    active = 1; assert(!video_kd_graphics());
    assert(video_set_vt_graphics(6, 1) == -1);
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vt-graphics-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: graphics mode follows the active VT, not all terminals")
