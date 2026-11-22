#!/usr/bin/env python3
"""Exercise the real fbdev write path with a fake framebuffer and video backend."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/video/fbdev.c").read_text()
snippet = source[source.index("void fbdev_copy_from("):source.index("int fbdev_mmap_user(")]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
static struct { void *kva; size_t len; uint32_t width, height, pitch; int active; } g_fbdev;
static unsigned updates, syncs;
static uint32_t rx, ry, rw, rh;
static void video_flush_region_pixels(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    updates++; rx = x; ry = y; rw = w; rh = h;
}
static void video_display_sync(void) { syncs++; }
''' + snippet + r'''
int main(void) {
    unsigned char fb[128] = {0}, src[128]; memset(src, 7, sizeof(src));
    g_fbdev.kva = fb; g_fbdev.len = sizeof(fb); g_fbdev.width = 6;
    g_fbdev.height = 4; g_fbdev.pitch = 32; g_fbdev.active = 1;
    fbdev_copy_from(34, src, 3);
    assert(updates == 1 && syncs == 1 && rx == 0 && ry == 1 && rw == 6 && rh == 1);
    assert(fb[34] == 7 && fb[36] == 7 && fb[37] == 0);
    fbdev_copy_from(63, src, 2);
    assert(updates == 2 && ry == 1 && rh == 2);
    fbdev_copy_from(126, src, 128);
    assert(updates == 3 && ry == 3 && rh == 1 && fb[127] == 7);
    fbdev_copy_from(128, src, 1);
    assert(updates == 3 && syncs == 3);
    g_fbdev.height = 2;
    fbdev_copy_from(64, src, 1);
    assert(updates == 3 && fb[64] == 7);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="fbdev-damage-", dir="/tmp/opencode") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: fbdev writes update only affected visible rows")
