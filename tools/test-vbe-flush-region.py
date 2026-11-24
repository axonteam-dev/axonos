#!/usr/bin/env python3
"""Host-test the actual VBE shadow copy and cache flush rectangle."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/video/vbe/vbe.c").read_text()
snippet = source[source.index("static void vbe_flush_region_internal("):
                 source.index("/* Public: flush entire backbuffer")]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
static void *g_frontbuf, *g_backbuf;
static uint32_t g_width, g_height, g_pitch, g_bpp;
static int g_enabled;
static unsigned flushes, barriers;
static size_t offsets[16], lengths[16];
static void vbe_fb_cache_flush_range(void *p, size_t n) {
    assert(flushes < 16);
    offsets[flushes] = (uint8_t *)p - (uint8_t *)g_frontbuf;
    lengths[flushes++] = n;
}
static void vbe_fb_store_barrier(void) { barriers++; }
''' + snippet + r'''
int main(void) {
    uint8_t front[3 * 128] = {0}, back[3 * 128];
    memset(back, 0x5a, sizeof(back));
    g_frontbuf = front; g_backbuf = back; g_enabled = 1;
    g_width = 24; g_height = 3; g_pitch = 128; g_bpp = 32;
    vbe_flush_region_internal(20, 1, 10, UINT_MAX);
    assert(flushes == 2 && barriers == 1);
    assert(offsets[0] == 208 && offsets[1] == 336);
    assert(lengths[0] == 16 && lengths[1] == 16);
    for (size_t i = 0; i < sizeof(front); ++i)
        assert(front[i] == ((i >= 208 && i < 224) ||
                            (i >= 336 && i < 352) ? 0x5a : 0));
    flushes = barriers = 0;
    vbe_flush_region_internal(0, 1, 24, 2);
    assert(flushes == 1 && barriers == 1);
    assert(offsets[0] == 128 && lengths[0] == 256);
    assert(memcmp(front + 128, back + 128, 256) == 0);
    flushes = barriers = 0;
    vbe_flush_region_internal(1, 2, 0, 1);
    vbe_flush_region_internal(1, 2, 1, 0);
    vbe_flush_region_internal(24, 2, 1, 1);
    assert(flushes == 0 && barriers == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="vbe-flush-", dir="/tmp/opencode") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: VBE shadow flush clips and writes back only the copied rectangle")
