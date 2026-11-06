#!/usr/bin/env python3
"""Test bounded framebuffer presentation while the graphics owner waits."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void console_graphics_wait_present(")
end = source.index("\n}\n", start) + 2
snippet = source[start:end]
for token in ("console_graphics_wait_present(curth)",
              "console_graphics_wait_present(poll_thr)",
              "console_graphics_wait_present(wait_thr)"):
    assert token in source
program = r'''
#include <assert.h>
#include <stdint.h>
typedef struct { int owner; } thread_t;
static int graphics, count;
static uint64_t now;
static int video_kd_graphics(void) { return graphics; }
static int console_graphics_owned_by(thread_t *t) { return t && t->owner; }
static uint64_t time_monotonic_ms(void) { return now; }
static void fbdev_sync_user_frontbuffer(void) { count++; }
''' + snippet + r'''
int main(void) {
    thread_t owner = {1}, other = {0};
    console_graphics_wait_present(&owner); assert(count == 0);
    graphics = 1; console_graphics_wait_present(&other); assert(count == 0);
    console_graphics_wait_present(&owner); assert(count == 1);
    now = 49; console_graphics_wait_present(&owner); assert(count == 1);
    now = 50; console_graphics_wait_present(&owner); assert(count == 2);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-graphics-present-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: graphics wait periodically presents only the owner's framebuffer")
