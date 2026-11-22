#!/usr/bin/env python3
"""Kernel console output must update the VT without painting over graphics."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/devfs.c").read_text()
console = (root / "drv/video/console.c").read_text()
for name in ("console_putch_xy", "console_fill_rect", "console_write_str_xy", "console_set_cursor",
             "console_clear_screen_attr", "console_clear_line_segment", "console_scroll_region_up",
             "console_putc_tty_literal"):
    pos = console.index("void " + name + "(")
    body = console[pos:console.index("\n}", pos)]
    assert "video_kd_graphics()" in body, name
end_batch = console[console.index("void console_end_tty_batch("):console.index("void console_set_cursor(")]
assert "video_kd_graphics()" in end_batch
start = source.index("void devfs_tty_console_write_locked(")
end = source.index("\n/*\n * Console paint re-entrancy guard", start)
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
struct devfs_tty { int id; uint8_t acs_mode, insert_mode; unsigned cursor_x, cursor_y; };
static struct devfs_tty tty = { .id = 1 };
static int active = 1, graphics, batches, cursors, painted, stored, polls;
static int video_vt_graphics(int i) { assert(i == 1); return graphics; }
static int devfs_get_active(void) { return active; }
static void console_begin_tty_batch(void) { batches++; }
static void console_end_tty_batch(void) { batches--; }
static void console_set_cursor(unsigned x, unsigned y) { (void)x; (void)y; cursors++; }
static void keyboard_poll_drain(void) { polls++; }
static void devfs_tty_emit_byte(struct devfs_tty *t, int visible, uint8_t c) {
    assert(!t->acs_mode && !t->insert_mode);
    stored++; painted += visible; t->cursor_x += c != '\r';
}
''' + source[start:end] + r'''
int main(void) {
    tty.acs_mode = 1; tty.insert_mode = 1;
    graphics = 1;
    devfs_tty_console_write_locked(&tty, "a\n", 2);
    assert(stored == 3 && painted == 0 && cursors == 0 && batches == 0);
    assert(tty.acs_mode == 1 && tty.insert_mode == 1 && polls == 1);
    graphics = 0;
    devfs_tty_console_write_locked(&tty, "b\n", 2);
    assert(stored == 6 && painted == 3 && cursors == 1 && batches == 0);
    assert(tty.acs_mode == 1 && tty.insert_mode == 1);
    active = 0;
    devfs_tty_console_write_locked(&tty, "c", 1);
    assert(stored == 7 && painted == 3 && cursors == 1 && batches == 0);
}
'''
with tempfile.TemporaryDirectory(prefix="axon-console-render-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: kernel console retains VT output without painting during graphics")
