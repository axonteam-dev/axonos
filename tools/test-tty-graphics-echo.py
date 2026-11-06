#!/usr/bin/env python3
"""Keyboard echo must preserve tty state without painting over graphics."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/devfs.c").read_text()
sig = "static void devfs_tty_echo_bytes(struct devfs_tty *tty, const uint8_t *bytes,\n                                 size_t count) {"
start = source.index(sig)
end = source.index("\n}\n", start) + 3
erase_start = source.index("static int devfs_tty_try_erase(struct devfs_tty *t, int tty) {")
erase_end = source.index("\n}\n", erase_start) + 3
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define TTY_ECHO 8
struct devfs_tty { int id, out_lock, cursor_x, cursor_y, in_count, in_tail, term_lflag;
                   unsigned char inbuf[8], *screen; uint8_t current_attr; };
static int graphics, begins, ends, draws, cursor, emitted, backing;
static int video_kd_graphics(void) { return graphics; }
static int devfs_get_active(void) { return 1; }
static int try_acquire(int *lock) { assert(!*lock); *lock=1; return 1; }
static void release(int *lock) { assert(*lock); *lock=0; }
static void console_begin_tty_batch(void) { begins++; }
static void console_end_tty_batch(void) { ends++; }
static void console_set_cursor(int x, int y) { (void)x; (void)y; cursor++; }
static void console_putch_xy(int x, int y, int ch, int a) { (void)x;(void)y;(void)ch;(void)a; draws++; }
static uint8_t console_get_cell_attr(int x, int y) { (void)x; (void)y; return 7; }
static unsigned devfs_tty_cols(void) { return 4; }
static void tty_cell_store(uint8_t *p, unsigned i, uint16_t c, uint8_t a) { (void)p;(void)i;(void)c;(void)a; backing++; }
static void devfs_tty_emit_byte(struct devfs_tty *t, int visible, uint8_t c) { (void)t;(void)c; emitted++; if (visible) draws++; }
''' + source[start:end] + source[erase_start:erase_end] + r'''
int main(void) {
    uint8_t screen[64]={0}, ch='a';
    struct devfs_tty t={.id=1,.cursor_x=1,.in_count=1,.in_tail=1,.term_lflag=TTY_ECHO,.screen=screen};
    t.inbuf[0]='a'; graphics=1;
    devfs_tty_echo_bytes(&t,&ch,1);
    assert(emitted==1 && !begins && !ends && !draws && !cursor);
    assert(devfs_tty_try_erase(&t,1)==1 && backing==1 && t.cursor_x==0 && !draws && !cursor);
    graphics=0; devfs_tty_echo_bytes(&t,&ch,1);
    assert(begins==1 && ends==1 && draws==1 && cursor==1);
    puts("PASS: keyboard echo and erase never paint in graphics mode");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-tty-echo-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
