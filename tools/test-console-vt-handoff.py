#!/usr/bin/env python3
"""Reproduce console output preempted by a VT/graphics handoff, without a VM."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
devfs = (root / "fs/virt/devfs.c").read_text()
vga = (root / "drv/video/vga.c").read_text()
console = (root / "drv/video/console.c").read_text()
cirrus = (root / "drv/video/cirrus/cirrusfb.c").read_text()

begin = cirrus[cirrus.index("void cirrusfb_begin_batch(void) {"):
               cirrus.index("void cirrusfb_end_batch(void) {")]
end = cirrus[cirrus.index("void cirrusfb_end_batch(void) {"):
             cirrus.index("/* ANSI: kputchar()")]
glyph = cirrus[cirrus.index("static uint32_t vga_palette[16] ="):
               cirrus.index("static void draw_text_row_noflush(")]
erase = cirrus[cirrus.index("static void swcursor_erase_at(uint32_t cx, uint32_t cy) {"):
               cirrus.index("static void swcursor_draw_at(uint32_t cx, uint32_t cy) {")]
batch = console[console.index("static int g_tty_batch ="):
                console.index("void console_get_cursor(")]
write = devfs[devfs.index("void devfs_tty_console_write_locked("):
              devfs.index("static void devfs_tty_emit_byte_impl(")]
printer = vga[vga.index("static int utoa_rev("):vga.index("void vga_set_cursor(")]

program = r'''
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef int spinlock_t;
struct devfs_tty {
    int id, out_lock;
    uint8_t acs_mode, insert_mode;
    uint32_t cursor_x, cursor_y;
};
static struct devfs_tty ttys[2] = { { .id = 0 }, { .id = 1 } };
static int active, mode[2], switch_on_lock, switch_target, erases, unlocked_stores, painted;
static int stored[2];
static uint8_t framebuffer = 0xa5;
static spinlock_t vga_lock_spin;
static int g_ready = 1, g_hwcursor_ok, g_swcursor_visible = 1;
static int g_swcursor_frozen, g_batch_depth, g_fb_dirty, g_hwcursor_deferred;
static uint32_t g_hwcursor_def_x, g_hwcursor_def_y;
static uint32_t g_cursor_x, g_cursor_y;
typedef struct { uint16_t ch; uint8_t attr; } cell_t;
static cell_t cell = { 'k', 7 }, *g_textbuf = &cell;
static void *g_fb = &framebuffer; /* no RAM shadow: draw directly into VRAM */
static uint32_t g_cols = 1, g_rows = 1, g_pitch = 4, g_bpp = 32, g_margin_rows;
static int g_logo_visible;
static int devfs_get_active(void) { return active; }
static struct devfs_tty *devfs_get_tty_by_index(int n) { return &ttys[n]; }
static int devfs_is_ready(void) { return 1; }
static int video_kd_graphics(void) { return mode[active]; }
static int video_vt_graphics(int n) { return mode[n]; }
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    if (switch_on_lock) { active = switch_target; switch_on_lock = 0; }
    assert(!*lock); *lock = 1; *flags = 1;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags; assert(*lock); *lock = 0;
}
static int cirrusfb_is_ready(void) { return 1; }
static int vbe_is_available(void) { return 0; }
static uint32_t FONT_W(void) { return 1; }
static uint32_t FONT_H(void) { return 1; }
static void fb_dirty_mark(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    (void)x; (void)y; (void)w; (void)h;
}
static void font_blit_glyph(void *fb, uint32_t pitch, uint32_t bpp,
                            uint32_t x, uint32_t y, uint16_t ch,
                            uint32_t fg, uint32_t bg) {
    (void)pitch; (void)bpp; (void)x; (void)y; (void)fg; (void)bg;
    erases++; *(uint8_t *)fb = (uint8_t)ch;
}
''' + glyph + erase + begin + r'''
static void hwcursor_set_pos(uint32_t x, uint32_t y) { (void)x; (void)y; }
static void cirrusfb_flush_dirty_if_small(void) {}
static void swcursor_draw_at(uint32_t x, uint32_t y) { (void)x; (void)y; }
''' + end + r'''
static void vbefb_begin_batch(void) { assert(0); }
static void vbefb_end_batch(void) { assert(0); }
static void cirrusfb_set_cursor(uint32_t x, uint32_t y) { (void)x; (void)y; }
static void vbefb_set_cursor(uint32_t x, uint32_t y) { (void)x; (void)y; }
static void vga_set_cursor(uint32_t x, uint32_t y) { (void)x; (void)y; }
''' + batch + r'''
static void console_get_cursor(uint32_t *x, uint32_t *y) { *x = *y = 0; }
static void keyboard_poll_drain(void) {}
static void devfs_tty_emit_byte(struct devfs_tty *t, int visible, uint8_t c) {
    (void)c; unlocked_stores += !t->out_lock; stored[t->id]++; painted += visible;
}
''' + write + r'''
static void console_putc_nolock(uint8_t c, uint8_t color) { (void)c; (void)color; }
static void flush_cursor_nolock(void) {}
''' + printer + r'''
int main(void) {
    /* A text-VT printk is preempted immediately before locking the tty. */
    mode[1] = 1; switch_target = 1; switch_on_lock = 1;
    kprintf("fault");
    assert(active == 1 && mode[1]);
    assert(framebuffer == 0xa5 && !erases && !painted);
    assert(!unlocked_stores && stored[0] == 5 && !stored[1]);
    assert(!ttys[0].out_lock && !ttys[1].out_lock && !g_tty_batch && !g_batch_depth);

    /* klog keeps the selected VT locked and in its backing store too. */
    memset(stored, 0, sizeof(stored));
    active = 0; switch_on_lock = 1;
    devfs_tty_console_write("log", 3);
    assert(framebuffer == 0xa5 && !erases && !painted);
    assert(!unlocked_stores && stored[0] == 3 && !stored[1]);
    assert(!ttys[0].out_lock && !ttys[1].out_lock && !g_tty_batch && !g_batch_depth);

    /* Even a defensive direct batch must not erase the cursor into VRAM. */
    cirrusfb_begin_batch();
    cirrusfb_end_batch();
    assert(framebuffer == 0xa5 && !erases && !g_batch_depth);

    /* Switching from graphics back to text never paints the old VT's log. */
    memset(stored, 0, sizeof(stored));
    active = 1; switch_target = 0; switch_on_lock = 1;
    devfs_tty_console_write("ok", 2);
    assert(!unlocked_stores && !stored[0] && stored[1] == 2 && !painted);
    assert(!erases && !ttys[0].out_lock && !ttys[1].out_lock);
    assert(!g_tty_batch && !g_batch_depth);

    /* Normal text output still paints after the handoff. */
    memset(stored, 0, sizeof(stored));
    devfs_tty_console_write("text", 4);
    assert(!unlocked_stores && stored[0] == 4 && !stored[1] && painted == 4);
    assert(erases == 1 && !ttys[0].out_lock && !ttys[1].out_lock);
    assert(!g_tty_batch && !g_batch_depth);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="console-vt-handoff-", dir="/tmp/opencode") as tmp:
    source, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    source.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: printk and klog follow a VT handoff without painting graphics")
