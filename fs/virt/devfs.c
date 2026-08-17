#include <devfs.h>
#include <heap.h>
#include <fs.h>
#include <ramfs.h>
#include <vga.h>
#include <vbe.h>
#include <console.h>
#include <keyboard.h>
#include <thread.h>
#include <process.h>
#include <smp.h>
#include <string.h>
#include <stddef.h>
#include <spinlock.h>
#include <ext2.h>
#include <keyboard.h>
#include <disk.h>
#include <stat.h>
#include <usb.h>
#include <fbdev.h>
#include <cirrusfb.h>
#include <mouse.h>
#include <klog.h>
#include <pty.h>

#define DEVFS_TTY_COUNT 6


static struct devfs_tty dev_ttys[DEVFS_TTY_COUNT];
static int devfs_active = 0;
static int devfs_ready = 0;

static struct fs_driver devfs_driver;
static struct fs_driver_ops devfs_ops;
static void *devfs_driver_data = NULL;

/* forward declarations (used by devfs_unlink) */
static int devfs_open(const char *path, struct fs_file **out_file);
static void devfs_release(struct fs_file *file);

/* devfs is a virtual filesystem: device nodes are not removable from userspace.
   However we must implement unlink() so tools like BusyBox rm report EPERM
   instead of ENOENT (which happens when VFS falls through to other drivers). */
static int devfs_unlink(const char *path) {
    if (!path) return -3; /* ENOENT */
    /* If this path is a valid devfs node, deny removal (EPERM). */
    struct fs_file *f = NULL;
    if (devfs_open(path, &f) == 0 && f) {
        devfs_release(f);
        return -1; /* EPERM */
    }
    return -3; /* ENOENT */
}

static int devfs_chmod(const char *path, mode_t mode) {
    (void)mode;
    if (!path) return -1;
    struct fs_file *f = NULL;
    if (devfs_open(path, &f) == 0 && f) {
        devfs_release(f);
        return 0;
    }
    return -1;
}

static inline uint32_t devfs_tty_cols(void) {
    int c = console_max_cols();
    if (c <= 0) c = MAX_COLS;
    /* vmwgfx/VBE can report a very large character grid; uncapped cols*rows*2
     * makes devfs_register() kmalloc and clear loop effectively hang boot. */
    if (c > 512) c = 512;
    return (uint32_t)c;
}

static inline uint32_t devfs_tty_rows(void) {
    int r = console_max_rows();
    if (r <= 0) r = MAX_ROWS;
    if (r > 512) r = 512;
    return (uint32_t)r;
}

static inline size_t devfs_tty_screen_bytes(void) {
    return (size_t)devfs_tty_rows() * (size_t)devfs_tty_cols() * 2u;
}

static void devfs_tty_snapshot_visible(struct devfs_tty *tty) {
    if (!tty || !tty->screen) return;
    size_t scr_sz = devfs_tty_screen_bytes();
    if (cirrusfb_is_ready()) {
        cirrusfb_snapshot_screen(tty->screen, scr_sz);
        cirrusfb_get_cursor(&tty->cursor_x, &tty->cursor_y);
        return;
    }
    if (vbe_is_available()) {
        vbefb_snapshot_screen(tty->screen, scr_sz);
        vbefb_get_cursor(&tty->cursor_x, &tty->cursor_y);
        return;
    }
    const size_t vga_scr_sz = (size_t)MAX_COLS * (size_t)MAX_ROWS * 2u;
    size_t copy_sz = scr_sz < vga_scr_sz ? scr_sz : vga_scr_sz;
    memcpy(tty->screen, (uint8_t *)VIDEO_ADDRESS, copy_sz);
    uint16_t pos = get_cursor();
    uint32_t tty_cols = MAX_COLS;
    tty->cursor_x = (pos % (tty_cols * 2)) / 2;
    tty->cursor_y = pos / (tty_cols * 2);
}

/* Push tty backing store to the visible console (active VC only). */
static void devfs_tty_blit_to_console(struct devfs_tty *tty) {
    if (!tty || !tty->screen) return;
    if (cirrusfb_is_ready()) {
        cirrusfb_restore_screen(tty->screen, cirrusfb_cols(), cirrusfb_rows());
        cirrusfb_set_cursor(tty->cursor_x, tty->cursor_y);
        return;
    }
    if (vbe_is_available()) {
        vbefb_restore_screen(tty->screen, devfs_tty_cols(), devfs_tty_rows());
        vbefb_set_cursor(tty->cursor_x, tty->cursor_y);
        return;
    }
    size_t scr_sz = devfs_tty_screen_bytes();
    const size_t vga_scr_sz = (size_t)MAX_COLS * (size_t)MAX_ROWS * 2u;
    size_t copy_sz = scr_sz < vga_scr_sz ? scr_sz : vga_scr_sz;
    memcpy((uint8_t *)VIDEO_ADDRESS, tty->screen, copy_sz);
    console_set_cursor(tty->cursor_x, tty->cursor_y);
}

void devfs_tty_leave_alt_screen(int tty_idx) {
    if (tty_idx < 0 || tty_idx >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *tty = &dev_ttys[tty_idx];
    if (!tty->alt_active) return;
    size_t scr_sz = devfs_tty_screen_bytes();
    if (tty->alt_screen && tty->screen)
        memcpy(tty->screen, tty->alt_screen, scr_sz);
    if (tty->alt_screen) {
        kfree(tty->alt_screen);
        tty->alt_screen = NULL;
    }
    tty->alt_active = 0;
    tty->cursor_x = tty->saved_x;
    tty->cursor_y = tty->saved_y;
    tty->acs_mode = 0;
    tty->g0_is_acs = 0;
    tty->insert_mode = 0;
    tty->need_wrap = 0;
    tty->ansi_escape_state = 0;
    if (tty_idx == devfs_get_active())
        devfs_tty_blit_to_console(tty);
}

/* Fast clear for tty backing buffer: fill cells as packed VGA words. */
static inline void devfs_tty_clear_backing_fast(struct devfs_tty *tty, uint8_t attr) {
    if (!tty || !tty->screen) return;
    uint32_t cells = devfs_tty_rows() * devfs_tty_cols();
    uint16_t cell = (uint16_t)' ' | ((uint16_t)attr << 8);
    uint16_t *dst = (uint16_t*)tty->screen;
    for (uint32_t i = 0; i < cells; i++) {
        dst[i] = cell;
    }
}

static void devfs_tty_init_scroll(struct devfs_tty *tty) {
    uint32_t rows = devfs_tty_rows();
    if (rows == 0) rows = 1;
    tty->scroll_top = 0;
    tty->scroll_bottom = rows - 1;
}

static void devfs_tty_scroll_backing(struct devfs_tty *tty, uint32_t top, uint32_t bottom) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || top >= bottom)
        return;
    if (bottom >= rows) bottom = rows - 1;
    size_t row_bytes = (size_t)cols * 2u;
    memmove(tty->screen + (size_t)top * row_bytes,
            tty->screen + (size_t)(top + 1u) * row_bytes,
            (size_t)(bottom - top) * row_bytes);
    uint16_t blank = (uint16_t)' ' | ((uint16_t)tty->current_attr << 8);
    uint16_t *last = (uint16_t *)(tty->screen + (size_t)bottom * row_bytes);
    for (uint32_t x = 0; x < cols; x++)
        last[x] = blank;
}

static void devfs_tty_scroll_backing_down(struct devfs_tty *tty, uint32_t top,
                                          uint32_t bottom) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || top >= bottom)
        return;
    if (bottom >= rows)
        bottom = rows - 1;

    size_t row_bytes = (size_t)cols * 2;
    for (uint32_t y = bottom; y > top; y--) {
        memcpy(tty->screen + (size_t)y * row_bytes,
               tty->screen + (size_t)(y - 1) * row_bytes, row_bytes);
    }
    for (uint32_t x = 0; x < cols; x++) {
        size_t off = ((size_t)top * cols + x) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = tty->current_attr;
    }
}

static void devfs_tty_scroll_region_up(struct devfs_tty *tty, int tty_on_vga) {
    uint32_t top = tty->scroll_top;
    uint32_t bot = tty->scroll_bottom;
    devfs_tty_scroll_backing(tty, top, bot);
    if (tty_on_vga) {
        /*
         * Reading legacy VGA VRAM is extremely slow on virtual hardware.
         * The backing buffer already contains the scrolled result, so publish
         * it using wide write-only stores instead of VRAM read-modify-copy.
         */
        if (!cirrusfb_is_ready() && !vbe_is_available())
            vga_blit_cells(tty->screen, top, bot);
        else
            console_scroll_region_up(top, bot, tty->current_attr);
    }
}

static void devfs_tty_newline(struct devfs_tty *tty, int tty_on_vga) {
    uint32_t rows = devfs_tty_rows();
    if (rows == 0) return;
    uint32_t bot = tty->scroll_bottom;
    if (bot >= rows) bot = rows - 1;
    if (tty->cursor_y == bot) {
        devfs_tty_scroll_region_up(tty, tty_on_vga);
        tty->cursor_y = bot;
    } else if (tty->cursor_y + 1 < rows) {
        tty->cursor_y++;
    }
    tty->cursor_x = 0;
    tty->need_wrap = 0;
    if (tty_on_vga)
        console_set_cursor(tty->cursor_x, tty->cursor_y);
}

static void devfs_tty_store_xy(struct devfs_tty *tty, uint32_t x, uint32_t y, uint8_t ch) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0)
        return;
    if (y >= rows) y = rows - 1;
    if (x >= cols) x = cols - 1;
    size_t off = ((size_t)y * cols + x) * 2;
    tty->screen[off] = ch;
    tty->screen[off + 1] = tty->current_attr;
}

static void devfs_tty_store_at_cursor(struct devfs_tty *tty, uint8_t ch) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0)
        return;
    if (tty->cursor_y >= rows) tty->cursor_y = rows - 1;
    if (tty->cursor_x >= cols) tty->cursor_x = cols - 1;
    size_t off = ((size_t)tty->cursor_y * cols + tty->cursor_x) * 2;
    tty->screen[off] = ch;
    tty->screen[off + 1] = tty->current_attr;
}

static void devfs_tty_advance_cursor(struct devfs_tty *tty) {
    uint32_t cols = devfs_tty_cols();
    if (cols == 0)
        return;
    if (tty->cursor_x + 1 >= cols) {
        tty->cursor_x = cols - 1;
        tty->need_wrap = 1;
    } else {
        tty->cursor_x++;
        tty->need_wrap = 0;
    }
}

/* Erase tty backing from (from_x, y) through end of line (for non-visible VC). */
static void devfs_tty_buf_erase_eol(struct devfs_tty *tty, uint32_t from_x, uint32_t y, uint8_t attr) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows || from_x >= cols) return;
    for (uint32_t rx = from_x; rx < cols; rx++) {
        size_t off = ((size_t)y * cols + rx) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = attr;
    }
}

/* Push backing-store cells [x0..x1] on row y to the visible console. */
static void devfs_tty_blit_cells(struct devfs_tty *tty, uint32_t x0, uint32_t x1, uint32_t y) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows)
        return;
    if (x0 >= cols)
        return;
    if (x1 >= cols)
        x1 = cols - 1;
    if (x0 > x1)
        return;
    for (uint32_t x = x0; x <= x1; x++) {
        size_t off = ((size_t)y * cols + x) * 2;
        uint8_t ch = tty->screen[off];
        uint8_t attr = tty->screen[off + 1];
        if (cirrusfb_is_ready())
            cirrusfb_putch_xy(x, y, ch, attr);
        else
            console_putch_xy(x, y, ch, attr);
    }
}

/* Insert blank cells at (x0,y), shifting [x0..cols) right. Cursor stays put. */
static void devfs_tty_insert_cells(struct devfs_tty *tty, int tty_on_vga, uint32_t x0, uint32_t y,
                                   int n) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows || n <= 0)
        return;
    if (x0 >= cols)
        return;
    if ((uint32_t)n > cols - x0)
        n = (int)(cols - x0);
    for (int k = 0; k < n; k++) {
        for (uint32_t x = cols - 1; x > x0; x--) {
            size_t dst = ((size_t)y * cols + x) * 2;
            size_t src = ((size_t)y * cols + (x - 1)) * 2;
            tty->screen[dst] = tty->screen[src];
            tty->screen[dst + 1] = tty->screen[src + 1];
        }
        size_t off = ((size_t)y * cols + x0) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = tty->current_attr;
    }
    if (tty_on_vga)
        devfs_tty_blit_cells(tty, x0, cols - 1, y);
}

/* Delete n cells at (x0,y), shifting left; blanks fill the end of the line. */
static void devfs_tty_delete_cells(struct devfs_tty *tty, int tty_on_vga, uint32_t x0, uint32_t y,
                                   int n) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows || n <= 0)
        return;
    if (x0 >= cols)
        return;
    if ((uint32_t)n > cols - x0)
        n = (int)(cols - x0);
    for (uint32_t x = x0; x + (uint32_t)n < cols; x++) {
        size_t dst = ((size_t)y * cols + x) * 2;
        size_t src = ((size_t)y * cols + x + (uint32_t)n) * 2;
        tty->screen[dst] = tty->screen[src];
        tty->screen[dst + 1] = tty->screen[src + 1];
    }
    for (uint32_t x = cols - (uint32_t)n; x < cols; x++) {
        size_t off = ((size_t)y * cols + x) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = tty->current_attr;
    }
    if (tty_on_vga)
        devfs_tty_blit_cells(tty, x0, cols - 1, y);
}

/* Erase n cells from (x0,y) with spaces; cursor does not move (CSI X / ech). */
static void devfs_tty_erase_cells(struct devfs_tty *tty, int tty_on_vga, uint32_t x0, uint32_t y,
                                  int n) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows || n <= 0)
        return;
    if (x0 >= cols)
        return;
    if ((uint32_t)n > cols - x0)
        n = (int)(cols - x0);
    uint32_t x1 = x0 + (uint32_t)n - 1u;
    for (uint32_t x = x0; x <= x1; x++) {
        size_t off = ((size_t)y * cols + x) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = tty->current_attr;
    }
    if (tty_on_vga)
        console_clear_line_segment(x0, x1, y, tty->current_attr);
}

/* Minimal tty output into backing store only (no VGA), for non-active virtual consoles. */
static void devfs_tty_virtual_putc(struct devfs_tty *tty, uint8_t c) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0) return;

    if (c == '\n') {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        return;
    }
    if (c == '\r') {
        tty->cursor_x = 0;
        return;
    }
    /* Non-destructive BS/DEL — same as Linux console (cursor left only). */
    if (c == '\b' || c == 0x7F) {
        if (tty->cursor_x > 0)
            tty->cursor_x--;
        return;
    }
    if (c == '\t') {
        uint32_t n = 8u - (tty->cursor_x % 8u);
        if (n == 0) n = 8;
        for (uint32_t k = 0; k < n; k++) {
            devfs_tty_virtual_putc(tty, ' ');
        }
        return;
    }
    if (tty->cursor_y >= rows) tty->cursor_y = rows - 1;
    if (tty->cursor_x >= cols) {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        else tty->cursor_y = rows - 1;
    }
    size_t off = ((size_t)tty->cursor_y * cols + tty->cursor_x) * 2;
    tty->screen[off] = c;
    tty->screen[off + 1] = tty->current_attr;
    tty->cursor_x++;
    if (tty->cursor_x >= cols) {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        else tty->cursor_y = rows - 1;
    }
}

/* Active-VC putc through console abstraction.
   We sync driver cursor from tty->cursor_x/y before emitting, then pull it back,
   so the backend (VGA text vs framebuffer) can't get out of step. */
/* DEC special graphics (what ncurses uses for ACS): map G0 charset bytes to glyphs
   in our 8x16 font (indices 0x00-0x7F only). */
static uint8_t devfs_tty_acs_translate(uint8_t ch, int acs_on) {
    if (!acs_on)
        return ch;
    unsigned c = (unsigned)ch;
    if (c == 0x5fu)
        return (uint8_t)' ';
    if (c >= 0x60u && c <= 0x7eu) {
        static const uint8_t map[31] = {
            0x04, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0f, 0x0f,
            0x1b, 0x1a, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x18,
            0x1a, 0x16, 0x0e, 0x16, 0x16, 0x16, 0x16, 0x16,
            0x0e, 0x1a, 0x18, 0x7b, 0x7c, 0x7d, 0x7e,
        };
        return map[c - 0x60u];
    }
    return ch;
}

static void devfs_tty_emit_byte(struct devfs_tty *tty, int tty_on_vga, uint8_t ch);
static ssize_t devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset);
static ssize_t devfs_tty_write_stream(struct devfs_tty *tty, const char *s,
                                      size_t size, const char *path);

enum devfs_vt_state {
    DEVFS_VT_GROUND = 0,
    DEVFS_VT_ESCAPE,
    DEVFS_VT_CSI,
    DEVFS_VT_SS3,
    DEVFS_VT_G1_SELECT,
    DEVFS_VT_G0_SELECT,
    DEVFS_VT_OSC,
    DEVFS_VT_OSC_ESC,
    DEVFS_VT_STRING,
    DEVFS_VT_STRING_ESC,
};

static void devfs_tty_vt_reset(struct devfs_tty *tty) {
    tty->ansi_escape_state = DEVFS_VT_GROUND;
    tty->ansi_csi_private = 0;
    tty->ansi_param_count = 0;
    tty->ansi_current_param = 0;
}

void devfs_tty_console_write_locked(const char *s, size_t n) {
    if (!s || n == 0)
        return;
    struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
    if (!tty)
        return;

    /*
     * printk is not a userspace VT writer.  Render it without touching the
     * userspace escape state: otherwise a kernel byte can finish an ESC/CSI
     * left by an application, or leave one that consumes the next stdout byte.
     */
    uint8_t saved_acs = tty->acs_mode;
    uint8_t saved_insert = tty->insert_mode;
    tty->acs_mode = 0;
    tty->insert_mode = 0;
    console_begin_tty_batch();
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = (uint8_t)s[i];
        if (ch == '\b' || ch == '\t' || ch == '\n' || ch == '\r' ||
            ch == 0x0B || ch == 0x0C ||
            (ch >= 0x20 && ch != 0x7F))
            devfs_tty_emit_byte(tty, 1, ch);
    }
    console_set_cursor(tty->cursor_x, tty->cursor_y);
    console_end_tty_batch();
    tty->acs_mode = saved_acs;
    tty->insert_mode = saved_insert;
}

void devfs_tty_console_write(const char *s, size_t n) {
    if (!s || n == 0)
        return;
    struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
    if (!tty)
        return;
    unsigned long flags = 0;
    acquire_irqsave(&tty->out_lock, &flags);
    devfs_tty_console_write_locked(s, n);
    release_irqrestore(&tty->out_lock, flags);
}

static void devfs_tty_emit_byte(struct devfs_tty *tty, int tty_on_vga, uint8_t ch) {
    ch = devfs_tty_acs_translate(ch, tty->acs_mode);
    /*
     * Linux VT C0 handling: controls act on the terminal and are never
     * rendered as glyphs.  In particular readline writes BEL when completion
     * is ambiguous; painting byte 0x07 produced the spurious first-Tab mark.
     */
    if (ch == 0x00 || ch == 0x07 || ch == 0x7F)
        return;
    if (ch == '\n' || ch == 0x0B || ch == 0x0C) {
        devfs_tty_newline(tty, tty_on_vga);
        return;
    }
    if (ch == '\r') {
        tty->cursor_x = 0;
        tty->need_wrap = 0;
        return;
    }
    /*
     * BS (0x08): Linux VT moves the cursor left and does NOT erase.
     * Shells/nano use \b to walk left when editing; erasing here wiped the
     * tail of the line as the cursor moved (looked like "left arrow clears").
     * Destructive backspace is the app's job: "\b \b" or CSI sequences.
     */
    if (ch == '\b' || ch == 0x7F) {
        if (tty->cursor_x > 0 && !tty->need_wrap)
            tty->cursor_x--;
        tty->need_wrap = 0;
        return;
    }
    if (ch == '\t') {
        uint32_t cols = devfs_tty_cols();
        if (cols == 0)
            return;
        uint32_t next = (tty->cursor_x + 8u) & ~7u;
        tty->cursor_x = next < cols ? next : cols - 1;
        if (tty_on_vga)
            console_set_cursor(tty->cursor_x, tty->cursor_y);
        return;
    }
    if (tty->need_wrap) {
        tty->cursor_x = 0;
        devfs_tty_newline(tty, tty_on_vga);
    }
    /* IRM: shift line right before writing, like Linux vt / xterm. */
    if (tty->insert_mode)
        devfs_tty_insert_cells(tty, tty_on_vga, tty->cursor_x, tty->cursor_y, 1);
    devfs_tty_store_at_cursor(tty, ch);
    if (tty_on_vga) {
        if (cirrusfb_is_ready())
            cirrusfb_putch_xy(tty->cursor_x, tty->cursor_y, ch, tty->current_attr);
        else
            console_putch_xy(tty->cursor_x, tty->cursor_y, ch, tty->current_attr);
        devfs_tty_advance_cursor(tty);
        /* Keep fbcon SW cursor on the cell after the glyph (echo has no end_batch). */
        console_set_cursor(tty->cursor_x, tty->cursor_y);
    } else {
        devfs_tty_advance_cursor(tty);
    }
}

static void devfs_tty_echo_bytes(struct devfs_tty *tty, const uint8_t *bytes,
                                 size_t count) {
    if (!tty || !bytes || count == 0 || tty->id != devfs_get_active())
        return;
    if (!try_acquire(&tty->out_lock))
        return;

    console_begin_tty_batch();
    for (size_t i = 0; i < count; i++)
        devfs_tty_emit_byte(tty, 1, bytes[i]);
    console_set_cursor(tty->cursor_x, tty->cursor_y);
    console_end_tty_batch();
    release(&tty->out_lock);
}

/* simple block device node registry for /dev/hdN */
struct devfs_block {
    char path[32];
    int device_id;
    uint32_t start_lba;
    uint32_t sectors;
    spinlock_t io_lock; /* сериализация read/write для стабильности */
};
static struct devfs_block dev_blocks[64];
static int dev_block_count = 0;
/* character device nodes (e.g., /dev/fb0) */
struct devfs_char {
    char path[32];
    void *driver_private;
};
static struct devfs_char dev_chars[32];
static int dev_char_count = 0;
static uint32_t devfs_rand_state = 0x12345678;
/* special device names exposed under /dev */
static const char * const devfs_special_names[] = {
    "null", "zero", "random",
    "stdin", "stdout", "stderr",
    "tty",          /* controlling tty (alias to thread-attached tty) */
    "urandom",
    "full",
    "ptmx",         /* Unix98 PTY master multiplexor (node present; pty pair TBD) */
    "kmsg",         /* Linux MEM_MAJOR 1, minor 11 — OpenRC seed_dev / udev */
};
static const int devfs_special_count = sizeof(devfs_special_names) / sizeof(devfs_special_names[0]);

/* Linux-like virtual directories under /dev. Always listed; some start empty. */
static const char * const devfs_subdir_names[] = {
    "input", "pts", "shm", "fd", "net",
};
static const int devfs_subdir_count =
    (int)(sizeof(devfs_subdir_names) / sizeof(devfs_subdir_names[0]));

/* Directory handle kinds — readdir must key off this, not path strings
 * (BusyBox opens "/dev/pts/" with a trailing slash and used to fall through
 * into the /dev root listing → ls: /dev/pts/console: No such file...). */
enum {
    DEVFS_DIR_ROOT = 1,
    DEVFS_DIR_INPUT = 2,
    DEVFS_DIR_EMPTY = 3, /* shm / fd / net stubs: only . and .. */
    DEVFS_DIR_PTS = 4,   /* /dev/pts — allocated slave names */
};
typedef struct {
    int is_dir;
    int kind;
    int dir_count;
} devfs_dir_t;

/* entropy and RNG state */
static uint32_t devfs_entropy = 0;
static int devfs_random_waiters[16];
static int devfs_random_waiters_count = 0;

/* simple ring buffers for /dev/stdout and /dev/stderr to allow reading */
typedef struct {
    char *buf;
    size_t head;
    size_t tail;
    size_t cap;
    spinlock_t lock;
    int waiters[8];
    int waiters_count;
} stdio_ring_t;
static stdio_ring_t stdio_bufs[2]; /* 0 = stdout, 1 = stderr */

/* helper: get tty index from path like /dev/ttyN */
static int devfs_path_to_tty(const char *path) {
    if (!path) return -1;
    if (strcmp(path, "/dev/console") == 0) return 0;
    /* /dev/N -> ttyN (getty/inittab sometimes passes "1" = tty1 = first VC) */
    if (strncmp(path, "/dev/", 5) == 0 && path[5] >= '0' && path[5] <= '9' && path[6] == '\0') {
        int n = path[5] - '0';
        if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;  /* 1->0, 2->1, ... */
        if (n == 0) return 0;
    }
    /* /dev/vc/N -> ttyN (BusyBox CURRENT_VC = /dev/vc/0) */
    if (strncmp(path, "/dev/vc/", 8) == 0 && path[8] >= '0' && path[8] < '0' + DEVFS_TTY_COUNT && path[9] == '\0')
        return path[8] - '0';
    if (strncmp(path, "/dev/tty", 8) == 0) {
        /* /dev/ttyS0 -> map to tty0 (serial console alias) */
        if (path[8] == 'S' && path[9] >= '0' && path[9] <= '9' && path[10] == '\0') {
            int sn = path[9] - '0';
            if (sn >= 0 && sn < DEVFS_TTY_COUNT) return sn;
            return 0;
        }
        /* /dev/ttyN: Linux tty1 = first VC, tty2 = second VC. Our index 0 = first VC. */
        if (path[8] >= '0' && path[8] <= '9' && path[9] == '\0') {
            int n = path[8] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;  /* tty1->0, tty2->1, ... */
            if (n == 0) return 0;  /* tty0 = current = first at boot */
        }
    }
    return -1;
}

static struct fs_file *devfs_alloc_file(const char *path, int tty) {
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return NULL;
    memset(f, 0, sizeof(*f));
    size_t plen = strlen(path) + 1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) { kfree(f); return NULL; }
    memcpy(pp, path, plen);
    f->path = (const char*)pp;
    f->fs_private = &devfs_driver_data;
    f->driver_private = (void*)&dev_ttys[tty];
    f->type = FS_TYPE_REG;
    f->size = 0;
    f->pos = 0;
    f->refcount = 1;
    return f;
}

static int devfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    /* devfs does not support file creation */
    return -1;
}

static int devfs_open(const char *path, struct fs_file **out_file) {
    if (!path) return -1;
    /* directory /dev */
    if (strcmp(path, "/dev") == 0 || strcmp(path, "/dev/") == 0) {
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
        if (!f) return -1;
        memset(f, 0, sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        if (!pp) { kfree(f); return -1; }
        memcpy(pp, path, plen);
        f->path = (const char*)pp;
        devfs_dir_t *h = kmalloc(sizeof(*h));
        if (!h) { kfree((void*)f->path); kfree(f); return -1; }
        h->is_dir = 1;
        h->kind = DEVFS_DIR_ROOT;
        h->dir_count = 0;
        f->driver_private = (void*)h;
        f->type = FS_TYPE_DIR;
        f->size = 0;
        f->pos = 0;
        f->fs_private = &devfs_driver_data;
        f->refcount = 1;
        *out_file = f;
        return 0;
    }
    /* Linux-like virtual subdirs: /dev/{input,pts,shm,fd,net} */
    for (int di = 0; di < devfs_subdir_count; di++) {
        char dpath[40];
        snprintf(dpath, sizeof(dpath), "/dev/%s", devfs_subdir_names[di]);
        size_t dlen = strlen(dpath);
        if (strcmp(path, dpath) == 0 ||
            (strncmp(path, dpath, dlen) == 0 && path[dlen] == '/' && path[dlen + 1] == '\0')) {
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
            if (!f) return -1;
            memset(f, 0, sizeof(*f));
            size_t plen = strlen(dpath) + 1;
            char *pp = (char*)kmalloc(plen);
            if (!pp) { kfree(f); return -1; }
            memcpy(pp, dpath, plen);
            f->path = (const char*)pp;
            devfs_dir_t *h = kmalloc(sizeof(*h));
            if (!h) { kfree((void*)f->path); kfree(f); return -1; }
            h->is_dir = 1;
            if (strcmp(devfs_subdir_names[di], "input") == 0)
                h->kind = DEVFS_DIR_INPUT;
            else if (strcmp(devfs_subdir_names[di], "pts") == 0)
                h->kind = DEVFS_DIR_PTS;
            else
                h->kind = DEVFS_DIR_EMPTY;
            h->dir_count = (h->kind == DEVFS_DIR_INPUT) ? 1 : 0;
            f->driver_private = (void*)h;
            f->type = FS_TYPE_DIR;
            f->size = 0;
            f->pos = 0;
            f->fs_private = &devfs_driver_data;
            f->refcount = 1;
            *out_file = f;
            return 0;
        }
    }
    /* /dev/fd/N — Linux: open equals dup(N) of the calling process. */
    if (strncmp(path, "/dev/fd/", 8) == 0 && path[8] >= '0' && path[8] <= '9') {
        int n = 0;
        for (const char *p = path + 8; *p >= '0' && *p <= '9'; p++)
            n = n * 10 + (*p - '0');
        if (n < 0 || n >= THREAD_MAX_FD) return -1;
        thread_t *cur = thread_current();
        if (!cur) cur = thread_get_current_user();
        if (!cur) return -1;
        struct fs_file *src = (cur->process && n < PROCESS_MAX_FD)
            ? cur->process->fds[n] : cur->fds[n];
        if (!src) return -1;
        if (src->refcount <= 0) src->refcount = 1;
        else src->refcount++;
        *out_file = src;
        return 0;
    }
    /* block device? */
    int bi = devfs_find_block_by_path(path);
    if (bi >= 0) {
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
        if (!f) return -1;
        memset(f, 0, sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        if (!pp) { kfree(f); return -1; }
        memcpy(pp, path, plen);
        f->path = (const char*)pp;
        f->fs_private = &devfs_driver_data;
        f->driver_private = (void*)&dev_blocks[bi];
        f->type = FS_TYPE_REG;
        f->size = (off_t)dev_blocks[bi].sectors * 512;
        f->pos = 0;
        f->refcount = 1;
        *out_file = f;
        return 0;
    }
    /* character device nodes (registered via devfs_create_char_node) */
    for (int ci = 0; ci < dev_char_count; ci++) {
        if (strcmp(path, dev_chars[ci].path) == 0) {
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
            if (!f) return -1;
            memset(f, 0, sizeof(*f));
            size_t plen = strlen(path) + 1;
            char *pp = (char*)kmalloc(plen);
            if (!pp) { kfree(f); return -1; }
            memcpy(pp, path, plen);
            f->path = (const char*)pp;
            f->fs_private = &devfs_driver_data;
            f->driver_private = dev_chars[ci].driver_private;
            f->type = FS_TYPE_REG;
            f->size = (strcmp(path, "/dev/fb0") == 0) ? (size_t)fbdev_byte_len() : 0;
            f->pos = 0;
            f->refcount = 1;
            *out_file = f;
            return 0;
        }
    }
    /* special device nodes like /dev/null, /dev/zero, /dev/random, /dev/stdin/out/err */
    for (int si = 0; si < devfs_special_count; si++) {
        char spath[32];
        snprintf(spath, sizeof(spath), "/dev/%s", devfs_special_names[si]);
        if (strcmp(path, spath) == 0) {
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
            if (!f) return -1;
            memset(f, 0, sizeof(*f));
            size_t plen = strlen(path) + 1;
            char *pp = (char*)kmalloc(plen);
            if (!pp) { kfree(f); return -1; }
            memcpy(pp, path, plen);
            f->path = (const char*)pp;
            f->fs_private = &devfs_driver_data;
            /*
             * Linux: /dev/tty and /dev/std{in,out,err} are the controlling tty.
             * Bind at open so TIOCSPGRP/TIOCGPGRP update real tty->fg_pgrp —
             * a deferred int marker left fg_pgrp stale (^C only hit the shell).
             */
            if (si == 3 || si == 4 || si == 5 || si == 6) {
                thread_t *cur = thread_current();
                if (!cur) cur = thread_get_current_user();
                int tty_idx = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                if (tty_idx < 0 || tty_idx >= DEVFS_TTY_COUNT) tty_idx = 0;
                f->driver_private = (void*)&dev_ttys[tty_idx];
            } else {
                int *ptype = (int*)kmalloc(sizeof(int));
                if (!ptype) { kfree((void*)f->path); kfree(f); return -1; }
                *ptype = 0x80000000 | si;
                f->driver_private = (void*)ptype;
            }
            f->type = FS_TYPE_REG;
            f->size = 0;
            f->refcount = 1;
            /* /dev/ptmx — real Unix98 master (si==9). */
            if (si == 9) {
                kfree(f->driver_private);
                kfree((void *)f->path);
                kfree(f);
                return pty_open_ptmx(out_file);
            }
            *out_file = f;
            return 0;
        }
    }
    /* /dev/pts/N — Unix98 slave */
    if (strncmp(path, "/dev/pts/", 9) == 0 && path[9] >= '0' && path[9] <= '9') {
        int n = 0;
        for (const char *p = path + 9; *p >= '0' && *p <= '9'; p++)
            n = n * 10 + (*p - '0');
        return pty_open_slave(n, out_file);
    }
    int tty = devfs_path_to_tty(path);
    if (tty < 0) return -1;
    struct fs_file *f = devfs_alloc_file(path, tty);
    if (!f) return -1;
    *out_file = f;
    return 0;
}

struct fs_file *devfs_open_direct(const char *path) {
    struct fs_file *f = NULL;
    if (devfs_open(path, &f) == 0) return f;
    return NULL;
}

static ssize_t devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (pty_is_file(file)) {
        (void)offset;
        return pty_read(file, buf, size);
    }
    if (!file || !buf) return -1;
    if (file->path && strcmp(file->path, "/dev/input/mice") == 0) {
        (void)offset;
        return mouse_read_stream(buf, size);
    }
    if (usb_is_devfs_file(file)) return usb_devfs_read(file, buf, size, offset);
    if (file->path && strcmp(file->path, "/dev/fb0") == 0) {
        if (!fbdev_is_active()) return -1;
        size_t flen = fbdev_byte_len();
        if (offset >= flen) return 0;
        if (offset + size > flen) size = flen - offset;
        fbdev_copy_to(buf, offset, size);
        return (ssize_t)size;
    }
    /* block device file handling: батч-чтение по 64 KB для стабильности при множестве операций */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            unsigned long flags = 0;
            acquire_irqsave(&b->io_lock, &flags);
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) { release_irqrestore(&b->io_lock, flags); return 0; }
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t nsectors = (uint32_t)((offset + size + 511) / 512) - start_sector;
            size_t off_in_first = offset % 512;
            size_t copied = 0;
#define DEVFS_BLOCK_CHUNK_SECTORS 128
#define DEVFS_BLOCK_CHUNK_BYTES   (DEVFS_BLOCK_CHUNK_SECTORS * 512)
            void *chunk = kmalloc(DEVFS_BLOCK_CHUNK_BYTES);
            if (!chunk) { release_irqrestore(&b->io_lock, flags); return -1; }
            uint32_t s = 0;
            while (s < nsectors) {
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    kfree(chunk);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint32_t chunk_sectors = nsectors - s;
                if (chunk_sectors > DEVFS_BLOCK_CHUNK_SECTORS) chunk_sectors = DEVFS_BLOCK_CHUNK_SECTORS;
                memset(chunk, 0, (size_t)chunk_sectors * 512);
                if (disk_read_sectors(b->device_id, b->start_lba + start_sector + s, chunk, chunk_sectors) != 0) {
                    kfree(chunk);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint8_t *src = (uint8_t*)chunk;
                for (uint32_t i = 0; i < chunk_sectors && copied < size; i++) {
                    size_t src_off = (s == 0 && i == 0) ? off_in_first : 0;
                    size_t seg = (size_t)(512 - (uint32_t)src_off);
                    if (seg > size - copied) seg = size - copied;
                    memcpy((uint8_t*)buf + copied, src + (size_t)(i * 512) + src_off, seg);
                    copied += seg;
                }
                s += chunk_sectors;
                if (s < nsectors) thread_yield();
            }
            kfree(chunk);
            release_irqrestore(&b->io_lock, flags);
            return (ssize_t)copied;
        }
    }
    /* special devices via driver_private marker */
    if (file->driver_private) {
        int marker = *(int*)file->driver_private;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            switch (si) {
                case 0: return 0; /* /dev/null */
                case 1: memset(buf, 0, size); return (ssize_t)size; /* /dev/zero */
                case 2: { /* /dev/random: non-blocking like /dev/urandom (always generate) */
                    uint8_t *p = (uint8_t*)buf;
                    for (size_t i = 0; i < size; i++) {
                        devfs_rand_state ^= devfs_rand_state << 13;
                        devfs_rand_state ^= devfs_rand_state >> 17;
                        devfs_rand_state ^= devfs_rand_state << 5;
                        p[i] = (uint8_t)(devfs_rand_state & 0xFF);
                    }
                    return (ssize_t)size;
                }
                case 3: { /* /dev/stdin -> map to console tty */
                    /* Map /dev/stdin to the tty attached to current thread if present,
                       otherwise to the active console. */
                    thread_t *cur = thread_current();
                    int tty_idx = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                    struct devfs_tty *tstdin = &dev_ttys[tty_idx];
                    file->driver_private = (void*)tstdin;
                    break;
                }
                case 6: { /* /dev/tty -> map to controlling tty (same logic as stdin) */
                    thread_t *cur = thread_current();
                    int tty_idx = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                    struct devfs_tty *tstdin = &dev_ttys[tty_idx];
                    file->driver_private = (void*)tstdin;
                    break;
                }
                case 7: { /* /dev/urandom - non-blocking random */
                    uint8_t *p = (uint8_t*)buf;
                    for (size_t i=0;i<size;i++) {
                        devfs_rand_state ^= devfs_rand_state << 13;
                        devfs_rand_state ^= devfs_rand_state >> 17;
                        devfs_rand_state ^= devfs_rand_state << 5;
                        p[i] = (uint8_t)(devfs_rand_state & 0xFF);
                    }
                    return (ssize_t)size;
                }
                case 8: /* /dev/full reads identically to /dev/zero */
                    memset(buf, 0, size);
                    return (ssize_t)size;
                case 10: { /* /dev/kmsg — printk ring (byte offset) */
                    long n = klog_ring_read((char *)buf, size, offset);
                    return (ssize_t)n;
                }
                default: break;
            }
        }
    }
    /* Support reading from /dev/stdout and /dev/stderr ring buffers */
    if (file->path) {
        if (strcmp(file->path, "/dev/stdout") == 0 || strcmp(file->path, "/dev/stderr") == 0) {
            int which = (strcmp(file->path, "/dev/stdout") == 0) ? 0 : 1;
            stdio_ring_t *rb = &stdio_bufs[which];
            size_t got = 0;
            char *outp = (char*)buf;
            for (;;) {
                unsigned long flags = 0;
                acquire_irqsave(&rb->lock, &flags);
                if (rb->head != rb->tail) {
                    outp[got++] = rb->buf[rb->head];
                    rb->head = (rb->head + 1) % rb->cap;
                    /* wake writers not needed */
                    release_irqrestore(&rb->lock, flags);
                    if (got >= size) break;
                    continue;
                }
                /* empty: block current thread until data written */
                thread_t *cur = thread_current();
                if (cur && cur->tid != 0) {
                    if (rb->waiters_count < (int)(sizeof(rb->waiters)/sizeof(rb->waiters[0]))) {
                        rb->waiters[rb->waiters_count++] = (int)cur->tid;
                    }
                    release_irqrestore(&rb->lock, flags);
                    thread_block((int)cur->tid);
                    thread_yield();
                    if (cur->pending_signals & ~cur->saved_sig_mask)
                        return got > 0 ? (ssize_t)got : (ssize_t)-4;
                    continue;
                } else {
                    release_irqrestore(&rb->lock, flags);
                    break;
                }
            }
            return (ssize_t)got;
        }
    }
    /* directory read */
    if (file->type == FS_TYPE_DIR && file->driver_private) {
        devfs_dir_t *dh = (devfs_dir_t *)file->driver_private;
        if (!dh->is_dir)
            return -1;

        if (dh->kind == DEVFS_DIR_INPUT) {
            uint8_t *out = (uint8_t*)buf;
            size_t pos = 0;
            size_t written = 0;
            static const char *const names[] = { ".", "..", "mice" };
            for (int i = 0; i < 3; i++) {
                const char *nm = names[i];
                size_t namelen = strlen(nm);
                size_t rec_len = 8 + namelen;
                rec_len = (rec_len + 3) & ~3u;
                if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
                if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
                if (written >= size) break;
                uint8_t tmp[64];
                memset(tmp, 0, sizeof(tmp));
                struct ext2_dir_entry de;
                memset(&de, 0, sizeof(de));
                de.inode = (uint32_t)(100 + i);
                de.rec_len = (uint16_t)rec_len;
                de.name_len = (uint8_t)namelen;
                de.file_type = (i < 2) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
                memcpy(tmp, &de, 8);
                memcpy(tmp + 8, nm, namelen);
                size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
                size_t avail = size - written;
                size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                if (tocopy > avail) tocopy = avail;
                memcpy(out + written, tmp + entry_off, tocopy);
                written += tocopy;
                pos += rec_len;
            }
            return (ssize_t)written;
        }

        if (dh->kind == DEVFS_DIR_EMPTY || dh->kind == DEVFS_DIR_PTS) {
            uint8_t *out = (uint8_t*)buf;
            size_t pos = 0;
            size_t written = 0;
            char slave_names[PTY_MAX][16];
            int nslaves = 0;
            int total;
            if (dh->kind == DEVFS_DIR_PTS)
                nslaves = pty_list_slaves(slave_names, PTY_MAX);
            total = 2 + nslaves;
            for (int i = 0; i < total; i++) {
                const char *nm = (i == 0) ? "." : (i == 1) ? ".." : slave_names[i - 2];
                size_t namelen = strlen(nm);
                size_t rec_len = 8 + namelen;
                rec_len = (rec_len + 3) & ~3u;
                if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
                if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
                if (written >= size) break;
                uint8_t tmp[64];
                memset(tmp, 0, sizeof(tmp));
                struct ext2_dir_entry de;
                memset(&de, 0, sizeof(de));
                de.inode = (uint32_t)(200 + i);
                de.rec_len = (uint16_t)rec_len;
                de.name_len = (uint8_t)namelen;
                de.file_type = (i < 2) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
                memcpy(tmp, &de, 8);
                memcpy(tmp + 8, nm, namelen);
                size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
                size_t avail = size - written;
                size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                if (tocopy > avail) tocopy = avail;
                memcpy(out + written, tmp + entry_off, tocopy);
                written += tocopy;
                pos += rec_len;
            }
            return (ssize_t)written;
        }

        if (dh->kind != DEVFS_DIR_ROOT)
            return -1;

        /* /dev root: unique top-level names (no nested paths, no duplicate dirs). */
        {
            char names[96][32];
            uint8_t is_dir[96];
            int nnames = 0;
#define DEVFS_ADD_NAME(nm, dirflag) do { \
                if (nnames >= 96) break; \
                int _dup = 0; \
                for (int _j = 0; _j < nnames; _j++) \
                    if (strcmp(names[_j], (nm)) == 0) { _dup = 1; break; } \
                if (_dup) break; \
                size_t _l = strlen(nm); \
                if (_l >= sizeof(names[0])) _l = sizeof(names[0]) - 1; \
                memcpy(names[nnames], (nm), _l); \
                names[nnames][_l] = '\0'; \
                is_dir[nnames] = (uint8_t)(dirflag); \
                nnames++; \
            } while (0)

            DEVFS_ADD_NAME(".", 1);
            DEVFS_ADD_NAME("..", 1);
            DEVFS_ADD_NAME("console", 0);
            for (int t = 1; t <= DEVFS_TTY_COUNT; t++) {
                char tn[8];
                tn[0] = 't'; tn[1] = 't'; tn[2] = 'y';
                tn[3] = (char)('0' + t); tn[4] = '\0';
                DEVFS_ADD_NAME(tn, 0);
            }
            for (int si = 0; si < devfs_special_count; si++)
                DEVFS_ADD_NAME(devfs_special_names[si], 0);
            for (int di = 0; di < devfs_subdir_count; di++)
                DEVFS_ADD_NAME(devfs_subdir_names[di], 1);
            for (int bi = 0; bi < dev_block_count; bi++) {
                const char *path = dev_blocks[bi].path;
                if (strncmp(path, "/dev/", 5) != 0) continue;
                const char *rest = path + 5;
                if (strchr(rest, '/')) continue;
                DEVFS_ADD_NAME(rest, 0);
            }
            for (int ci = 0; ci < dev_char_count; ci++) {
                const char *path = dev_chars[ci].path;
                if (strncmp(path, "/dev/", 5) != 0) continue;
                const char *rest = path + 5;
                if (strchr(rest, '/')) continue;
                DEVFS_ADD_NAME(rest, 0);
            }
#undef DEVFS_ADD_NAME

            uint8_t *out = (uint8_t*)buf;
            size_t pos = 0;
            size_t written = 0;
            for (int i = 0; i < nnames; i++) {
                const char *nm = names[i];
                size_t namelen = strlen(nm);
                size_t rec_len = 8 + namelen;
                rec_len = (rec_len + 3) & ~3u;
                if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
                if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
                if (written >= size) break;
                uint8_t tmp[64];
                if (rec_len > sizeof(tmp)) { pos += rec_len; continue; }
                memset(tmp, 0, rec_len);
                struct ext2_dir_entry de;
                memset(&de, 0, sizeof(de));
                de.inode = (uint32_t)(i + 1);
                de.rec_len = (uint16_t)rec_len;
                de.name_len = (uint8_t)namelen;
                de.file_type = is_dir[i] ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
                memcpy(tmp, &de, 8);
                memcpy(tmp + 8, nm, namelen);
                size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
                size_t avail = size - written;
                size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                if (tocopy > avail) tocopy = avail;
                memcpy(out + written, tmp + entry_off, tocopy);
                written += tocopy;
                pos += rec_len;
            }
            return (ssize_t)written;
        }
    }
    /* regular device read (tty) */
    struct devfs_tty *t = (struct devfs_tty*)file->driver_private;
    if (!t) return -1;
    size_t got = 0;
    char *out = (char*)buf;
    while (got < size) {
        unsigned long flags = 0;
        acquire_irqsave(&t->in_lock, &flags);
        int is_canonical = (t->term_lflag & 0x00000002u) ? 1 : 0; /* ICANON bit (kernel mapping) */
        uint8_t vtime = t->term_vtime;
        if (t->in_count > 0) {
            /* pop one */
            /* Decide mode: canonical vs non-canonical */
            if (is_canonical) {
                /* canonical: deliver one char, stop on newline */
                char c = t->inbuf[t->in_head];
                t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
                t->in_count--;
                release_irqrestore(&t->in_lock, flags);
                if (c == '\r') c = '\n';
                out[got++] = c;
                if (c == '\n') break;
                continue;
            } else {
                /* non-canonical: deliver ONE byte per lock hold so ISR never drops keypresses.
                 * (Holding lock for N bytes caused next N keypresses to be dropped.) */
                char c = t->inbuf[t->in_head];
                t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
                t->in_count--;
                release_irqrestore(&t->in_lock, flags);
                out[got++] = c;
                if (got > 0) break;
                continue;
            }
        }
        /* no data: block current thread until pushed */
        thread_t* cur = thread_current();
        if (cur) {
            if (!is_canonical && t->term_vmin == 0 && vtime == 0) {
                release_irqrestore(&t->in_lock, flags);
                return (ssize_t)got;
            }
            /* If current is main kernel thread (tid 0), fall back to direct blocking kgetc */
            if (cur->tid == 0) {
                release_irqrestore(&t->in_lock, flags);
                char c = kgetc();
                if (c == '\r') c = '\n';
                /* deliver character (including backspace) to userspace and do not echo here */
                out[got++] = c;
                if (c == '\n') break;
                continue;
            }
            /* add to waiters if not already */
            int tid = (int)cur->tid;
            int already = 0;
            for (int i = 0; i < t->waiters_count; i++) if (t->waiters[i] == tid) { already = 1; break; }
            if (!already && t->waiters_count < (int)(sizeof(t->waiters)/sizeof(t->waiters[0]))) {
                t->waiters[t->waiters_count++] = tid;
            }
            release_irqrestore(&t->in_lock, flags);
            if (tid == thread_get_init_user_tid())
                kprintf("pid1: waiting for tty input\n");
            if (!is_canonical && vtime > 0 && got == 0)
                thread_block_with_timeout((int)cur->tid, (uint32_t)vtime * 100u);
            else
                thread_block((int)cur->tid);
            thread_yield();
            /* Woke: if still no data but have pending SIGINT (Ctrl+C), return EINTR
               so read() returns and maybe_deliver_pending_signal can terminate the process. */
            acquire_irqsave(&t->in_lock, &flags);
            if (t->in_count == 0) {
                thread_t *me = thread_current();
                if (me && (me->pending_signals & ~me->saved_sig_mask)) {
                    release_irqrestore(&t->in_lock, flags);
                    return got > 0 ? (ssize_t)got : (ssize_t)-4; /* -EINTR */
                }
                if (!is_canonical && vtime > 0) {
                    release_irqrestore(&t->in_lock, flags);
                    return (ssize_t)got;
                }
            }
            release_irqrestore(&t->in_lock, flags);
            /* when unblocked with data, loop to try again */
            continue;
        } else {
            release_irqrestore(&t->in_lock, flags);
            return (ssize_t)got;
        }
    }
    return (ssize_t)got;
}

static ssize_t devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (pty_is_file(file)) {
        (void)offset;
        return pty_write(file, buf, size);
    }
    if (!file || !buf) return -1;
    if (file->path && strcmp(file->path, "/dev/input/mice") == 0) {
        (void)offset;
        return (ssize_t)size;
    }
    if (usb_is_devfs_file(file)) return usb_devfs_write(file, buf, size, offset);
    if (file->path && strcmp(file->path, "/dev/fb0") == 0) {
        if (!fbdev_is_active()) return -1;
        size_t flen = fbdev_byte_len();
        if (offset >= flen) return -1;
        if (offset + size > flen) size = flen - offset;
        fbdev_copy_from(offset, buf, size);
        return (ssize_t)size;
    }
    /* special devices via driver_private marker: handle /dev/null, /dev/zero, /dev/random writes */
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        if (!(dp >= (uintptr_t)&dev_ttys[0] && dp < (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT])) {
            /* likely a marker pointer */
            int marker = *(int*)file->driver_private;
            if ((marker & 0x80000000) == 0x80000000) {
                int si = marker & 0x7FFFFFFF;
                switch (si) {
                    case 0: /* /dev/null */ return (ssize_t)size;
                    case 1: /* /dev/zero */ return (ssize_t)size;
                    case 2: /* /dev/random - mix written bytes into RNG state and accept */
                    {
                        const uint8_t *p = (const uint8_t*)buf;
                        for (size_t i = 0; i < size; i++) {
                            devfs_rand_state ^= (uint32_t)p[i];
                            devfs_rand_state = (devfs_rand_state << 5) | (devfs_rand_state >> 27);
                        }
                        /* increase entropy estimate and wake any random waiters */
                        devfs_entropy += (uint32_t)size;
                        if (devfs_random_waiters_count > 0) {
                            for (int wi = 0; wi < devfs_random_waiters_count; wi++) {
                                int tid = devfs_random_waiters[wi];
                                if (tid >= 0) thread_unblock(tid);
                            }
                            devfs_random_waiters_count = 0;
                        }
                        return (ssize_t)size;
                    }
                    case 8: /* /dev/full: Linux returns ENOSPC for every write */
                        return -28;
                    case 10: /* /dev/kmsg — userspace printk inject */
                        klog_user_write((const char *)buf, size);
                        return (ssize_t)size;
                    default: break;
                }
            }
        }
    }
    /* block device write: чанками по 64 KB, чтобы не исчерпывать кучу и не зависать */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            unsigned long flags = 0;
            acquire_irqsave(&b->io_lock, &flags);
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) { release_irqrestore(&b->io_lock, flags); return -1; }
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t nsectors = (uint32_t)((offset + size + 511) / 512) - start_sector;
            size_t off_in_first = offset % 512;
#define DEVFS_WRITE_CHUNK_SECTORS 128
#define DEVFS_WRITE_CHUNK_BYTES   (DEVFS_WRITE_CHUNK_SECTORS * 512)
            void *tmp = kmalloc(DEVFS_WRITE_CHUNK_BYTES);
            if (!tmp) { release_irqrestore(&b->io_lock, flags); return -1; }
            size_t written = 0;
            uint32_t cur_sector = 0;
            while (cur_sector < nsectors) {
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint32_t chunk_sectors = nsectors - cur_sector;
                if (chunk_sectors > DEVFS_WRITE_CHUNK_SECTORS) chunk_sectors = DEVFS_WRITE_CHUNK_SECTORS;
                if (disk_read_sectors(b->device_id, b->start_lba + start_sector + cur_sector, tmp, chunk_sectors) != 0) {
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                size_t merge_off = (cur_sector == 0) ? off_in_first : 0;
                size_t merge_max = (size_t)chunk_sectors * 512 - merge_off;
                size_t merge_len = size - written;
                if (merge_len > merge_max) merge_len = merge_max;
                memcpy((uint8_t*)tmp + merge_off, (const uint8_t*)buf + written, merge_len);
                written += merge_len;
                if (disk_write_sectors(b->device_id, b->start_lba + start_sector + cur_sector, tmp, chunk_sectors) != 0) {
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                cur_sector += chunk_sectors;
                if (cur_sector < nsectors) thread_yield();
            }
            kfree(tmp);
            release_irqrestore(&b->io_lock, flags);
            return (ssize_t)size;
        }
    }
    /* Resolve driver_private: it may be either a pointer into dev_ttys (tty handle)
       or a pointer to an allocated int marker for special devices (/dev/null, /dev/stdout, etc). */
    void *dp = file->driver_private;
    if (!dp) return -1;
    struct devfs_tty *t = NULL;
    uintptr_t p = (uintptr_t)dp;
    if (p >= (uintptr_t)&dev_ttys[0] && p < (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT]) {
        /* already a tty pointer */
        t = (struct devfs_tty*)dp;
    } else {
        /* assume marker pointer (allocated int) */
        int marker = *(int*)dp;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            if (si == 4 || si == 5) { /* stdout or stderr */
                thread_t *cur = thread_current();
                int tty = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                t = &dev_ttys[tty];
                /* update file handle to point directly to tty to avoid repeated marker derefs */
                file->driver_private = (void*)t;
            } else if (si == 3 || si == 6) {
                /* /dev/stdin used for writing — map to console tty */
                thread_t *cur = thread_current();
                int tty = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                t = &dev_ttys[tty];
                file->driver_private = (void*)t;
            } else {
                /* other special devices are not writable here */
                return -1;
            }
        } else {
            return -1;
        }
    }
    if (!t) return -1;
    return devfs_tty_write_stream(t, (const char *)buf, size, file->path);
}

static ssize_t devfs_tty_write_stream(struct devfs_tty *t, const char *s,
                                      size_t size, const char *path) {
    if (!t || !s) return -1;
    int idx = t->id;
    const int tty_on_vga_batch = (idx == devfs_active);
    unsigned long out_flags = 0;
    acquire_irqsave(&t->out_lock, &out_flags);
    if (tty_on_vga_batch)
        console_begin_tty_batch();
    for (size_t i = 0; i < size; i++) {
        char ch = s[i];
        {
            const int tty_on_vga = tty_on_vga_batch;
            /* Parse ANSI for every VC; drive VGA only when this tty is visible. */
            struct devfs_tty *tty = t;
            unsigned char uc = (unsigned char)ch;

            /* CAN/SUB cancel any ECMA-48 control sequence. */
            if (uc == 0x18 || uc == 0x1A) {
                devfs_tty_vt_reset(tty);
                continue;
            }

            /* OSC and DCS/SOS/PM/APC strings end only at BEL or ST (ESC \). */
            if (uc == 0x07) {
                if (tty->ansi_escape_state == DEVFS_VT_OSC ||
                    tty->ansi_escape_state == DEVFS_VT_OSC_ESC)
                    devfs_tty_vt_reset(tty);
                continue;
            }
            if (tty->ansi_escape_state == DEVFS_VT_OSC) {
                if (uc == 0x1B)
                    tty->ansi_escape_state = DEVFS_VT_OSC_ESC;
                continue;
            }
            if (tty->ansi_escape_state == DEVFS_VT_OSC_ESC) {
                if (ch == '\\')
                    devfs_tty_vt_reset(tty);
                else if (uc != 0x1B)
                    tty->ansi_escape_state = DEVFS_VT_OSC;
                continue;
            }
            if (tty->ansi_escape_state == DEVFS_VT_STRING) {
                if (uc == 0x1B)
                    tty->ansi_escape_state = DEVFS_VT_STRING_ESC;
                continue;
            }
            if (tty->ansi_escape_state == DEVFS_VT_STRING_ESC) {
                if (ch == '\\')
                    devfs_tty_vt_reset(tty);
                else if (uc != 0x1B)
                    tty->ansi_escape_state = DEVFS_VT_STRING;
                continue;
            }

            /* ESC restarts parsing even in an incomplete CSI. */
            if (uc == 0x1B) {
                tty->ansi_escape_state = DEVFS_VT_ESCAPE;
                continue;
            }

            /*
             * Linux VT executes ordinary C0 controls without turning them into
             * glyphs.  State survives write boundaries, but a complete write
             * is serialized by out_lock so another writer cannot splice bytes.
             */
            if (uc == 0x00 || uc == 0x7F)
                continue;
            if (uc == '\b' || uc == '\t' || uc == '\n' || uc == '\r' ||
                uc == 0x0B || uc == 0x0C) {
                devfs_tty_emit_byte(tty, tty_on_vga, uc);
                continue;
            }
            if (uc == 0x0E) {
                tty->acs_mode = tty->g0_is_acs ? 1 : 0;
                continue;
            }
            if (uc == 0x0F) {
                tty->acs_mode = 0;
                continue;
            }
            if (uc < 0x20)
                continue;

            if (tty->ansi_escape_state == DEVFS_VT_GROUND) {
                devfs_tty_emit_byte(tty, tty_on_vga, (uint8_t)ch);
            } else if (tty->ansi_escape_state == DEVFS_VT_ESCAPE) {
                if (ch == '[') {
                    tty->ansi_escape_state = DEVFS_VT_CSI;
                    tty->ansi_csi_private = 0;
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                } else if (ch == 'O') {
                    tty->ansi_escape_state = DEVFS_VT_SS3;
                } else if (ch == ')') {
                    tty->ansi_escape_state = DEVFS_VT_G1_SELECT;
                } else if (ch == '(') {
                    tty->ansi_escape_state = DEVFS_VT_G0_SELECT;
                } else if (ch == ']') {
                    tty->ansi_escape_state = DEVFS_VT_OSC;
                } else if (ch == 'P' || ch == 'X' || ch == '^' || ch == '_') {
                    tty->ansi_escape_state = DEVFS_VT_STRING;
                } else if (ch == 'c') {
                    /* RIS: reset the virtual console to its initial state. */
                    tty->current_attr = GRAY_ON_BLACK;
                    tty->ansi_bold = 0;
                    tty->attr_reverse = 0;
                    tty->g0_is_acs = 0;
                    tty->acs_mode = 0;
                    tty->insert_mode = 0;
                    tty->ansi_csi_private = 0;
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                    devfs_tty_init_scroll(tty);
                    devfs_tty_clear_backing_fast(tty, tty->current_attr);
                    tty->cursor_x = 0;
                    tty->cursor_y = 0;
                    tty->need_wrap = 0;
                    devfs_tty_vt_reset(tty);
                    if (tty_on_vga) {
                        console_clear_screen_attr(tty->current_attr);
                        console_set_cursor(0, 0);
                    }
                } else {
                    /* A syntactically complete but unsupported ESC function. */
                    devfs_tty_vt_reset(tty);
                }
            } else if (tty->ansi_escape_state == DEVFS_VT_G1_SELECT) {
                if (ch == '0')
                    tty->g0_is_acs = 1;
                else if (ch == 'B')
                    tty->g0_is_acs = 0;
                devfs_tty_vt_reset(tty);
            } else if (tty->ansi_escape_state == DEVFS_VT_G0_SELECT) {
                /* G0 select via ESC ( X : treat 0 as ACS table, B as ASCII */
                if (ch == '0')
                    tty->g0_is_acs = 1;
                else if (ch == 'B')
                    tty->g0_is_acs = 0;
                devfs_tty_vt_reset(tty);
            } else if (tty->ansi_escape_state == DEVFS_VT_SS3) {
                /* SS3: single final byte (e.g. A=up, B=down, C=right, D=left) */
                unsigned char fc = (unsigned char)ch;
                if (fc == 'A') {
                    if (tty->cursor_y > 0) tty->cursor_y--;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'B') {
                    uint32_t tty_rows = devfs_tty_rows();
                    if (tty->cursor_y + 1 < tty_rows) tty->cursor_y++;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'C') {
                    uint32_t tty_cols = devfs_tty_cols();
                    if (tty->cursor_x + 1 < tty_cols) tty->cursor_x++;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'D') {
                    if (tty->cursor_x > 0) tty->cursor_x--;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                }
                tty->need_wrap = 0;
                devfs_tty_vt_reset(tty);
            } else if (tty->ansi_escape_state == DEVFS_VT_CSI) {
                /* ECMA-48 CSI: parameters 30-3f, intermediates 20-2f, final 40-7e. */
                if (ch >= '0' && ch <= '9') {
                    if (tty->ansi_current_param < 100000)
                        tty->ansi_current_param =
                            tty->ansi_current_param * 10 + (ch - '0');
                } else if (uc >= 0x3C && uc <= 0x3F) {
                    tty->ansi_csi_private = 1;
                } else if (ch == ';') {
                    if (tty->ansi_param_count < (int)(sizeof(tty->ansi_param)/sizeof(tty->ansi_param[0]))) {
                        tty->ansi_param[tty->ansi_param_count++] = tty->ansi_current_param;
                    }
                    tty->ansi_current_param = 0;
                } else if (ch == ':' || (uc >= 0x20 && uc <= 0x2F)) {
                    /* Unsupported sub-parameters/intermediates are consumed. */
                } else if (uc >= 0x40 && uc <= 0x7E) {
                    /* final byte of CSI */
                    if (tty->ansi_param_count < (int)(sizeof(tty->ansi_param)/sizeof(tty->ansi_param[0]))) {
                        tty->ansi_param[tty->ansi_param_count++] = tty->ansi_current_param;
                    }
                    unsigned char final_byte = (unsigned char)ch;
                    if (final_byte == 'm') {
                        /* SGR - color + reverse (ncurses/htop) */
                        if (tty->ansi_param_count == 0) {
                            tty->current_attr = GRAY_ON_BLACK;
                            tty->ansi_bold = 0;
                            tty->attr_reverse = 0;
                        } else {
                            int bright = tty->ansi_bold ? 1 : 0;
                            for (int pi = 0; pi < tty->ansi_param_count; pi++) {
                                int code = tty->ansi_param[pi];
                                if (code == 38 || code == 48) {
                                    if (pi + 2 < tty->ansi_param_count &&
                                        tty->ansi_param[pi + 1] == 5)
                                        pi += 2;
                                    continue;
                                }
                                if (code == 0) {
                                    tty->current_attr = GRAY_ON_BLACK;
                                    bright = 0;
                                    tty->attr_reverse = 0;
                                } else if (code == 1) {
                                    bright = 1;
                                } else if (code == 22) {
                                    bright = 0;
                                } else if (code == 7) {
                                    tty->attr_reverse = 1;
                                } else if (code == 27) {
                                    tty->attr_reverse = 0;
                                } else if (code == 39) {
                                    int bg = (tty->current_attr & 0xF0) >> 4;
                                    int fg = 7;
                                    if (bright) fg |= 8;
                                    tty->current_attr = (uint8_t)((bg << 4) | (fg & 0x0F));
                                } else if (code >= 30 && code <= 37) {
                                    static const uint8_t ansi_to_vga[8] = {0, 4, 2, 6, 1, 5, 3, 7};
                                    int fg_vga = ansi_to_vga[(code - 30) & 7];
                                    if (bright) fg_vga |= 8;
                                    int bg = (tty->current_attr & 0xF0) >> 4;
                                    tty->current_attr = (uint8_t)((bg << 4) | (fg_vga & 0x0F));
                                } else if (code >= 90 && code <= 97) {
                                    static const uint8_t ansi_to_vga[8] = {0, 4, 2, 6, 1, 5, 3, 7};
                                    int fg_vga = ansi_to_vga[(code - 90) & 7] | 8;
                                    int bg = (tty->current_attr & 0xF0) >> 4;
                                    tty->current_attr = (uint8_t)((bg << 4) | (fg_vga & 0x0F));
                                } else if (code >= 40 && code <= 47) {
                                    static const uint8_t ansi_to_vga_bg[8] = {0, 4, 2, 6, 1, 5, 3, 0};
                                    int bg_vga = ansi_to_vga_bg[(code - 40) & 7];
                                    int fg = tty->current_attr & 0x0F;
                                    tty->current_attr = (uint8_t)((bg_vga << 4) | (fg & 0x0F));
                                } else if (code >= 100 && code <= 107) {
                                    static const uint8_t ansi_to_vga_bg[8] = {0, 4, 2, 6, 1, 5, 3, 0};
                                    int bg_vga = ansi_to_vga_bg[(code - 100) & 7];
                                    int fg = tty->current_attr & 0x0F;
                                    tty->current_attr = (uint8_t)((bg_vga << 4) | (fg & 0x0F));
                                }
                            }
                            if (tty->attr_reverse) {
                                uint8_t fg = tty->current_attr & 0x0F;
                                uint8_t bg = (tty->current_attr >> 4) & 0x0F;
                                tty->current_attr = (uint8_t)((fg << 4) | (bg & 0x0F));
                            }
                            tty->ansi_bold = bright ? 1 : 0;
                        }
                    } else if (final_byte == 'G') {
                        int col = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                      ? tty->ansi_param[0] : 1;
                        uint32_t tty_cols = devfs_tty_cols();
                        if ((uint32_t)col > tty_cols) col = (int)tty_cols;
                        tty->cursor_x = (uint32_t)col - 1u;
                        tty->need_wrap = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'd') {
                        int row = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                      ? tty->ansi_param[0] : 1;
                        uint32_t tty_rows = devfs_tty_rows();
                        if ((uint32_t)row > tty_rows) row = (int)tty_rows;
                        tty->cursor_y = (uint32_t)row - 1u;
                        tty->need_wrap = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'E') {
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        uint32_t tty_rows = devfs_tty_rows();
                        tty->cursor_x = 0;
                        tty->need_wrap = 0;
                        if (tty->cursor_y + (uint32_t)n < tty_rows)
                            tty->cursor_y += (uint32_t)n;
                        else
                            tty->cursor_y = tty_rows - 1;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'F') {
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        tty->cursor_x = 0;
                        tty->need_wrap = 0;
                        if ((int)tty->cursor_y >= n)
                            tty->cursor_y -= (uint32_t)n;
                        else
                            tty->cursor_y = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 's') {
                        tty->dec_saved_x = tty->cursor_x;
                        tty->dec_saved_y = tty->cursor_y;
                    } else if (final_byte == 'u') {
                        tty->cursor_x = tty->dec_saved_x;
                        tty->cursor_y = tty->dec_saved_y;
                        tty->need_wrap = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'H' || final_byte == 'f') {
                        /* Cursor position: ESC [ <row> ; <col> H (1-based) */
                        int row = 1, col = 1;
                        if (tty->ansi_param_count >= 1) row = tty->ansi_param[0];
                        if (tty->ansi_param_count >= 2) col = tty->ansi_param[1];
                        if (row < 1) row = 1;
                        if (col < 1) col = 1;
                        uint32_t tty_rows = devfs_tty_rows();
                        uint32_t tty_cols = devfs_tty_cols();
                        if ((uint32_t)row > tty_rows) row = (int)tty_rows;
                        if ((uint32_t)col > tty_cols) col = (int)tty_cols;
                        tty->cursor_y = row - 1;
                        tty->cursor_x = col - 1;
                        tty->need_wrap = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'J') {
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        if (param == 2 || param == 3) {
                            /* ED never moves the cursor.  Mode 3 also clears
                             * scrollback; there is no scrollback buffer yet. */
                            uint32_t saved_x = tty->cursor_x;
                            uint32_t saved_y = tty->cursor_y;
                            devfs_tty_clear_backing_fast(tty, tty->current_attr);
                            tty->cursor_x = saved_x;
                            tty->cursor_y = saved_y;
                            if (tty_on_vga) {
                                console_clear_screen_attr(tty->current_attr);
                                console_set_cursor(saved_x, saved_y);
                            }
                        } else if (param == 0) {
                            /* Clear from cursor to end of screen */
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_rows = devfs_tty_rows();
                            uint32_t tty_cols = devfs_tty_cols();
                            for (uint32_t ry = cy; ry < tty_rows; ry++) {
                                uint32_t x0 = (ry == cy) ? tty->cursor_x : 0;
                                uint32_t x1 = tty_cols - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    size_t off = ((size_t)ry * tty_cols + rx) * 2;
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                if (tty_on_vga) console_clear_line_segment((uint32_t)x0, x1, ry, tty->current_attr);
                            }
                            if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                        } else if (param == 1) {
                            /* Clear from start of screen to cursor */
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_cols = devfs_tty_cols();
                            for (uint32_t ry = 0; ry <= cy; ry++) {
                                uint32_t x0 = 0;
                                uint32_t x1 = (ry == cy) ? tty->cursor_x : tty_cols - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    size_t off = ((size_t)ry * tty_cols + rx) * 2;
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                if (tty_on_vga) console_clear_line_segment(x0, x1, ry, tty->current_attr);
                            }
                            if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                        }
                        tty->need_wrap = 0;
                    } else if (final_byte == 'K') {
                        /* Erase in line: 0=from cursor to EOL, 1=BOL to cursor, 2=whole line.
                         * EL never moves the cursor; ncurses relies on this when repainting rows. */
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        uint32_t saved_x = tty->cursor_x;
                        uint32_t saved_y = tty->cursor_y;
                        uint32_t cy = tty->cursor_y;
                        uint32_t tty_cols = devfs_tty_cols();
                        if (tty_cols > 0) {
                            uint32_t x0 = 0, x1 = tty_cols - 1;
                            if (param == 0)
                                x0 = tty->cursor_x;
                            else if (param == 1)
                                x1 = tty->cursor_x;
                            if (x0 >= tty_cols)
                                x0 = tty_cols - 1;
                            if (x1 >= tty_cols)
                                x1 = tty_cols - 1;
                            if (tty->screen) {
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    size_t off = ((size_t)cy * tty_cols + rx) * 2;
                                    tty->screen[off] = ' ';
                                    tty->screen[off + 1] = tty->current_attr;
                                }
                            }
                            if (tty_on_vga)
                                console_clear_line_segment(x0, x1, cy, tty->current_attr);
                        }
                        tty->cursor_x = saved_x;
                        tty->cursor_y = saved_y;
                        tty->need_wrap = 0;
                        if (tty_on_vga)
                            console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'A' || final_byte == 'B' || final_byte == 'C' || final_byte == 'D') {
                        /* Cursor movement: CUU A=up, CUD B=down, CUF C=forward/right, CUB D=back/left */
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0) ? tty->ansi_param[0] : 1;
                        if (final_byte == 'A') {
                            if ((int)tty->cursor_y >= n) tty->cursor_y -= n; else tty->cursor_y = 0;
                        } else if (final_byte == 'B') {
                            uint32_t tty_rows = devfs_tty_rows();
                            if (tty->cursor_y + (uint32_t)n < tty_rows) tty->cursor_y += (uint32_t)n; else tty->cursor_y = tty_rows - 1;
                        } else if (final_byte == 'C') {
                            uint32_t tty_cols = devfs_tty_cols();
                            if (tty->cursor_x + (uint32_t)n < tty_cols) tty->cursor_x += (uint32_t)n; else tty->cursor_x = tty_cols - 1;
                        } else {
                            if ((int)tty->cursor_x >= n) tty->cursor_x -= n; else tty->cursor_x = 0;
                        }
                        tty->need_wrap = 0;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (!tty->ansi_csi_private && final_byte == 'r') {
                        uint32_t rows = devfs_tty_rows();
                        if (rows == 0) rows = 1;
                        if (tty->ansi_param_count == 0) {
                            devfs_tty_init_scroll(tty);
                        } else {
                            int top = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                          ? tty->ansi_param[0] : 1;
                            int bot = (tty->ansi_param_count > 1 && tty->ansi_param[1] > 0)
                                          ? tty->ansi_param[1]
                                          : (int)rows;
                            if ((uint32_t)top > rows) top = (int)rows;
                            if ((uint32_t)bot > rows) bot = (int)rows;
                            if (top < bot) {
                                tty->scroll_top = (uint32_t)top - 1u;
                                tty->scroll_bottom = (uint32_t)bot - 1u;
                            }
                        }
                        tty->cursor_x = 0;
                        tty->cursor_y = 0;
                        tty->need_wrap = 0;
                        if (tty_on_vga)
                            console_set_cursor(0, 0);
                        if (tty_on_vga && cirrusfb_is_ready())
                            cirrusfb_set_margin_rows(tty->scroll_top);
                    } else if (!tty->ansi_csi_private && final_byte == 'L') {
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        uint32_t cols = devfs_tty_cols();
                        uint32_t y0 = tty->cursor_y;
                        uint32_t bot = tty->scroll_bottom;
                        for (int ins = 0; ins < n; ins++) {
                            if (y0 < bot)
                                devfs_tty_scroll_backing_down(tty, y0, bot);
                        }
                        if (tty_on_vga) {
                            for (uint32_t y = y0; y <= bot; y++)
                                devfs_tty_blit_cells(tty, 0,
                                    cols > 0 ? cols - 1 : 0, y);
                        }
                        tty->need_wrap = 0;
                    } else if (!tty->ansi_csi_private && final_byte == 'M') {
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        uint32_t cols = devfs_tty_cols();
                        uint32_t rows = devfs_tty_rows();
                        uint32_t bot = tty->scroll_bottom;
                        if (bot >= rows) bot = rows - 1;
                        for (int del = 0; del < n; del++) {
                            if (tty->cursor_y >= rows) break;
                            for (uint32_t y = tty->cursor_y; y < bot && y + 1 < rows; y++) {
                                for (uint32_t x = 0; x < cols; x++) {
                                    size_t dst = ((size_t)y * cols + x) * 2;
                                    size_t src = ((size_t)(y + 1) * cols + x) * 2;
                                    if (tty->screen) {
                                        tty->screen[dst] = tty->screen[src];
                                        tty->screen[dst + 1] = tty->screen[src + 1];
                                    }
                                }
                            }
                            if (tty->screen && cols > 0) {
                                for (uint32_t x = 0; x < cols; x++) {
                                    size_t off = ((size_t)bot * cols + x) * 2;
                                    tty->screen[off] = ' ';
                                    tty->screen[off + 1] = tty->current_attr;
                                }
                            }
                            if (tty_on_vga) {
                                for (uint32_t y = tty->cursor_y; y <= bot; y++)
                                    devfs_tty_blit_cells(tty, 0, cols > 0 ? cols - 1 : 0, y);
                            }
                        }
                        tty->need_wrap = 0;
                    } else if (!tty->ansi_csi_private && final_byte == '@') {
                        /* ICH: insert n blank cells at cursor (ncurses ich/ich1). */
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        devfs_tty_insert_cells(tty, tty_on_vga, tty->cursor_x, tty->cursor_y, n);
                        tty->need_wrap = 0;
                        if (tty_on_vga)
                            console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (!tty->ansi_csi_private && final_byte == 'P') {
                        /* DCH: delete n cells at cursor (ncurses dch/dch1). */
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        devfs_tty_delete_cells(tty, tty_on_vga, tty->cursor_x, tty->cursor_y, n);
                        tty->need_wrap = 0;
                        if (tty_on_vga)
                            console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (!tty->ansi_csi_private && final_byte == 'X') {
                        /* ECH: erase n cells at cursor without moving it (ncurses ech).
                         * Without this, htop CPU meters smear leftover bar glyphs. */
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0)
                                    ? tty->ansi_param[0] : 1;
                        uint32_t saved_x = tty->cursor_x;
                        uint32_t saved_y = tty->cursor_y;
                        devfs_tty_erase_cells(tty, tty_on_vga, saved_x, saved_y, n);
                        tty->cursor_x = saved_x;
                        tty->cursor_y = saved_y;
                        tty->need_wrap = 0;
                        if (tty_on_vga)
                            console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'h' || final_byte == 'l') {
                        int set = (final_byte == 'h');
                        if (tty->ansi_csi_private) {
                            for (int pi = 0; pi < tty->ansi_param_count; pi++) {
                                int mode = tty->ansi_param[pi];
                                if (mode == 1049 || mode == 47) {
                                    /* smcup/rmcup: alternate screen (nano/htop/ncurses) */
                                    if (set) {
                                        size_t scr_sz = devfs_tty_screen_bytes();
                                        if (!tty->alt_active) {
                                            if (!tty->alt_screen)
                                                tty->alt_screen = (uint8_t *)kmalloc(scr_sz);
                                            if (tty->alt_screen && tty->screen)
                                                memcpy(tty->alt_screen, tty->screen, scr_sz);
                                            tty->alt_active = 1;
                                        }
                                        tty->saved_x = tty->cursor_x;
                                        tty->saved_y = tty->cursor_y;
                                        devfs_tty_clear_backing_fast(tty, tty->current_attr);
                                        tty->cursor_x = 0;
                                        tty->cursor_y = 0;
                                        if (tty_on_vga) {
                                            console_clear_screen_attr(tty->current_attr);
                                            console_set_cursor(0, 0);
                                        }
                                    } else {
                                        devfs_tty_leave_alt_screen(tty->id);
                                    }
                                }
                            }
                        } else {
                            /* SM/RM: CSI 4h / 4l = IRM insert mode (terminfo smir/rmir). */
                            for (int pi = 0; pi < tty->ansi_param_count; pi++) {
                                if (tty->ansi_param[pi] == 4)
                                    tty->insert_mode = set ? 1 : 0;
                            }
                        }
                    }
                    devfs_tty_vt_reset(tty);
                } else {
                    /* Invalid byte: cancel instead of swallowing future text. */
                    devfs_tty_vt_reset(tty);
                }
            }
        }
    }
    if (tty_on_vga_batch) {
        console_set_cursor(t->cursor_x, t->cursor_y);
        console_end_tty_batch();
    }
    release_irqrestore(&t->out_lock, out_flags);
    /* Also append written chars to stdout/stderr ring buffers if applicable */
    if (path) {
        int which = -1;
        if (strcmp(path, "/dev/stdout") == 0) which = 0;
        else if (strcmp(path, "/dev/stderr") == 0) which = 1;
        if (which >= 0) {
            stdio_ring_t *rb = &stdio_bufs[which];
            unsigned long flags = 0;
            acquire_irqsave(&rb->lock, &flags);
            for (size_t ii = 0; ii < size; ii++) {
                char ch2 = s[ii];
                size_t next = (rb->tail + 1) % rb->cap;
                if (next != rb->head) {
                    rb->buf[rb->tail] = ch2;
                    rb->tail = next;
                } else {
                    /* buffer full: drop oldest */
                    rb->head = (rb->head + 1) % rb->cap;
                    rb->buf[rb->tail] = ch2;
                    rb->tail = (rb->tail + 1) % rb->cap;
                }
            }
            /* wake readers */
            for (int wi = 0; wi < rb->waiters_count; wi++) {
                int tid = rb->waiters[wi];
                if (tid >= 0) thread_unblock(tid);
            }
            rb->waiters_count = 0;
            release_irqrestore(&rb->lock, flags);
        }
    }
    return (ssize_t)size;
}

static void devfs_release(struct fs_file *file) {
    if (!file) return;
    if (pty_is_file(file)) {
        pty_release_handle(file);
        if (file->path) kfree((void *)file->path);
        kfree(file);
        return;
    }
    // free driver_private if it was allocated for special device markers
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        uintptr_t base_tty = (uintptr_t)&dev_ttys[0];
        uintptr_t end_tty = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
        uintptr_t base_blk = (uintptr_t)&dev_blocks[0];
        uintptr_t end_blk = (uintptr_t)&dev_blocks[dev_block_count];
        int is_allocated_marker = 1;
        /* if driver_private points into tty array or block array, don't free */
        if (dp >= base_tty && dp < end_tty) is_allocated_marker = 0;
        if (dp >= base_blk && dp < end_blk) is_allocated_marker = 0;
        /* if driver_private matches any registered dev_chars entry, do not free (it's owned by caller) */
        for (int ci = 0; ci < dev_char_count; ci++) {
            if (file->driver_private == dev_chars[ci].driver_private) { is_allocated_marker = 0; break; }
        }
        if (is_allocated_marker) {
            kfree(file->driver_private);
        }
    }
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int devfs_block_count(void) {
    return dev_block_count;
}

int devfs_block_get(int index, char *out_name, size_t out_cap, int *out_device_id, uint32_t *out_sectors) {
    if (index < 0 || index >= dev_block_count) return -1;
    if (!out_name || out_cap == 0) return -1;
    const char *path = dev_blocks[index].path;
    const char *last = path ? strrchr(path, '/') : NULL;
    const char *nm = last ? (last + 1) : (path ? path : "");
    strncpy(out_name, nm, out_cap - 1);
    out_name[out_cap - 1] = '\0';
    if (out_device_id) *out_device_id = dev_blocks[index].device_id;
    if (out_sectors) *out_sectors = dev_blocks[index].sectors;
    return 0;
}

int devfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st) return -1;
    if (pty_is_file(file))
        return pty_fill_stat(file, st);
    memset(st, 0, sizeof(*st));

    const char *p = file->path ? file->path : "";
    /* directory /dev */
    if (strcmp(p, "/dev") == 0 || strcmp(p, "/dev/") == 0 || file->type == FS_TYPE_DIR) {
        st->st_ino = 2;
        st->st_mode = (mode_t)(S_IFDIR | 0755);
        st->st_nlink = 2;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = 0;
        return 0;
    }

    /* block device node? */
    int did = devfs_get_device_id(p);
    if (did >= 0) {
        st->st_ino = (ino_t)(1000u + (unsigned)did);
        st->st_mode = (mode_t)(S_IFBLK | 0600);
        st->st_nlink = 1;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = (off_t)file->size;
        /* Linux majors: 8=sd, 11=sr, 259=nvme (simplified). */
        {
            const char *nm = strrchr(p, '/');
            nm = nm ? nm + 1 : p;
            unsigned major = 0, minor = 0;
            if (nm[0] == 's' && nm[1] == 'd' && nm[2] >= 'a' && nm[2] <= 'z') {
                int disk = nm[2] - 'a';
                int part = 0;
                if (nm[3] >= '1' && nm[3] <= '9')
                    part = nm[3] - '0';
                major = DISK_MAJOR_SD;
                minor = (unsigned)(disk * 16 + part);
            } else if ((nm[0] == 's' && nm[1] == 'r' && nm[2] >= '0' && nm[2] <= '9') ||
                       strcmp(nm, "cdrom") == 0) {
                major = DISK_MAJOR_SR;
                if (strcmp(nm, "cdrom") == 0)
                    minor = 0;
                else {
                    for (int k = 2; nm[k] >= '0' && nm[k] <= '9'; k++)
                        minor = minor * 10u + (unsigned)(nm[k] - '0');
                }
            } else if (strncmp(nm, "nvme", 4) == 0) {
                major = 259;
                minor = (unsigned)did;
            } else {
                major = DISK_MAJOR_SD;
                minor = (unsigned)did * 16u;
            }
            st->st_rdev = MKDEV(major, minor);
        }
        return 0;
    }

    /* /dev/fb0: Linux fb major 29, minor 0 */
    if (strcmp(p, "/dev/fb0") == 0) {
        st->st_dev = MKDEV(0, 1); /* arbitrary containing device */
        st->st_ino = 2100;
        st->st_mode = (mode_t)(S_IFCHR | 0666);
        st->st_nlink = 1;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_rdev = MKDEV(FB_MAJOR, 0);
        st->st_size = (off_t)fbdev_byte_len();
        return 0;
    }

    /* tty and special devices behave like character devices */
    st->st_ino = 2000;
    st->st_mode = (mode_t)(S_IFCHR | 0666);
    st->st_nlink = 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_size = 0;
    return 0;
}

int devfs_register(void) {
    /* init ttys */
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        dev_ttys[i].id = i;
        dev_ttys[i].cursor_x = get_cursor_x();
        dev_ttys[i].cursor_y = get_cursor_y();
        devfs_tty_init_scroll(&dev_ttys[i]);
        dev_ttys[i].in_head = dev_ttys[i].in_tail = dev_ttys[i].in_count = 0;
        dev_ttys[i].in_lock.lock = 0;
        dev_ttys[i].out_lock.lock = 0;
        dev_ttys[i].waiters_count = 0;
        dev_ttys[i].fg_pgrp = -1;
        size_t scr_sz = devfs_tty_screen_bytes();
        dev_ttys[i].screen = (uint8_t*)kmalloc(scr_sz);
        if (dev_ttys[i].screen) {
            for (size_t j = 0; j + 1 < scr_sz; j += 2) { dev_ttys[i].screen[j] = ' '; dev_ttys[i].screen[j + 1] = GRAY_ON_BLACK; }
        }
        /* initialize ANSI/escape parsing state and current attribute */
        dev_ttys[i].current_attr = GRAY_ON_BLACK;
        dev_ttys[i].ansi_escape_state = 0;
        dev_ttys[i].g0_is_acs = 0;
        dev_ttys[i].acs_mode = 0;
        dev_ttys[i].insert_mode = 0;
        dev_ttys[i].ansi_csi_private = 0;
        dev_ttys[i].ansi_param_count = 0;
        dev_ttys[i].ansi_current_param = 0;
        dev_ttys[i].controlling_sid = -1;
        dev_ttys[i].term_lflag = 0x00000002u /* ICANON */ | 0x00000008u /* ECHO */ | 0x00000001u /* ISIG */;
        dev_ttys[i].term_vmin = 1;
        dev_ttys[i].term_vtime = 0;
        dev_ttys[i].echo_escape_state = 0;
        dev_ttys[i].unget_char = -1;
    }
    /* Capture boot-time console into tty0 so VC switch can restore it. */
    devfs_tty_snapshot_visible(&dev_ttys[0]);
    /* init stdio ring buffers */
    for (int si = 0; si < 2; si++) {
        stdio_bufs[si].cap = 4096;
        stdio_bufs[si].buf = (char*)kmalloc(stdio_bufs[si].cap);
        stdio_bufs[si].head = stdio_bufs[si].tail = 0;
        stdio_bufs[si].lock.lock = 0;
        stdio_bufs[si].waiters_count = 0;
    }
    devfs_entropy = 0;
    devfs_random_waiters_count = 0;
    devfs_ops.name = "devfs";
    devfs_ops.create = devfs_create;
    devfs_ops.open = devfs_open;
    devfs_ops.read = devfs_read;
    devfs_ops.write = devfs_write;
    devfs_ops.chmod = devfs_chmod;
    devfs_ops.unlink = devfs_unlink;
    devfs_ops.release = devfs_release;
    devfs_driver.ops = &devfs_ops;
    /* set a unique non-NULL driver_data so VFS dispatch finds this driver for our files */
    devfs_driver_data = &devfs_driver; /* unique pointer */
    devfs_driver.driver_data = &devfs_driver_data;
    int r = fs_register_driver(&devfs_driver);
    if (r == 0) devfs_ready = 1;
    return r;
}

void devfs_tty_realloc_for_console(void) {
    size_t scr_sz = devfs_tty_screen_bytes();
    uint8_t *new_screens[DEVFS_TTY_COUNT];
    int i;
    for (i = 0; i < DEVFS_TTY_COUNT; i++)
        new_screens[i] = NULL;
    for (i = 0; i < DEVFS_TTY_COUNT; i++) {
        new_screens[i] = (uint8_t*)kmalloc(scr_sz);
        if (!new_screens[i]) {
            for (int j = 0; j < i; j++) {
                kfree(new_screens[j]);
                new_screens[j] = NULL;
            }
            return;
        }
    }
    for (i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].alt_screen) {
            kfree(dev_ttys[i].alt_screen);
            dev_ttys[i].alt_screen = NULL;
            dev_ttys[i].alt_active = 0;
        }
        kfree(dev_ttys[i].screen);
        dev_ttys[i].screen = new_screens[i];
        for (size_t j = 0; j + 1 < scr_sz; j += 2) {
            dev_ttys[i].screen[j] = ' ';
            dev_ttys[i].screen[j + 1] = GRAY_ON_BLACK;
        }
        dev_ttys[i].cursor_x = 0;
        dev_ttys[i].cursor_y = 0;
        devfs_tty_init_scroll(&dev_ttys[i]);
        dev_ttys[i].ansi_escape_state = 0;
        dev_ttys[i].ansi_csi_private = 0;
        dev_ttys[i].ansi_param_count = 0;
        dev_ttys[i].ansi_current_param = 0;
        dev_ttys[i].g0_is_acs = 0;
        dev_ttys[i].acs_mode = 0;
        dev_ttys[i].insert_mode = 0;
        dev_ttys[i].echo_escape_state = 0;
    }
}

int devfs_mount(const char *path) {
    if (!path) return -1;
    return fs_mount(path, &devfs_driver);
}

void devfs_switch_tty(int index) {
    if (index < 0 || index >= DEVFS_TTY_COUNT) return;
    if (index == devfs_active) return;

    /* When cirrusfb is active, tty backing store matches its internal textbuf.
       Never memcpy fbcon-sized buffers into legacy VGA text memory; that corrupts memory. */
    if (cirrusfb_is_ready()) {
        devfs_tty_snapshot_visible(&dev_ttys[devfs_active]);
        devfs_active = index;
        devfs_tty_blit_to_console(&dev_ttys[devfs_active]);
        return;
    }

    if (vbe_is_available()) {
        devfs_tty_snapshot_visible(&dev_ttys[devfs_active]);
        devfs_active = index;
        devfs_tty_blit_to_console(&dev_ttys[devfs_active]);
        return;
    }

    /* Fallback: legacy VGA text mode only.
       Clamp copy size so we never write beyond the actual VGA text buffer. */
    devfs_tty_snapshot_visible(&dev_ttys[devfs_active]);
    devfs_active = index;
    devfs_tty_blit_to_console(&dev_ttys[devfs_active]);
    /* set current user/process to first process attached to this tty, if any */
    /* NOTE:
       Do NOT call thread_set_current_user() here.
       current_user must track the *currently running* user thread (scheduler-owned),
       not "foreground tty process". Desync causes syscalls to be dispatched using the
       wrong thread struct and leads to user-mode GPF after vfork/exec. */
}

int devfs_tty_count(void) { return DEVFS_TTY_COUNT; }

int devfs_unregister(void) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].alt_screen) kfree(dev_ttys[i].alt_screen);
        if (dev_ttys[i].screen) kfree(dev_ttys[i].screen);
    }
    devfs_ready = 0;
    return fs_unregister_driver(&devfs_driver);
}

int devfs_is_ready(void) { return devfs_ready; }

static int devfs_tty_try_erase(struct devfs_tty *t, int tty) {
    if (!t || t->in_count <= 0) return 0;
    /* Do not erase past a newline (start of current line). */
    int last_idx = t->in_tail - 1;
    if (last_idx < 0) last_idx += (int)sizeof(t->inbuf);
    if (t->inbuf[last_idx] == '\n') return 0;
    /* Remove last buffered character. */
    t->in_tail = last_idx;
    t->in_count--;
    /* Echo erase: use TTY's cursor (kept in sync on each echo) so visual matches buffer. */
    if ((t->term_lflag & 0x00000008u) /* ECHO */ && tty == devfs_get_active()) {
        if (t->cursor_x > 0) {
            uint32_t cx = (uint32_t)t->cursor_x;
            uint32_t cy = (uint32_t)t->cursor_y;
            uint8_t attr = console_get_cell_attr(cx - 1, cy);
            console_putch_xy(cx - 1, cy, ' ', attr);
            t->cursor_x = cx - 1;
            console_set_cursor(t->cursor_x, t->cursor_y);
        }
    }
    return 1;
}

/* push input char into tty's input queue and wake waiters */
void devfs_tty_push_input(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    /* Backspace (DEL 0x7F / BS 0x08): never handle in kernel; always pass to application.
       Otherwise it is handled twice (kernel try_erase + app line editor) and display/buffer get out of sync. */
    if (t->in_count < (int)sizeof(t->inbuf)) {
        t->inbuf[t->in_tail] = c;
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    /* wake waiters */
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;
    release_irqrestore(&t->in_lock, flags);
}

int devfs_get_active(void) { return devfs_active; }

ssize_t devfs_tty_debug_dump(char *buf, size_t size) {
    if (!buf || size == 0) return 0;
    size_t w = 0;
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    w += (size_t)snprintf(buf + w, (w < size) ? size - w : 0,
                          "active=%d cols=%u rows=%u\n", devfs_active + 1, cols, rows);
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        struct devfs_tty *t = &dev_ttys[i];
        size_t cells = (size_t)cols * (size_t)rows;
        size_t nonspace = 0;
        char preview[65];
        size_t pi = 0;
        if (t->screen) {
            for (size_t c = 0; c < cells; c++) {
                uint8_t ch = t->screen[c * 2];
                if (ch != ' ' && ch != '\0') {
                    nonspace++;
                    if (pi + 1 < sizeof(preview)) {
                        preview[pi++] = (ch >= 32 && ch <= 126) ? (char)ch : '.';
                    }
                }
            }
        }
        preview[pi] = '\0';
        w += (size_t)snprintf(buf + w, (w < size) ? size - w : 0,
                              "tty%d cur=%u,%u attr=0x%02x fg=%d sid=%d nonspace=%llu preview=\"%s\"\n",
                              i + 1,
                              (unsigned)t->cursor_x,
                              (unsigned)t->cursor_y,
                              (unsigned)t->current_attr,
                              t->fg_pgrp,
                              t->controlling_sid,
                              (unsigned long long)nonspace,
                              preview);
        if (w >= size) return (ssize_t)size;
    }
    return (ssize_t)w;
}

void devfs_tty_push_input_sequence(int tty, const char *seq, size_t len) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT || !seq || len == 0)
        return;
    struct devfs_tty *t = &dev_ttys[tty];
    if (len > sizeof(t->inbuf))
        return;

    /*
     * A key string is one input event.  Linux's keyboard/tty flip-buffer path
     * cannot expose a suffix such as "[H" without the leading ESC.  Reserve
     * and enqueue the complete string while holding the tty input lock.
     */
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if ((size_t)t->in_count + len > sizeof(t->inbuf)) {
        release_irqrestore(&t->in_lock, flags);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        t->inbuf[t->in_tail] = seq[i];
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;

    /*
     * Preserve the existing tty echo policy, but advance it atomically for
     * the whole key string.  Thus ESC [ H is either fully suppressed as a
     * function-key sequence or fully delivered; VMware cannot expose "[H".
     */
    if (tty == devfs_get_active() && (t->term_lflag & 0x00000008u)) {
        for (size_t i = 0; i < len; i++) {
            unsigned char uc = (unsigned char)seq[i];
            if (t->echo_escape_state == 0) {
                if (uc == 0x1Bu)
                    t->echo_escape_state = 1;
            } else if (t->echo_escape_state == 1) {
                if (uc == '[' || uc == 'O')
                    t->echo_escape_state = 2;
                else
                    t->echo_escape_state = 0;
            } else if (uc >= 0x40u && uc <= 0x7Eu) {
                t->echo_escape_state = 0;
            }
        }
    }
    release_irqrestore(&t->in_lock, flags);
    thread_request_resched();
}

/* Non-blocking push from ISR: try lock; on failure park the char in a
 * lock-free overflow slot instead of dropping it (htop can hold in_lock via
 * poll/read briefly under STI syscalls). */
void devfs_tty_push_input_noblock(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    if (!try_acquire(&t->in_lock)) {
        /* Ctrl+C: Linux n_tty — SIGINT to the tty foreground process group only. */
        if ((unsigned char)c == 0x03) {
            int pgrp = devfs_get_tty_fg_pgrp(tty);
            if (pgrp >= 0) {
                thread_send_sigint_to_pgrp(pgrp);
            }
            thread_request_resched();
            return;
        }
        /* Best-effort overflow: one pending byte survives a contested lock. */
        if (t->unget_char < 0)
            t->unget_char = (unsigned char)c;
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        thread_request_resched();
        return;
    }
    /* Backspace (DEL 0x7F / BS 0x08): never handle in kernel; always pass to application.
       Prevents double handling (kernel try_erase + sh line editor) and keeps display in sync. */
    /* Ctrl+C (0x03): SIGINT to tty->pgrp only (Linux n_tty_receive_char). */
    if ((unsigned char)c == 0x03) {
        if (t->fg_pgrp >= 0) thread_send_sigint_to_pgrp(t->fg_pgrp);
        /* Wake readers so they can observe updated process state. */
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        int do_echo_cc = (tty == devfs_get_active() && (t->term_lflag & 0x00000008u));
        release(&t->in_lock);
        if (do_echo_cc) {
            static const uint8_t echo_intr[] = { '^', 'C', '\n' };
            devfs_tty_echo_bytes(t, echo_intr, sizeof(echo_intr));
        }
        thread_request_resched();
        return;
    }
    if (t->in_count < (int)sizeof(t->inbuf)) {
        t->inbuf[t->in_tail] = c;
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    /* inbuf full: drop char */
    /* wake waiters (don't unblock in ISR) */
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;
    /*
     * Local echo (N_TTY). Release in_lock before painting so a concurrent
     * reader/poll cannot starve the next scancode on try_acquire.
     */
    unsigned char echo_uc = 0;
    int do_echo = 0;
    if (tty == devfs_get_active() && (t->term_lflag & 0x00000008u)) {
        unsigned char uc = (unsigned char)c;
        int skip_echo = 0;
        if (t->echo_escape_state == 0) {
            if (uc == 0x1Bu) {
                t->echo_escape_state = 1;
                skip_echo = 1;
            }
        } else if (t->echo_escape_state == 1) {
            if (uc == '[' || uc == 'O') {
                t->echo_escape_state = 2;
                skip_echo = 1;
            } else {
                t->echo_escape_state = 0;
            }
        } else { /* CSI / SS3 body */
            skip_echo = 1;
            if (uc >= 0x40u && uc <= 0x7Eu)
                t->echo_escape_state = 0;
        }
        if (!skip_echo) {
            if (uc == '\r')
                uc = '\n';
            if (uc == '\n' || uc == '\t' || uc >= 32u) {
                echo_uc = uc;
                do_echo = 1;
            }
        }
    }
    release(&t->in_lock);
    if (do_echo)
        devfs_tty_echo_bytes(t, &echo_uc, 1);
    /* IRQ context only marks waiters runnable. Scheduling from IRQ1 can
     * corrupt the active syscall/IRQ frame; timer preemption / syscall-exit
     * cond_resched performs the context switch after the handler returns. */
    thread_request_resched();
}

int devfs_tty_pop_nb(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if (t->unget_char >= 0) {
        int c = t->unget_char;
        t->unget_char = -1;
        release_irqrestore(&t->in_lock, flags);
        return c;
    }
    if (t->in_count == 0) { release_irqrestore(&t->in_lock, flags); return -1; }
    char c = t->inbuf[t->in_head];
    t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
    t->in_count--;
    release_irqrestore(&t->in_lock, flags);
    return (int)(unsigned char)c;
}

int devfs_tty_unget(int tty, int c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    if (c < 0 || c > 255) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if (t->unget_char >= 0) { release_irqrestore(&t->in_lock, flags); return -1; }
    t->unget_char = (unsigned char)c;
    release_irqrestore(&t->in_lock, flags);
    return 0;
}

int devfs_tty_available(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return 0;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    int v = t->in_count;
    if (t->unget_char >= 0) v++;
    release_irqrestore(&t->in_lock, flags);
    return v;
}

void devfs_tty_flush_input(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT)
        return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    t->in_head = 0;
    t->in_tail = 0;
    t->in_count = 0;
    t->unget_char = -1;
    t->echo_escape_state = 0;
    release_irqrestore(&t->in_lock, flags);
}

int devfs_tty_add_waiter(int tty, int tid) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    for (int i = 0; i < t->waiters_count; i++) if (t->waiters[i] == tid) { release_irqrestore(&t->in_lock, flags); return 0; }
    if (t->waiters_count >= (int)(sizeof(t->waiters)/sizeof(t->waiters[0]))) { release_irqrestore(&t->in_lock, flags); return -1; }
    t->waiters[t->waiters_count++] = tid;
    release_irqrestore(&t->in_lock, flags);
    return 0;
}

void devfs_tty_remove_waiter(int tty, int tid) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    for (int i = 0; i < t->waiters_count; i++) {
        if (t->waiters[i] == tid) {
            t->waiters[i] = t->waiters[t->waiters_count - 1];
            t->waiters_count--;
            break;
        }
    }
    release_irqrestore(&t->in_lock, flags);
}

void devfs_tty_remove_waiter_from_all_ttys(int tid) {
    if (tid < 0) return;
    for (int tty = 0; tty < DEVFS_TTY_COUNT; tty++) {
        for (;;) {
            struct devfs_tty *t = &dev_ttys[tty];
            unsigned long flags = 0;
            int found = 0;
            acquire_irqsave(&t->in_lock, &flags);
            for (int i = 0; i < t->waiters_count; i++) {
                if (t->waiters[i] == tid) {
                    t->waiters[i] = t->waiters[t->waiters_count - 1];
                    t->waiters_count--;
                    found = 1;
                    break;
                }
            }
            release_irqrestore(&t->in_lock, flags);
            if (!found) break;
        }
    }
}

/* Helpers exposed to other kernel components */
int devfs_tty_get_fg_pgrp(struct fs_file *file) {
    int idx = devfs_get_tty_index_from_file(file);
    if (idx < 0 || idx >= DEVFS_TTY_COUNT) return -1;
    return dev_ttys[idx].fg_pgrp;
}

int devfs_tty_set_fg_pgrp(struct fs_file *file, int pgrp) {
    int idx = devfs_get_tty_index_from_file(file);
    if (idx < 0 || idx >= DEVFS_TTY_COUNT) return -1;
    dev_ttys[idx].fg_pgrp = pgrp;
    return 0;
}

/* Get/set controlling session id via file handle helpers */
int devfs_get_tty_controlling_sid(struct fs_file *file) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    return t->controlling_sid;
}

int devfs_set_tty_controlling_sid(struct fs_file *file, int sid) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    t->controlling_sid = sid;
    return 0;
}

int devfs_tty_get_index_from_file(struct fs_file *file) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    return t->id;
}

int devfs_tty_attach_thread(struct fs_file *file, thread_t *th) {
    if (!file || !file->driver_private || !th) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    th->attached_tty = t->id;
    return 0;
}

int devfs_is_tty_file(struct fs_file *file) {
    if (!file) return 0;
    if (pty_is_file(file)) return 1;
    /* Fast path by path name: treat console/stdin/stdout/stderr/tty as tty-like. */
    if (file->path) {
        if (strcmp(file->path, "/dev/console") == 0) return 1;
        if (strcmp(file->path, "/dev/tty") == 0) return 1;
        if (strcmp(file->path, "/dev/stdin") == 0) return 1;
        if (strcmp(file->path, "/dev/stdout") == 0) return 1;
        if (strcmp(file->path, "/dev/stderr") == 0) return 1;
    }
    /* driver_private for devfs files points into dev_ttys array */
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (file->driver_private == &dev_ttys[i]) return 1;
    }
    return 0;
}

/* Map an open file handle to a tty index if possible, or -1 otherwise.
+   Encapsulates logic used to resolve /dev/stdin/out/err, /dev/tty and ttyN. */
int devfs_get_tty_index_from_file(struct fs_file *file) {
    if (!file) return -1;
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        uintptr_t base_tty = (uintptr_t)&dev_ttys[0];
        uintptr_t end_tty = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
        if (dp >= base_tty && dp < end_tty) {
            struct devfs_tty *t = (struct devfs_tty*)dp;
            return t->id;
        }
        /* marker pointer for special devices */
        int marker = *(int*)file->driver_private;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            if (si == 3 || si == 6 || si == 4 || si == 5) {
                thread_t *cur = thread_current();
                return (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
            }
        }
    }
    if (file->path) {
        if (strcmp(file->path, "/dev/console") == 0) return 0;
        /* /dev/N and /dev/ttyN: same mapping as devfs_path_to_tty */
        if (strncmp(file->path, "/dev/", 5) == 0 && file->path[5] >= '0' && file->path[5] <= '9' && file->path[6] == '\0') {
            int n = file->path[5] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;
            if (n == 0) return 0;
        }
        if (strlen(file->path) >= 9 && strncmp(file->path, "/dev/tty", 8) == 0 && file->path[8] >= '0' && file->path[8] <= '9') {
            int n = file->path[8] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;
            if (n == 0) return 0;
        }
        if (strcmp(file->path, "/dev/stdin") == 0 || strcmp(file->path, "/dev/tty") == 0) {
            thread_t *cur = thread_current();
            return (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
        }
    }
    return -1;
}

/* Return pointer to internal tty struct by index, or NULL if invalid. */
struct devfs_tty *devfs_get_tty_by_index(int idx) {
    if (idx < 0 || idx >= DEVFS_TTY_COUNT) return NULL;
    return &dev_ttys[idx];
}

int devfs_get_tty_fg_pgrp(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    return dev_ttys[tty].fg_pgrp;
}

void devfs_set_tty_fg_pgrp(int tty, int pgrp) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    dev_ttys[tty].fg_pgrp = pgrp;
}

/* Clear controlling_sid for any ttys owned by given session id */
void devfs_clear_controlling_by_sid(int sid) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].controlling_sid == sid) dev_ttys[i].controlling_sid = -1;
    }
}

int devfs_create_block_node_lba(const char *path, int device_id, uint32_t start_lba, uint32_t sectors) {
    if (!path) return -1;
    for (int i = 0; i < dev_block_count; i++) {
        if (strcmp(dev_blocks[i].path, path) == 0) {
            dev_blocks[i].device_id = device_id;
            dev_blocks[i].start_lba = start_lba;
            dev_blocks[i].sectors = sectors;
            return 0;
        }
    }
    if (dev_block_count >= (int)(sizeof(dev_blocks)/sizeof(dev_blocks[0]))) return -1;
    strncpy(dev_blocks[dev_block_count].path, path, sizeof(dev_blocks[dev_block_count].path)-1);
    dev_blocks[dev_block_count].path[sizeof(dev_blocks[dev_block_count].path)-1] = '\0';
    dev_blocks[dev_block_count].device_id = device_id;
    dev_blocks[dev_block_count].start_lba = start_lba;
    dev_blocks[dev_block_count].sectors = sectors;
    dev_block_count++;
    return 0;
}

/* Create a whole-disk block node and register mapping */
int devfs_create_block_node(const char *path, int device_id, uint32_t sectors) {
    return devfs_create_block_node_lba(path, device_id, 0, sectors);
}

/* Create a character device node and register mapping (e.g., /dev/fb0) */
int devfs_create_char_node(const char *path, void *driver_private) {
    if (!path) return -1;
    if (dev_char_count >= (int)(sizeof(dev_chars)/sizeof(dev_chars[0]))) return -1;
    /* avoid duplicate registrations for same path: update driver_private if provided */
    for (int i = 0; i < dev_char_count; i++) {
        if (strcmp(dev_chars[i].path, path) == 0) {
            if (driver_private) dev_chars[i].driver_private = driver_private;
            return 0;
        }
    }
    strncpy(dev_chars[dev_char_count].path, path, sizeof(dev_chars[dev_char_count].path)-1);
    dev_chars[dev_char_count].path[sizeof(dev_chars[dev_char_count].path)-1] = '\0';
    dev_chars[dev_char_count].driver_private = driver_private;
    dev_char_count++;
    return 0;
}

/* helper: find block index by path */
int devfs_find_block_by_path(const char *path) {
    if (!path) return -1;
    for (int i = 0; i < dev_block_count; i++) {
        if (strcmp(path, dev_blocks[i].path) == 0) return i;
    }
    return -1;
}

/* Return the underlying disk device_id for a block node path, or -1 if not found */
int devfs_get_device_id(const char *path) {
    int idx = devfs_find_block_by_path(path);
    if (idx < 0) return -1;
    return dev_blocks[idx].device_id;
}


