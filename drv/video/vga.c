#include <stdint.h>
#include <serial.h>
#include <vga.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <vbe.h>
#include <cirrusfb.h>
#include <spinlock.h>
#include <console.h>
#include <devfs.h>

static uint8_t parse_color_code(char bg, char fg);

/* Serialize console with IRQ-save: timer/keyboard ISRs may flush or move cursor;
 * plain spin + IF=1 deadlocks if an IRQ tries to take this lock while we hold it.
 * kprintf/kprint hold this for an entire format string so SMP log lines do not interleave. */
static spinlock_t vga_lock_spin = { 0 };
static uint16_t vga_cursor_offset = 0;
static uint64_t vga_cursor_last_phase = 0;
static int vga_cursor_visible = 1;

extern volatile uint64_t timer_ticks;
extern volatile uint32_t timer_frequency;

/* Internal nolock primitives for callers that already hold the lock. */
static inline void write_nolock(uint8_t character, uint8_t attribute_byte, uint16_t offset) {
        uint8_t *vga = (uint8_t *) VIDEO_ADDRESS;
        vga[offset] = character;
        vga[offset + 1] = attribute_byte;
}

static inline uint16_t get_cursor_nolock(void) {
        return vga_cursor_offset;
}

static inline void set_cursor_nolock(uint16_t pos) {
        vga_cursor_offset = pos;
}

/*
 * CRTC port writes cause a VM-exit under QEMU/VMware. Keep cursor movement in
 * RAM while drawing and publish only the final position for the whole write.
 */
static inline void flush_cursor_nolock(void) {
        uint16_t pos = (uint16_t)(vga_cursor_offset / 2);
        outb(REG_SCREEN_CTRL, 14);
        outb(REG_SCREEN_DATA, (uint8_t)(pos >> 8));
        outb(REG_SCREEN_CTRL, 15);
        outb(REG_SCREEN_DATA, (uint8_t)(pos & 0xff));
}

/* --- ANSI CSI for plain VGA text (no Cirrus/VBE): otherwise ESC[H prints as "[H" --- */
enum { VGA_TX_ESC_NONE = 0, VGA_TX_ESC = 1, VGA_TX_CSI = 2, VGA_TX_SS3 = 3 };
static int vga_tx_esc = VGA_TX_ESC_NONE;
static int vga_tx_csi_p[8];
static int vga_tx_csi_np = 0;
static int vga_tx_csi_cur = 0;

static void vga_nolock_fill_range(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr) {
        if (y >= MAX_ROWS || x0 > x1) return;
        if (x1 >= MAX_COLS) x1 = MAX_COLS - 1;
        for (uint32_t x = x0; x <= x1; x++) {
                write_nolock(' ', attr, (uint16_t)((y * MAX_COLS + x) * 2));
        }
}

static void vga_nolock_csi_dispatch(uint8_t fb, uint8_t attr) {
        int np = vga_tx_csi_np;
        int *p = vga_tx_csi_p;

        if (fb == 'm') {
                /* Swallow SGR; per-character attr comes from the caller (e.g. devfs tty). */
                (void)np;
                (void)p;
                return;
        }
        if (fb == 'H' || fb == 'f') {
                int row = (np >= 1) ? p[0] : 1;
                int col = (np >= 2) ? p[1] : 1;
                if (row < 1) row = 1;
                if (col < 1) col = 1;
                if ((uint32_t)row > MAX_ROWS) row = MAX_ROWS;
                if ((uint32_t)col > MAX_COLS) col = MAX_COLS;
                set_cursor_nolock((uint16_t)(((uint32_t)(row - 1) * MAX_COLS + (uint32_t)(col - 1)) * 2));
                return;
        }
        if (fb == 'J') {
                int pm = (np > 0) ? p[0] : 0;
                if (pm == 2 || pm == 3) {
                        for (uint32_t i = 0; i < (uint32_t)(MAX_ROWS * MAX_COLS); i++) {
                                write_nolock(' ', attr, (uint16_t)(i * 2));
                        }
                        set_cursor_nolock(0);
                        return;
                }
                uint16_t off = get_cursor_nolock();
                uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
                uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
                if (pm == 0) {
                        vga_nolock_fill_range(cx, MAX_COLS - 1, cy, attr);
                        for (uint32_t yy = cy + 1; yy < MAX_ROWS; yy++) {
                                vga_nolock_fill_range(0, MAX_COLS - 1, yy, attr);
                        }
                } else if (pm == 1) {
                        for (uint32_t yy = 0; yy < cy; yy++) {
                                vga_nolock_fill_range(0, MAX_COLS - 1, yy, attr);
                        }
                        vga_nolock_fill_range(0, cx, cy, attr);
                }
                return;
        }
        if (fb == 'K') {
                int pm = (np > 0) ? p[0] : 0;
                uint16_t off = get_cursor_nolock();
                uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
                uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
                if (pm == 0) {
                        vga_nolock_fill_range(cx, MAX_COLS - 1, cy, attr);
                } else if (pm == 1) {
                        vga_nolock_fill_range(0, cx, cy, attr);
                } else {
                        vga_nolock_fill_range(0, MAX_COLS - 1, cy, attr);
                }
                return;
        }
        if (fb == 'A' || fb == 'B' || fb == 'C' || fb == 'D') {
                int n = (np > 0 && p[0] > 0) ? p[0] : 1;
                uint16_t off = get_cursor_nolock();
                uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
                uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
                if (fb == 'A') {
                        if (cy >= (uint32_t)n) cy -= (uint32_t)n; else cy = 0;
                } else if (fb == 'B') {
                        if (cy + (uint32_t)n < MAX_ROWS) cy += (uint32_t)n; else cy = MAX_ROWS - 1;
                } else if (fb == 'C') {
                        if (cx + (uint32_t)n < MAX_COLS) cx += (uint32_t)n; else cx = MAX_COLS - 1;
                } else {
                        if (cx >= (uint32_t)n) cx -= (uint32_t)n; else cx = 0;
                }
                set_cursor_nolock((uint16_t)((cy * MAX_COLS + cx) * 2));
        }
}

static void kputchar_vga_text_nolock(uint8_t character, uint8_t attribute_byte);
static void console_putc_nolock(uint8_t character, uint8_t attribute_byte);
static void kputn_nolock(char ch, int count, uint8_t color);

static int vga_text_ansi_feed_nolock(uint8_t ch, uint8_t attr) {
        if (vga_tx_esc == VGA_TX_ESC_NONE) {
                if (ch == 0x1B) {
                        vga_tx_esc = VGA_TX_ESC;
                        return 1;
                }
                return 0;
        }
        if (vga_tx_esc == VGA_TX_ESC) {
                if (ch == '[') {
                        vga_tx_esc = VGA_TX_CSI;
                        vga_tx_csi_np = 0;
                        vga_tx_csi_cur = 0;
                        return 1;
                }
                if (ch == 'O') {
                        vga_tx_esc = VGA_TX_SS3;
                        return 1;
                }
                vga_tx_esc = VGA_TX_ESC_NONE;
                /* Unknown ESC X — discard (do not paint control glyphs). */
                return 1;
        }
        if (vga_tx_esc == VGA_TX_SS3) {
                vga_tx_esc = VGA_TX_ESC_NONE;
                return 1;
        }
        if (ch >= '0' && ch <= '9') {
                vga_tx_csi_cur = vga_tx_csi_cur * 10 + (ch - '0');
                return 1;
        }
        if (ch == ';') {
                if (vga_tx_csi_np < 8) vga_tx_csi_p[vga_tx_csi_np++] = vga_tx_csi_cur;
                vga_tx_csi_cur = 0;
                return 1;
        }
        if (ch == '?' || ch == '>') {
                return 1;
        }
        if (vga_tx_csi_np < 8) vga_tx_csi_p[vga_tx_csi_np++] = vga_tx_csi_cur;
        vga_tx_csi_cur = 0;
        if ((unsigned char)ch >= 0x40 && (unsigned char)ch <= 0x7E) {
                vga_nolock_csi_dispatch((uint8_t)ch, attr);
        }
        vga_tx_esc = VGA_TX_ESC_NONE;
        vga_tx_csi_np = 0;
        return 1;
}

/* Fast direct VGA helpers */
void vga_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
        if (x >= MAX_COLS || y >= MAX_ROWS) return;
        uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2);
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        write_nolock(ch, attr, off);
        release_irqrestore(&vga_lock_spin, fl);
}

uint8_t vga_get_cell_attr(uint32_t x, uint32_t y) {
        if (cirrusfb_is_ready() || vbe_is_available()) return GRAY_ON_BLACK;
        if (x >= MAX_COLS || y >= MAX_ROWS) return GRAY_ON_BLACK;
        uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2 + 1);
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        uint8_t attr = ((uint8_t *)VIDEO_ADDRESS)[off];
        release_irqrestore(&vga_lock_spin, fl);
        return attr;
}

void vga_clear_line_segment(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr) {
        if (y >= MAX_ROWS) return;
        if (x0 > x1) return;
        if (x1 >= MAX_COLS) x1 = MAX_COLS - 1;
        if (cirrusfb_is_ready()) {
                for (uint32_t x = x0; x <= x1; x++)
                        cirrusfb_putch_xy(x, y, ' ', attr);
        } else if (vbe_is_available()) {
                for (uint32_t x = x0; x <= x1; x++)
                        vbefb_putch_xy(x, y, ' ', attr);
        } else {
                vga_fill_rect(x0, y, x1 - x0 + 1, 1, ' ', attr);
        }
}

void vga_clear_screen_attr(uint8_t attr) {
        if (cirrusfb_is_ready()) {
                cirrusfb_clear(attr);
                return;
        }
        if (vbe_is_available()) {
                vbefb_clear(attr);
                return;
        }
        uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
        uint32_t total = MAX_ROWS * MAX_COLS;
        for (uint32_t i = 0; i < total; i++) {
                vga[i*2] = ' ';
                vga[i*2 + 1] = attr;
        }
}


void vga_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr) {
        if (x >= MAX_COLS || y >= MAX_ROWS || w == 0 || h == 0)
                return;
        if (w > MAX_COLS - x) w = MAX_COLS - x;
        if (h > MAX_ROWS - y) h = MAX_ROWS - y;
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        for (uint32_t ry = 0; ry < h; ry++) {
                for (uint32_t rx = 0; rx < w; rx++) {
                        uint16_t off = (uint16_t)((((y + ry) * MAX_COLS) + x + rx) * 2);
                        write_nolock(ch, attr, off);
                }
        }
        release_irqrestore(&vga_lock_spin, fl);
}

void vga_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr) {
        if (!s || x >= MAX_COLS || y >= MAX_ROWS) return;
        uint32_t cx = x, cy = y;
        uint8_t cur_attr = attr;
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        for (size_t i = 0; s[i] && cy < MAX_ROWS; ) {
                if ((uint8_t)s[i] == 0x1B && s[i + 1] == '[') {
                        i += 2;
                        int nums[16], nnums = 0, cur = 0, hasnum = 0;
                        while (s[i] && s[i] != 'm' && nnums < 16) {
                                if (s[i] >= '0' && s[i] <= '9') {
                                        hasnum = 1;
                                        cur = cur * 10 + (s[i++] - '0');
                                } else if (s[i] == ';') {
                                        nums[nnums++] = cur;
                                        cur = 0;
                                        hasnum = 0;
                                        i++;
                                } else {
                                        i++;
                                }
                        }
                        if (hasnum && nnums < 16) nums[nnums++] = cur;
                        if (s[i] == 'm') i++;
                        if (nnums == 0) cur_attr = GRAY_ON_BLACK;
                        for (int k = 0; k < nnums; k++) {
                                int v = nums[k];
                                if (v == 0) cur_attr = GRAY_ON_BLACK;
                                else if (v == 1) cur_attr |= 0x08;
                                else if (v >= 30 && v <= 37)
                                        cur_attr = (uint8_t)((cur_attr & 0xF0) | (v - 30));
                                else if (v >= 40 && v <= 47)
                                        cur_attr = (uint8_t)(((v - 40) << 4) | (cur_attr & 0x0F));
                                else if (v >= 90 && v <= 97)
                                        cur_attr = (uint8_t)((cur_attr & 0xF0) | (v - 90 + 8));
                                else if (v >= 100 && v <= 107)
                                        cur_attr = (uint8_t)(((v - 100 + 8) << 4) | (cur_attr & 0x0F));
                        }
                        continue;
                }
                uint8_t ch = (uint8_t)s[i++];
                uint32_t count = (ch == '\t') ? (8u - (cx % 8u)) : 1u;
                if (ch == '\t') ch = ' ';
                while (count-- && cy < MAX_ROWS) {
                        write_nolock(ch, cur_attr,
                                     (uint16_t)(((cy * MAX_COLS) + cx) * 2));
                        if (++cx >= MAX_COLS) {
                                cx = 0;
                                cy++;
                        }
                }
        }
        release_irqrestore(&vga_lock_spin, fl);
}

void kprint(uint8_t *str) {
        if (!str) return;
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        while (*str) console_putc_nolock(*str++, GRAY_ON_BLACK);
        if (!cirrusfb_is_ready() && !vbe_is_available())
                flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

static void kputchar_vga_text_nolock(uint8_t character, uint8_t attribute_byte)
{
        uint16_t offset = get_cursor_nolock();
        if (character == '\r')
        {
                /* Carriage return: move to start of current line. */
                set_cursor_nolock((uint16_t)(offset - (offset % (MAX_COLS * 2))));
        }
        if (character == '\n')
        {
                if ((offset / 2 / MAX_COLS) != (MAX_ROWS - 1))
                        set_cursor_nolock((uint16_t)((offset - offset % (MAX_COLS*2)) + MAX_COLS*2));

                /* if we're on last line, perform scroll now */
                if ((offset / 2 / MAX_COLS) == (MAX_ROWS - 1)) {
                        /* scroll */
                        uint8_t i = 1;
                        while (i < MAX_ROWS) {
                                memcpy(
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)), /* dst <- src */
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),         /* src */
                                        (MAX_COLS*2)
                                );
                                i++;
                        }
                        uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
                        for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
                                write_nolock(' ', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
                        }
                        set_cursor_nolock(last_line);
                }
        }
        else if (character == '\t')
        {
                // move to next tab stop (8 columns)
                uint16_t col = (uint16_t)((offset / 2) % MAX_COLS);
                uint16_t spaces = (uint16_t)(8 - (col % 8));
                for (uint16_t i = 0; i < spaces; i++) {
                        if (offset == (MAX_COLS * MAX_ROWS * 2)) {
                                /* scroll */
                                uint8_t i2 = 1;
                                while (i2 < MAX_ROWS) {
                                        memcpy(
                                                (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i2-1) * 2)),
                                                (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i2 * 2)),
                                                (MAX_COLS*2)
                                        );
                                        i2++;
                                }
                                uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
                                for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
                                        write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
                                }
                                set_cursor_nolock(last_line);
                                offset = last_line;
                        }
                        write_nolock(' ', attribute_byte, offset);
                        offset += 2;
                }
                set_cursor_nolock(offset);
        }
        else if (character == '\b' || character == 0x7F)
        {
                /* Non-destructive BS: cursor left only (Linux vt). Do not clear the cell. */
                uint16_t col = (uint16_t)((offset / 2) % MAX_COLS);
                if (col > 0) {
                        offset -= 2;
                        set_cursor_nolock(offset);
                }
        }
        else if (character < 0x20)
        {
                /* Ignore other C0 (BEL/NUL/…) — do not paint CP437 control glyphs. */
                return;
        }
        else
        {
                /* write char and handle end-of-line / scroll correctly */
                if (offset >= (MAX_COLS * MAX_ROWS * 2)) {
                        /* scroll */
                        uint8_t i = 1;
                        while (i < MAX_ROWS) {
                                memcpy(
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)),
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),
                                        (MAX_COLS*2)
                                );
                                i++;
                        }
                        uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
                        for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
                                write_nolock(' ', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
                        }
                        /* reset offset to start of last line */
                        offset = (MAX_ROWS - 1) * MAX_COLS * 2;
                }
                write_nolock(character, attribute_byte, offset);
                uint32_t new_offset = offset + 2;
                if (new_offset >= (MAX_COLS * MAX_ROWS * 2)) {
                        /* writing past the last cell: scroll and set cursor to start of last line */
                        uint8_t i = 1;
                        while (i < MAX_ROWS) {
                                memcpy(
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)),
                                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),
                                        (MAX_COLS*2)
                                );
                                i++;
                        }
                        uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
                        for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
                                write_nolock(' ', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
                        }
                        set_cursor_nolock((uint16_t)((MAX_ROWS - 1) * MAX_COLS * 2));
                } else {
                        set_cursor_nolock((uint16_t)new_offset);
                }
        }
}

/* One character worth of output without taking vga_lock_spin (caller must hold lock). */
static void console_putc_nolock(uint8_t character, uint8_t attribute_byte)
{
        if (cirrusfb_is_ready()) { cirrusfb_putchar(character, attribute_byte); return; }
        if (vbe_is_available()) { vbefb_putchar(character, attribute_byte); return; }
        if (vga_text_ansi_feed_nolock(character, attribute_byte))
                return;
        kputchar_vga_text_nolock(character, attribute_byte);
}

static void kputn_nolock(char ch, int count, uint8_t color)
{
        for (int i = 0; i < count; i++)
                console_putc_nolock((uint8_t)ch, color);
}

void kputchar(uint8_t character, uint8_t attribute_byte)
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        console_putc_nolock(character, attribute_byte);
        if (!cirrusfb_is_ready() && !vbe_is_available())
                flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

void vga_putchar_literal(uint8_t character, uint8_t attribute_byte)
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        kputchar_vga_text_nolock(character, attribute_byte);
        flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

void kprint_colorized(const char* str)
{
        /* Color tags removed: print text literally using default color. */
        kprint((uint8_t*)str);
}

void        scroll_line()
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        uint8_t i = 1;
        uint16_t last_line;

        while (i < MAX_ROWS)
        {
                memcpy(
                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)), /* dst <- src */
                        (uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),         /* src */
                        (MAX_COLS*2)
                );
                i++;
        }

        last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
        i = 0;
        while (i < MAX_COLS)
        {
                write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + i * 2));
                i++;
        }
        set_cursor_nolock(last_line);
        flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

void vga_scroll_region(uint32_t top, uint32_t bottom, uint8_t attr)
{
	if (top >= MAX_ROWS)
		top = MAX_ROWS - 1;
	if (bottom >= MAX_ROWS)
		bottom = MAX_ROWS - 1;
	if (top >= bottom)
		return;

	unsigned long flags;
	acquire_irqsave(&vga_lock_spin, &flags);
	size_t row_bytes = (size_t)MAX_COLS * 2u;
	memmove((void *)(VIDEO_ADDRESS + (uintptr_t)top * row_bytes),
		(const void *)(VIDEO_ADDRESS + (uintptr_t)(top + 1u) * row_bytes),
		(size_t)(bottom - top) * row_bytes);
	for (uint32_t x = 0; x < MAX_COLS; x++) {
		uint16_t offset = (uint16_t)((bottom * MAX_COLS + x) * 2);
		write_nolock(' ', attr, offset);
	}
	release_irqrestore(&vga_lock_spin, flags);
}

void vga_blit_cells(const uint8_t *cells, uint32_t top, uint32_t bottom)
{
	if (!cells || top >= MAX_ROWS)
		return;
	if (bottom >= MAX_ROWS)
		bottom = MAX_ROWS - 1;
	if (top > bottom)
		return;

	const size_t row_bytes = (size_t)MAX_COLS * 2u;
	const size_t bytes = (size_t)(bottom - top + 1u) * row_bytes;
	const uint64_t *src = (const uint64_t *)(cells + (size_t)top * row_bytes);
	volatile uint64_t *dst =
		(volatile uint64_t *)(VIDEO_ADDRESS + (uintptr_t)top * row_bytes);
	unsigned long flags;
	acquire_irqsave(&vga_lock_spin, &flags);
	for (size_t i = 0; i < bytes / sizeof(uint64_t); i++)
		dst[i] = src[i];
	release_irqrestore(&vga_lock_spin, flags);
}

void        kclear()
{
        if (cirrusfb_is_ready()) {
                cirrusfb_clear(WHITE_ON_BLACK);
        } else if (vbe_is_available()) {
                vbefb_clear(WHITE_ON_BLACK);
        } else {
        uint16_t        offset = 0;
        while (offset < (MAX_ROWS * MAX_COLS * 2))
        {
                write('\0', WHITE_ON_BLACK, offset);
                offset += 2;
        }
        set_cursor(0);
        }

        /* Sync devfs TTY cursor to (0,0) so interactive programs don't overwrite.
           kclear is a "global clear" primitive and should affect the active tty. */
        {
                struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
                if (tty) {
                        tty->cursor_x = 0;
                        tty->cursor_y = 0;
                }
        }
        console_set_cursor(0, 0);
}

void kclear_col(uint8_t attribute_byte)
{
        uint16_t offset = 0;
        while (offset < (MAX_ROWS * MAX_COLS * 2))
        {
                write('\0', attribute_byte, offset);
                offset += 2;
        }
        set_cursor(0);
}

void        write(uint8_t character, uint8_t attribute_byte, uint16_t offset)
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        write_nolock(character, attribute_byte, offset);
        release_irqrestore(&vga_lock_spin, fl);
}

uint16_t                get_cursor()
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        uint16_t r = get_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
        return r;
}

void        set_cursor(uint16_t pos)
{
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        set_cursor_nolock(pos);
        flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

// Получить текущую позицию курсора по X
uint16_t get_cursor_x() {
        uint16_t offset = get_cursor();
        return offset % (MAX_COLS * 2);
}

// Получить текущую позицию курсора по Y
uint16_t get_cursor_y() {
        uint16_t offset = get_cursor();
        return offset / (MAX_COLS * 2);
}

// Установить позицию курсора по X
void set_cursor_x(uint16_t x) {
        uint16_t offset = get_cursor();
        uint16_t new_offset = (offset / (MAX_COLS * 2)) * (MAX_COLS * 2) + x * 2;
        set_cursor(new_offset);
}

// Установить позицию курсора по Y
void set_cursor_y(uint16_t y) {
        uint16_t offset = get_cursor();
        uint16_t new_offset = (y * MAX_COLS * 2) + (offset % (MAX_COLS * 2));
        set_cursor(new_offset);
}

void hex_to_str(uint32_t num, char *str);
void hex_to_str(uint32_t num, char *str) {
        int i = 0;

        if (num == 0) {
                str[i++] = '0';
                str[i] = '\0';
                return;
        }

        while (num != 0) {
                uint32_t rem = num % 16;
                if (rem < 10) {
                        str[i++] = rem + '0';
                } else {
                        str[i++] = (rem - 10) + 'A';
                }
                num = num / 16;
        }

        str[i] = '\0';

        // Reverse the string
        int start = 0;
        int end = i - 1;
        while (start < end) {
                char temp = str[start];
                str[start] = str[end];
                str[end] = temp;
                start++;
                end--;
        }
}

static uint8_t parse_color_code(char bg, char fg) {
        uint8_t background = 0;
        uint8_t foreground = 0;

        // Преобразование шестнадцатеричного символа в число
        if (bg >= '0' && bg <= '9') {
                background = bg - '0';
        } else if (bg >= 'a' && bg <= 'f') {
                background = bg - 'a' + 0xa;
        } else if (bg >= 'A' && bg <= 'F') {
                background = bg - 'A' + 0xa;
        }

        if (fg >= '0' && fg <= '9') {
                foreground = fg - '0';
        } else if (fg >= 'a' && fg <= 'f') {
                foreground = fg - 'a' + 0xa;
        } else if (fg >= 'A' && fg <= 'F') {
                foreground = fg - 'A' + 0xa;
        }

        return (background << 4) | foreground;
}

void ftos(double n, char *buf, int precision) {
        int i = 0;
        int sign = 1;
        if (n < 0) {
                sign = -1;
                n = -n;
        }

        double integer_part = (int)n;
        double fractional_part = n - integer_part;

        // Вывод целой части
        while (integer_part > 0) {
                buf[i++] = ((int)integer_part % 10) + '0';
                integer_part /= 10;
        }

        // Вывод точки
        buf[i++] = '.';

        // Вывод дробной части
        for (int j = 0; j < precision; j++) {
                fractional_part *= 10;
                buf[i++] = (int)fractional_part + '0';
                fractional_part -= (int)fractional_part;
        }

        // Добавление знака
        if (sign == -1) {
                buf[i++] = '-';
        }

        // Обратная запись строки
        for (int j = 0; j < i / 2; j++) {
                char temp = buf[j];
                buf[j] = buf[i - j - 1];
                buf[i - j - 1] = temp;
        }

        buf[i] = '\0';
}

static int utoa_rev(unsigned long long v, unsigned base, int upper, char *out)
{
        const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
        int n = 0;
        if (v == 0) { out[n++] = '0'; return n; }
        while (v) { out[n++] = digits[v % base]; v /= base; }
        return n;
}

/* kprintf may bypass /dev/console write(). Drive the active tty so its
 * cursor_x/y (and screen backing) stay aligned with userspace I/O — otherwise
 * the next write(1) / ECHO lands at a stale position (often 0,0). */
static inline void kprintf_putc_locked(struct devfs_tty *tty, uint8_t ch, uint8_t color) {
        if (tty)
                devfs_tty_console_write_locked((const char *)&ch, 1);
        else
                console_putc_nolock(ch, color);
}

static inline void kprintf_putn_locked(struct devfs_tty *tty, uint8_t ch, int count, uint8_t color) {
        for (int i = 0; i < count; i++)
                kprintf_putc_locked(tty, ch, color);
}

void kprintf(const char* fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);

        uint8_t color = 0x07; // светло-серый на чёрном
        /* Keep devfs active tty cursor in sync with framebuffer/VGA backend.
         * Must use console_get/set_cursor (fb-aware), not VGA CRTC ports. */
        struct devfs_tty *tty = NULL;
        if (devfs_is_ready()) {
                tty = devfs_get_tty_by_index(devfs_get_active());
        }
        unsigned long output_fl;
        if (tty) {
                /*
                 * Same lock order as userspace: tty output lock, then backend lock.
                 * Previously kprintf held vga_lock first and mutated the userspace
                 * ANSI state without out_lock, allowing printk to eat child byte 0.
                 */
                acquire_irqsave(&tty->out_lock, &output_fl);
                console_set_cursor(tty->cursor_x, tty->cursor_y);
                /* Keep nested one-byte printk writes in one VGA cursor batch. */
                console_begin_tty_batch();
        } else {
                acquire_irqsave(&vga_lock_spin, &output_fl);
        }
        for (const char *p = fmt; *p; ) {
                // Color tags are no longer supported; treat them as normal characters.
                // support tab character: move to next tab stop (8 columns) like Linux
                if (*p == '\t') {
                        uint32_t cx = 0, cy = 0;
                        if (tty) {
                                cx = tty->cursor_x;
                                cy = tty->cursor_y;
                        } else {
                                console_get_cursor(&cx, &cy);
                        }
                        uint32_t spaces = 8u - (cx % 8u);
                        if (spaces == 0) spaces = 8;
                        kprintf_putn_locked(tty, ' ', (int)spaces, color);
                        (void)cy;
                        p++; continue;
                }

                if (*p != '%') { kprintf_putc_locked(tty, (uint8_t)*p++, color); continue; }
                 p++;
                // flags
                 int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
                 for (;;){
                         if (*p == '-') { left = 1; p++; }
                         else if (*p == '+') { plus = 1; p++; }
                         else if (*p == ' ') { space = 1; p++; }
                         else if (*p == '#') { alt = 1; p++; }
                         else if (*p == '0') { zero = 1; p++; }
                         else break;
                 }
                 // width
                 int width = 0;
                 if (*p == '*') { width = va_arg(ap, int); p++; }
                 else while (*p >= '0' && *p <= '9') { width = width*10 + (*p++ - '0'); }
                 // precision
                 int prec = -1;
                 if (*p == '.') {
                         p++;
                         if (*p == '*') { prec = va_arg(ap, int); p++; }
                         else { prec = 0; while (*p >= '0' && *p <= '9') prec = prec*10 + (*p++ - '0'); }
                 }
                 // совместимость с нестандартным %10-4x (ширина-точность)
                 if (prec < 0 && *p == '-') {
                         p++;
                         prec = 0; while (*p >= '0' && *p <= '9') prec = prec*10 + (*p++ - '0');
                 }
                 // length (минимальный набор)
                 enum { LEN_DEF, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z } len = LEN_DEF;
                 if (*p == 'h') { p++; if (*p == 'h') { len = LEN_HH; p++; } else len = LEN_H; }
                 else if (*p == 'l') { p++; if (*p == 'l') { len = LEN_LL; p++; } else len = LEN_L; }
                 else if (*p == 'z') { len = LEN_Z; p++; }

                 char spec = *p ? *p++ : '\0';
                 char tmp[64];
                 int tmplen = 0;
                 int negative = 0;
                 char signch = 0;

                 switch (spec) {
                 case 'c': {
                         int ch = va_arg(ap, int);
                         int pad = (width > 1) ? width - 1 : 0;
                         if (!left) kprintf_putn_locked(tty, ' ', pad, color);
                         kprintf_putc_locked(tty, (uint8_t)ch, color);
                         if (left) kprintf_putn_locked(tty, ' ', pad, color);
                         break; }

                 case 's': {
                         const char *s = va_arg(ap, const char*);
                         if (!s) s = "(null)";
                         int slen = 0; while (s[slen]) slen++;
                         if (prec >= 0 && prec < slen) slen = prec;
                         int pad = (width > slen) ? width - slen : 0;
                         if (!left) kprintf_putn_locked(tty, ' ', pad, color);
                         for (int i = 0; i < slen; i++) kprintf_putc_locked(tty, (uint8_t)s[i], color);
                         if (left) kprintf_putn_locked(tty, ' ', pad, color);
                         break; }

                 case 'd': case 'i': {
                         long long v;
                         if (len == LEN_LL) v = va_arg(ap, long long);
                         else if (len == LEN_L) v = va_arg(ap, long);
                         else v = va_arg(ap, int);
                         unsigned long long u = (v < 0) ? (unsigned long long)(-v) : (unsigned long long)v;
                         negative = (v < 0);
                         tmplen = utoa_rev(u, 10, 0, tmp);
                         signch = negative ? '-' : (plus ? '+' : (space ? ' ' : 0));
                         goto PRINT_NUMBER_BASE10;
                 }

                 case 'u': case 'x': case 'X': case 'o': case 'p': {
                         unsigned base = 10; int upper = 0;
                         unsigned long long u;
                         if (spec == 'p') { u = (unsigned long long)(uintptr_t)va_arg(ap, void*); base = 16; alt = 1; }
                         else {
                                 if (len == LEN_LL) u = va_arg(ap, unsigned long long);
                                 else if (len == LEN_L) u = va_arg(ap, unsigned long);
                                 else if (len == LEN_Z) u = va_arg(ap, size_t);
                                 else u = va_arg(ap, unsigned int);
                                 if (spec == 'x' || spec == 'X') { base = 16; upper = (spec == 'X'); }
                                 else if (spec == 'o') { base = 8; }
                         }
                         tmplen = utoa_rev(u, base, upper, tmp);
                         signch = 0;

                         // точность для целых
                         int num_digits = tmplen;
                         int prec_zeros = 0;
                         if (prec >= 0) {
                                 zero = 0; // при точности флаг 0 игнорируется
                                 if (prec > num_digits) prec_zeros = prec - num_digits;
                         }

                         // префиксы
                         char prefix[2]; int plen = 0;
                         if (alt && base == 16 && u != 0) { prefix[0] = '0'; prefix[1] = (upper ? 'X' : 'x'); plen = 2; }
                         else if (alt && base == 8 && (u != 0 || prec == 0)) { prefix[0] = '0'; plen = 1; }

                         int field_len = plen + prec_zeros + num_digits;
                         int pad = (width > field_len) ? width - field_len : 0;
                         char padch = (zero && !left) ? '0' : ' ';

                        if (!left && padch == ' ') kprintf_putn_locked(tty, ' ', pad, color);
                        // вывод префикса/нулями заполнение
                        if (!left && padch == '0') kprintf_putn_locked(tty, '0', pad, color);
                        if (plen) { for (int i = 0; i < plen; i++) kprintf_putc_locked(tty, (uint8_t)prefix[i], color); }
                        kprintf_putn_locked(tty, '0', prec_zeros, color);
                        for (int i = num_digits - 1; i >= 0; i--) kprintf_putc_locked(tty, (uint8_t)tmp[i], color);
                        if (left) kprintf_putn_locked(tty, ' ', pad, color);
                        break; }

                case '%':
                        kprintf_putc_locked(tty, '%', color);
                        break;

                 default:
                        kprintf_putc_locked(tty, (uint8_t)spec, color);
                         break;

PRINT_NUMBER_BASE10:
                 {
                         int num_digits = tmplen;
                         int prec_zeros = 0;
                         if (prec >= 0) { zero = 0; if (prec > num_digits) prec_zeros = prec - num_digits; }
                         int sign_len = signch ? 1 : 0;
                         int field_len = sign_len + prec_zeros + num_digits;
                         int pad = (width > field_len) ? width - field_len : 0;
                         char padch = (zero && !left) ? '0' : ' ';
                        if (!left && padch == ' ' ) kprintf_putn_locked(tty, ' ', pad, color);
                        if (signch) kprintf_putc_locked(tty, (uint8_t)signch, color);
                        if (!left && padch == '0') kprintf_putn_locked(tty, '0', pad, color);
                        kprintf_putn_locked(tty, '0', prec_zeros, color);
                        for (int i = num_digits - 1; i >= 0; i--) kprintf_putc_locked(tty, (uint8_t)tmp[i], color);
                        if (left) kprintf_putn_locked(tty, ' ', pad, color);
                         break;
                 }
                 }
         }

        if (tty) {
                console_end_tty_batch();
                release_irqrestore(&tty->out_lock, output_fl);
        } else {
                if (!cirrusfb_is_ready() && !vbe_is_available())
                        flush_cursor_nolock();
                release_irqrestore(&vga_lock_spin, output_fl);
        }
        va_end(ap);
}

void vga_set_cursor(uint32_t x, uint32_t y) {
        if (cirrusfb_is_ready()) { cirrusfb_set_cursor(x, y); return; }
        if (vbe_is_available()) { vbefb_set_cursor(x, y); return; }
        if (x >= MAX_COLS) x = MAX_COLS - 1;
        if (y >= MAX_ROWS) y = MAX_ROWS - 1;
        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        set_cursor_nolock((uint16_t)(((y * MAX_COLS) + x) * 2));
        flush_cursor_nolock();
        release_irqrestore(&vga_lock_spin, fl);
}

void vga_update_cursor(void) {
        uint32_t hz = timer_frequency ? timer_frequency : 250u;
        uint32_t quarter_period = (hz + 3u) / 4u;
        if (quarter_period < 1u) quarter_period = 1u;
        uint64_t phase = timer_ticks / quarter_period;
        if (phase == vga_cursor_last_phase) return;
        vga_cursor_last_phase = phase;
        int visible = ((phase & 1ULL) == 0ULL);
        if (visible == vga_cursor_visible) return;
        vga_cursor_visible = visible;

        unsigned long fl;
        acquire_irqsave(&vga_lock_spin, &fl);
        outb(REG_SCREEN_CTRL, 0x0A);
        uint8_t start = inb(REG_SCREEN_DATA);
        outb(REG_SCREEN_DATA, visible ? (uint8_t)(start & ~0x20u)
                                     : (uint8_t)(start | 0x20u));
        release_irqrestore(&vga_lock_spin, fl);
}

void vga_get_cursor(uint32_t* x, uint32_t* y) {
        if (cirrusfb_is_ready()) { cirrusfb_get_cursor(x, y); return; }
        if (vbe_is_available()) { vbefb_get_cursor(x, y); return; }
        uint16_t pos = get_cursor();
        if (x) *x = (pos % (MAX_COLS * 2)) / 2;
        if (y) *y = pos / (MAX_COLS * 2);
}

uint16_t cell_offset(uint8_t x, uint8_t y) {
        return (uint16_t)((y * MAX_COLS + x) * 2);
}

void draw_cell(uint8_t x, uint8_t y, uint8_t ch, uint8_t color) {
        write(ch, color, cell_offset(x, y));
}

void draw_text(uint8_t x, uint8_t y, const char* s, uint8_t color) {
        for (uint8_t i = 0; s[i]; i++) draw_cell(x + i, y, (uint8_t)s[i], color);
}

/* Set hardware cursor shape (scanline start/end). */
void set_cursor_shape(uint8_t start, uint8_t end) {
        outb(REG_SCREEN_CTRL, 0x0A);
        outb(REG_SCREEN_DATA, start & 0x1F);
        outb(REG_SCREEN_CTRL, 0x0B);
        outb(REG_SCREEN_DATA, end & 0x1F);
}

// ---- minimal printf-to-buffer (vsnprintf/snprintf/sprintf) ----
typedef struct { char* buf; size_t cap; size_t len; } __bufw;
static void __bw_putc(__bufw* w, char ch) {
        if (w->len + 1 < w->cap) w->buf[w->len] = ch;
        w->len++;
}

static void __bw_putn(__bufw* w, char ch, int count) {
        for (int i = 0; i < count; i++) __bw_putc(w, ch);
}

static void __bw_putstrn(__bufw* w, const char* s, int slen) {
        for (int i = 0; i < slen; i++) __bw_putc(w, s[i]);
}

int __vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap_in) {
        if (!out || outsz==0) return 0;
        __bufw W = { .buf = out, .cap = outsz, .len = 0 };
        va_list ap; va_copy(ap, ap_in);
        for (const char *p = fmt; *p; ) {
                if (*p != '%') { __bw_putc(&W, *p++); continue; }
                p++;

                /* flags */
                int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
                for (;;) {
                        if (*p == '-') { left = 1; p++; }
                        else if (*p == '+') { plus = 1; p++; }
                        else if (*p == ' ') { space = 1; p++; }
                        else if (*p == '#') { alt = 1; p++; }
                        else if (*p == '0') { zero = 1; p++; }
                        else break;
                }

                /* width */
                int width = 0;
                if (*p == '*') { width = va_arg(ap, int); p++; }
                else while (*p >= '0' && *p <= '9') { width = width * 10 + (*p++ - '0'); }
                if (width < 0) { left = 1; width = -width; }

                /* precision */
                int prec = -1;
                if (*p == '.') {
                        p++;
                        if (*p == '*') { prec = va_arg(ap, int); p++; }
                        else { prec = 0; while (*p >= '0' && *p <= '9') prec = prec * 10 + (*p++ - '0'); }
                }

                /* length */
                enum { LEN_DEF, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z } len = LEN_DEF;
                if (*p == 'h') { p++; if (*p == 'h') { len = LEN_HH; p++; } else len = LEN_H; }
                else if (*p == 'l') { p++; if (*p == 'l') { len = LEN_LL; p++; } else len = LEN_L; }
                else if (*p == 'z') { len = LEN_Z; p++; }

                char spec = *p ? *p++ : '\0';

                char num[64];
                int n = 0;

                switch (spec) {
                case 'c': {
                        int ch = va_arg(ap, int);
                        int pad = (width > 1) ? width - 1 : 0;
                        if (!left) __bw_putn(&W, ' ', pad);
                        __bw_putc(&W, (char)ch);
                        if (left) __bw_putn(&W, ' ', pad);
                        break; }

                case 's': {
                        const char *s = va_arg(ap, const char*);
                        if (!s) s = "(null)";
                        int slen = 0; while (s[slen]) slen++;
                        if (prec >= 0 && prec < slen) slen = prec;
                        int pad = (width > slen) ? width - slen : 0;
                        if (!left) __bw_putn(&W, ' ', pad);
                        __bw_putstrn(&W, s, slen);
                        if (left) __bw_putn(&W, ' ', pad);
                        break; }

                        case 'd': case 'i': {
                        long long v;
                        if (len == LEN_LL) v = va_arg(ap, long long);
                        else if (len == LEN_L) v = va_arg(ap, long);
                        else if (len == LEN_Z) v = (long long)va_arg(ap, size_t);
                        else v = va_arg(ap, int);
                        unsigned long long u = (v < 0) ? (unsigned long long)(-v) : (unsigned long long)v;
                        n = utoa_rev(u, 10, 0, num);
                        char signch = 0;
                        if (v < 0) signch = '-';
                        else if (plus) signch = '+';
                        else if (space) signch = ' ';
                        int digits = n;
                        int tot = digits + (signch ? 1 : 0);
                        int pad = (width > tot) ? width - tot : 0;
                        char padch = (zero && !left && prec < 0) ? '0' : ' ';
                        if (!left) __bw_putn(&W, padch, pad);
                        if (signch) __bw_putc(&W, signch);
                        for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
                        if (left) __bw_putn(&W, ' ', pad);
                        break; }

                        case 'u': case 'x': case 'X': {
                        unsigned base = (spec == 'u') ? 10u : 16u;
                        int upper = (spec == 'X');
                        unsigned long long u;
                        if (len == LEN_LL) u = va_arg(ap, unsigned long long);
                        else if (len == LEN_L) u = va_arg(ap, unsigned long);
                        else if (len == LEN_Z) u = (unsigned long long)va_arg(ap, size_t);
                        else u = va_arg(ap, unsigned int);
                        n = utoa_rev(u, base, upper, num);
                        int prefix = 0;
                        if (alt && base == 16 && u != 0) prefix = 2;
                        int tot = n + prefix;
                        int pad = (width > tot) ? width - tot : 0;
                        char padch = (zero && !left && prec < 0) ? '0' : ' ';
                        if (!left) __bw_putn(&W, padch, pad);
                        if (prefix) { __bw_putc(&W, '0'); __bw_putc(&W, upper ? 'X' : 'x'); }
                        for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
                        if (left) __bw_putn(&W, ' ', pad);
                        break; }

                case 'p': {
                        void *pv = va_arg(ap, void*);
                        unsigned long long u = (unsigned long long)(uintptr_t)pv;
                        n = utoa_rev(u, 16, 0, num);
                        /* always 0x prefix */
                        int tot = n + 2;
                        int pad = (width > tot) ? width - tot : 0;
                        if (!left) __bw_putn(&W, ' ', pad);
                        __bw_putc(&W, '0'); __bw_putc(&W, 'x');
                        for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
                        if (left) __bw_putn(&W, ' ', pad);
                        break; }

                case '%': __bw_putc(&W, '%'); break;
                default:
                        /* unknown specifier: print it literally to avoid desync */
                        __bw_putc(&W, '%');
                        __bw_putc(&W, spec);
                                break;
                }
        }
        // NUL
        if (W.len < W.cap) W.buf[W.len] = '\0'; else W.buf[W.cap-1] = '\0';
        va_end(ap);
        return (int)W.len;
}

void enable_cursor() {
        outb(0x3D4, 0x0A);
        char curstart = inb(0x3D5) & 0x1F; // cursor scanline start (bits 0-4)

        // Clear bit 5 (cursor disable) to enable the cursor
        outb(0x3D4, 0x0A);
        outb(0x3D5, (curstart & ~0x20));

        // custom shape!
        set_cursor_shape(14, 15);
}

int vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap) { return __vsnprintf(out, outsz, fmt, ap); }
int snprintf(char* out, size_t outsz, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,outsz,fmt,ap); va_end(ap); return r; }
int sprintf(char* out, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,(size_t)-1,fmt,ap); va_end(ap); return r; }