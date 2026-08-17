#include <console.h>
#include <vbe.h>
#include <vga.h>
#include <stdint.h>
#include <cirrusfb.h>
#include <devfs.h>
#include <font.h>

void console_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
	if (cirrusfb_is_ready()) {
		cirrusfb_putch_xy(x, y, ch, attr);
	} else if (vbe_is_available()) {
		vbefb_putch_xy(x, y, ch, attr);
	} else {
		vga_putch_xy(x, y, ch, attr);
	}
}

int console_max_rows() {
	if (cirrusfb_is_ready()) {
		return (int)cirrusfb_rows();
	}
	if (vbe_is_available()) {
		uint32_t h = vbe_get_height();
		uint32_t fh = font_cell_height();
		if (fh == 0) return MAX_ROWS;
		return (int)(h / fh);
	}
	return MAX_ROWS;
}

int console_max_cols() {
	if (cirrusfb_is_ready()) {
		return (int)cirrusfb_cols();
	}
	if (vbe_is_available()) {
		uint32_t w = vbe_get_width();
		uint32_t fw = font_cell_width();
		if (fw == 0) return MAX_COLS;
		return (int)(w / fw);
	}
	return MAX_COLS;
}

void console_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr) {
	if (cirrusfb_is_ready()) {
		uint8_t run[256];
		cirrusfb_begin_batch();
		for (uint32_t ry = 0; ry < h; ry++) {
			uint32_t left = w;
			uint32_t cx = x;
			while (left) {
				uint32_t n = left > (uint32_t)sizeof(run) ? (uint32_t)sizeof(run) : left;
				for (uint32_t i = 0; i < n; i++)
					run[i] = ch;
				cirrusfb_putch_run(cx, y + ry, run, n, attr);
				cx += n;
				left -= n;
			}
		}
		cirrusfb_end_batch();
		return;
	}
	if (vbe_is_available()) {
		vbefb_begin_batch();
		for (uint32_t ry = 0; ry < h; ry++) {
			for (uint32_t rx = 0; rx < w; rx++)
				vbefb_putch_xy(x + rx, y + ry, ch, attr);
		}
		vbefb_end_batch();
	} else {
		for (uint32_t ry = 0; ry < h; ry++) {
			for (uint32_t rx = 0; rx < w; rx++) {
				vga_putch_xy(x + rx, y + ry, ch, attr);
			}
		}
	}
}

void console_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr) {
	if (!s) return;
	if (cirrusfb_is_ready()) {
		uint32_t cx = x, cy = y;
		uint32_t maxc = (uint32_t)console_max_cols();
		cirrusfb_begin_batch();
		for (size_t i = 0; s[i]; ) {
			if (s[i] == '\t') {
				uint32_t n = 8 - (cx % 8);
				if (n == 0) n = 8;
				for (uint32_t k = 0; k < n; k++) {
					cirrusfb_putch_xy(cx, cy, ' ', attr);
					cx++;
					if (cx >= maxc) { cx = 0; cy++; }
				}
				i++;
				continue;
			}
			/* Coalesce printable runs on one row — one dirty rect. */
			size_t j = i;
			while (s[j] && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' &&
			       cx + (uint32_t)(j - i) < maxc)
				j++;
			if (j > i) {
				cirrusfb_putch_run(cx, cy, (const uint8_t *)s + i,
						   (uint32_t)(j - i), attr);
				cx += (uint32_t)(j - i);
				i = j;
				if (cx >= maxc) { cx = 0; cy++; }
				continue;
			}
			cirrusfb_putch_xy(cx, cy, (uint8_t)s[i], attr);
			i++;
			cx++;
			if (cx >= maxc) { cx = 0; cy++; }
		}
		cirrusfb_end_batch();
	} else if (vbe_is_available()) {
		uint32_t cx = x, cy = y;
		vbefb_begin_batch();
		for (size_t i = 0; s[i]; ) {
			if (s[i] == 0x1B && s[i+1] == '[') {
				size_t j = i;
				while (s[j] && s[j] != 'm') j++;
				if (s[j] == 'm') {
					for (size_t k = i; k <= j; k++) {
						vbefb_putchar((uint8_t)s[k], attr);
					}
					i = j + 1;
					continue;
				}
			}
			if (s[i] == '\t') {
				uint32_t n = 8 - (cx % 8);
				if (n == 0) n = 8;
				for (uint32_t k = 0; k < n; k++) {
					vbefb_set_cursor(cx, cy);
					vbefb_putchar(' ', attr);
					cx++;
					if (cx >= (uint32_t)console_max_cols()) { cx = 0; cy++; }
				}
				i++;
				continue;
			}
			vbefb_set_cursor(cx, cy);
			vbefb_putchar((uint8_t)s[i], attr);
			i++;
			cx++;
			if (cx >= (uint32_t)console_max_cols()) { cx = 0; cy++; }
		}
		vbefb_end_batch();
	} else {
		vga_write_str_xy(x, y, s, attr);
	}
}

/* Defer VGA CRTC cursor ports across one tty write (nano redraw). */
static int g_tty_batch = 0;
static int g_tty_cursor_pending = 0;
static uint32_t g_tty_cursor_x = 0, g_tty_cursor_y = 0;

void console_begin_tty_batch(void) {
	g_tty_batch++;
	/* The framebuffer backend must see only the outermost batch. */
	if (g_tty_batch > 1)
		return;
	if (cirrusfb_is_ready())
		cirrusfb_begin_batch();
	else if (vbe_is_available())
		vbefb_begin_batch();
}

void console_end_tty_batch(void) {
	if (g_tty_batch <= 0)
		return;
	g_tty_batch--;
	if (g_tty_batch > 0)
		return;
	if (g_tty_cursor_pending) {
		g_tty_cursor_pending = 0;
		if (cirrusfb_is_ready())
			cirrusfb_set_cursor(g_tty_cursor_x, g_tty_cursor_y);
		else if (vbe_is_available())
			vbefb_set_cursor(g_tty_cursor_x, g_tty_cursor_y);
		else
			vga_set_cursor(g_tty_cursor_x, g_tty_cursor_y);
	}
	if (cirrusfb_is_ready())
		cirrusfb_end_batch();
	else if (vbe_is_available())
		vbefb_end_batch();
}

void console_set_cursor(uint32_t x, uint32_t y) {
	if (g_tty_batch > 0) {
		/* Record only — apply once in console_end_tty_batch(). */
		g_tty_cursor_x = x;
		g_tty_cursor_y = y;
		g_tty_cursor_pending = 1;
		return;
	}
	if (cirrusfb_is_ready()) { cirrusfb_set_cursor(x,y); return; }
	if (vbe_is_available()) { vbefb_set_cursor(x,y); return; }
	vga_set_cursor(x,y);
}

void console_get_cursor(uint32_t *x, uint32_t *y) {
	if (cirrusfb_is_ready()) { cirrusfb_get_cursor(x,y); return; }
	if (vbe_is_available()) { vbefb_get_cursor(x,y); return; }
	vga_get_cursor(x,y);
}

static void console_sync_active_tty_home(void) {
	if (!devfs_is_ready())
		return;
	struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
	if (!tty)
		return;
	tty->cursor_x = 0;
	tty->cursor_y = 0;
}

void console_clear_screen_attr(uint8_t attr) {
	if (cirrusfb_is_ready()) {
		cirrusfb_clear(attr);
		console_set_cursor(0, 0);
		return;
	}
	if (vbe_is_available()) {
		vbefb_clear(attr);
		console_sync_active_tty_home();
		console_set_cursor(0, 0);
		return;
	}
	vga_clear_screen_attr(attr);
	console_sync_active_tty_home();
	console_set_cursor(0, 0);
}

void console_clear_line_segment(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr) {
	if (cirrusfb_is_ready()) {
		if (x0 > x1) return;
		for (uint32_t x = x0; x <= x1; x++)
			cirrusfb_putch_xy(x, y, ' ', attr);
		return;
	}
	if (vbe_is_available()) {
		if (x0 > x1) return;
		vbefb_begin_batch();
		for (uint32_t x = x0; x <= x1; x++)
			vbefb_putch_xy(x, y, ' ', attr);
		vbefb_end_batch();
		return;
	}
	vga_clear_line_segment(x0, x1, y, attr);
}

void console_scroll_region_up(uint32_t top, uint32_t bottom, uint8_t attr)
{
	if (cirrusfb_is_ready()) {
		cirrusfb_scroll_region(top, bottom);
		return;
	}
	if (vbe_is_available()) {
		vbefb_scroll_region(top, bottom, attr);
		return;
	}
	vga_scroll_region(top, bottom, attr);
}

uint8_t console_get_cell_attr(uint32_t x, uint32_t y) {
	if (cirrusfb_is_ready())
		return cirrusfb_get_cell_attr(x, y);
	if (vbe_is_available())
		return 0x07;
	return vga_get_cell_attr(x, y);
}

void console_putc_tty_literal(uint8_t ch, uint8_t attr) {
	if (cirrusfb_is_ready()) {
		cirrusfb_putchar_literal(ch, attr);
		return;
	}
	if (vbe_is_available()) {
		vbefb_putchar_literal(ch, attr);
		return;
	}
	/* Bypass VGA ANSI FSM — '[' from klog timestamps must not complete a stale ESC. */
	vga_putchar_literal(ch, attr);
}
