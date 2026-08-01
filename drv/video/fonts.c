#include <font.h>
#include <string.h>
#include <heap.h>
#include <klog.h>
#include <cirrusfb.h>

#define FONTS_DEFAULT_8X16_DEFINE 1
#include <fonts/default_8x16.h>

/* Embedded ascii.pf2 (makefile blob). Weak so a missing blob still links. */
extern const uint8_t ascii_pf2_blob_start[] __attribute__((weak));
extern const uint8_t ascii_pf2_blob_end[] __attribute__((weak));

static struct font g_font;
static uint8_t g_default_bits[FONT_GLYPH_CACHE * 16];
static int g_ready;

static void font_build_default_bits(void) {
	memset(g_default_bits, 0, sizeof(g_default_bits));
	for (unsigned ch = 0; ch < 256; ch++) {
		uint8_t *dst = g_default_bits + ch * 16u;
		for (unsigned row = 0; row < 16; row++)
			dst[row] = font8x16[ch][row];
	}
}

void font_init_default(void) {
	font_build_default_bits();
	memset(&g_font, 0, sizeof(g_font));
	g_font.cwidth = 8;
	g_font.cheight = 16;
	g_font.ascent = 14;
	g_font.descent = 2;
	g_font.bits = g_default_bits;
	g_font.stride = 1;
	g_font.bits_bytes = sizeof(g_default_bits);
	g_font.bits_owned = 0;
	strncpy(g_font.name, "default_8x16", sizeof(g_font.name) - 1);
	g_ready = 1;
}

const struct font *font_current(void) {
	if (!g_ready)
		font_init_default();
	return &g_font;
}

uint32_t font_cell_width(void) {
	const struct font *f = font_current();
	return f->cwidth ? f->cwidth : 8;
}

uint32_t font_cell_height(void) {
	const struct font *f = font_current();
	return f->cheight ? f->cheight : 16;
}

int font_set(const struct font *f) {
	if (!f || !f->bits || f->cwidth == 0 || f->cheight == 0 || f->stride == 0)
		return -1;
	if (!g_ready)
		font_init_default();
	if (g_font.bits_owned && g_font.bits && g_font.bits != g_default_bits)
		kfree(g_font.bits);
	g_font = *f;
	return 0;
}

void font_try_embedded_pf2(void) {
	if (!g_ready)
		font_init_default();
	if (!ascii_pf2_blob_start || !ascii_pf2_blob_end)
		return;
	if ((uintptr_t)ascii_pf2_blob_end <= (uintptr_t)ascii_pf2_blob_start)
		return;
	size_t n = (size_t)(ascii_pf2_blob_end - ascii_pf2_blob_start);
	if (n < 32 || n > (2u * 1024u * 1024u))
		return;
	if (font_load_pf2(ascii_pf2_blob_start, n) != 0)
		klogprintf("font: embedded ascii.pf2 failed — keeping %s\n", g_font.name);
}

void font_try_load_console_pf2(void) {
	/*
	 * Only an explicit console font.  Do NOT load /usr/share/grub/*.pf2:
	 * grub-install drops ascii.pf2/euro.pf2 with MAXW=16 half-width glyphs;
	 * using them as fbcon cell metrics leaves a full glyph of empty space
	 * between every character ("s p a c e d" text) after the initfs grows.
	 */
	static const char *const paths[] = {
		"/etc/fonts/console.pf2",
		"/lib/fonts/console.pf2",
		NULL
	};
	for (int i = 0; paths[i]; i++) {
		if (font_load_pf2_path(paths[i]) == 0)
			return;
	}
}

static inline const uint8_t *glyph_rows(unsigned ch) {
	const struct font *f = font_current();
	if (ch >= FONT_GLYPH_CACHE)
		ch = 0;
	return f->bits + (uint32_t)ch * (f->stride * f->cheight);
}

static inline void put_pix(uint8_t *line, uint32_t bpp, uint32_t x, uint32_t pix) {
	if (bpp == 4)
		((uint32_t *)line)[x] = pix;
	else if (bpp == 3) {
		line[x * 3 + 0] = (uint8_t)(pix & 0xFF);
		line[x * 3 + 1] = (uint8_t)((pix >> 8) & 0xFF);
		line[x * 3 + 2] = (uint8_t)((pix >> 16) & 0xFF);
	} else if (bpp == 2)
		((uint16_t *)line)[x] = (uint16_t)pix;
}

static void font_blit_glyph_generic(void *fb, uint32_t pitch, uint32_t bpp_bytes,
				    uint32_t px, uint32_t py, uint8_t ch,
				    uint32_t fg, uint32_t bg) {
	const struct font *f = font_current();
	const uint8_t *rows = glyph_rows(ch);
	uint32_t w = f->cwidth;
	uint32_t h = f->cheight;
	uint32_t stride = f->stride;
	for (uint32_t row = 0; row < h; row++) {
		const uint8_t *srow = rows + row * stride;
		uint8_t *line = (uint8_t *)fb + (size_t)(py + row) * pitch + px * bpp_bytes;
		for (uint32_t col = 0; col < w; col++) {
			uint8_t bit = srow[col >> 3] & (uint8_t)(0x80u >> (col & 7));
			put_pix(line, bpp_bytes, col, bit ? fg : bg);
		}
	}
}

/* Branchless fg/bg select — keeps the glyph loop free of mispredicts. */
static inline uint32_t font_pix(uint32_t bits, uint32_t mask, uint32_t fg, uint32_t bg) {
	uint32_t m = (uint32_t)-(int32_t)((bits & mask) != 0);
	return (fg & m) | (bg & ~m);
}

static inline void font_store8_32(uint32_t *line, uint8_t bits, uint32_t fg, uint32_t bg) {
	/*
	 * Two uint64 stores (8 pixels). line is always 4-byte aligned from
	 * px*4; for even px it is also 8-byte aligned.
	 */
	uint32_t p0 = font_pix(bits, 0x80u, fg, bg);
	uint32_t p1 = font_pix(bits, 0x40u, fg, bg);
	uint32_t p2 = font_pix(bits, 0x20u, fg, bg);
	uint32_t p3 = font_pix(bits, 0x10u, fg, bg);
	uint32_t p4 = font_pix(bits, 0x08u, fg, bg);
	uint32_t p5 = font_pix(bits, 0x04u, fg, bg);
	uint32_t p6 = font_pix(bits, 0x02u, fg, bg);
	uint32_t p7 = font_pix(bits, 0x01u, fg, bg);
	*(uint64_t *)(line + 0) = ((uint64_t)p1 << 32) | p0;
	*(uint64_t *)(line + 2) = ((uint64_t)p3 << 32) | p2;
	*(uint64_t *)(line + 4) = ((uint64_t)p5 << 32) | p4;
	*(uint64_t *)(line + 6) = ((uint64_t)p7 << 32) | p6;
}

static void font_fill_cell_32(void *fb, uint32_t pitch, uint32_t px, uint32_t py,
			      uint32_t w, uint32_t h, uint32_t bg) {
	uint64_t pair = ((uint64_t)bg << 32) | bg;
	for (uint32_t row = 0; row < h; row++) {
		uint32_t *line = (uint32_t *)((uint8_t *)fb +
			(size_t)(py + row) * pitch + px * 4u);
		uint32_t col = 0;
		for (; col + 2u <= w; col += 2u)
			*(uint64_t *)(line + col) = pair;
		if (col < w)
			line[col] = bg;
	}
}

void font_blit_glyph_32(void *fb, uint32_t pitch, uint32_t px, uint32_t py,
			uint8_t ch, uint32_t fg, uint32_t bg) {
	const struct font *f = font_current();
	const uint8_t *rows = glyph_rows(ch);
	uint32_t w = f->cwidth;
	uint32_t h = f->cheight;
	uint32_t stride = f->stride;

	/* Space / blank: solid bg fill (very common in clears and scrolls). */
	if (fg == bg || ch == ' ' || ch == 0) {
		font_fill_cell_32(fb, pitch, px, py, w, h, bg);
		return;
	}

	if (w == 8 && stride == 1) {
		uint8_t *base = (uint8_t *)fb + (size_t)py * pitch + px * 4u;
		for (uint32_t row = 0; row < h; row++) {
			uint8_t bits = rows[row];
			if (bits == 0) {
				uint64_t pair = ((uint64_t)bg << 32) | bg;
				uint64_t *q = (uint64_t *)(base + (size_t)row * pitch);
				q[0] = pair;
				q[1] = pair;
				q[2] = pair;
				q[3] = pair;
			} else if (bits == 0xFFu) {
				uint64_t pair = ((uint64_t)fg << 32) | fg;
				uint64_t *q = (uint64_t *)(base + (size_t)row * pitch);
				q[0] = pair;
				q[1] = pair;
				q[2] = pair;
				q[3] = pair;
			} else {
				font_store8_32((uint32_t *)(base + (size_t)row * pitch),
					       bits, fg, bg);
			}
		}
		return;
	}

	if (w == 16 && stride == 2) {
		uint8_t *base = (uint8_t *)fb + (size_t)py * pitch + px * 4u;
		for (uint32_t row = 0; row < h; row++) {
			uint8_t b0 = rows[row * 2u];
			uint8_t b1 = rows[row * 2u + 1u];
			uint32_t *line = (uint32_t *)(base + (size_t)row * pitch);
			font_store8_32(line, b0, fg, bg);
			font_store8_32(line + 8, b1, fg, bg);
		}
		return;
	}

	font_blit_glyph_generic(fb, pitch, 4, px, py, ch, fg, bg);
}

void font_blit_glyph(void *fb, uint32_t pitch, uint32_t bpp_bytes,
		     uint32_t px, uint32_t py, uint8_t ch,
		     uint32_t fg, uint32_t bg) {
	if (!fb || bpp_bytes == 0)
		return;
	if (bpp_bytes == 4) {
		font_blit_glyph_32(fb, pitch, px, py, ch, fg, bg);
		return;
	}
	font_blit_glyph_generic(fb, pitch, bpp_bytes, px, py, ch, fg, bg);
}

void font_notify_changed(void) {
	if (cirrusfb_is_ready())
		(void)cirrusfb_recompute_geometry();
}
