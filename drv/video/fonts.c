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
	static const char *const paths[] = {
		"/etc/fonts/console.pf2",
		"/lib/fonts/console.pf2",
		"/usr/share/grub/ascii.pf2",
		"/usr/share/grub/euro.pf2",
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

void font_blit_glyph_32(void *fb, uint32_t pitch, uint32_t px, uint32_t py,
			uint8_t ch, uint32_t fg, uint32_t bg) {
	const struct font *f = font_current();
	const uint8_t *rows = glyph_rows(ch);
	uint32_t w = f->cwidth;
	uint32_t h = f->cheight;
	uint32_t stride = f->stride;

	if (w == 8 && stride == 1) {
		for (uint32_t row = 0; row < h; row++) {
			uint8_t bits = rows[row];
			uint32_t *line = (uint32_t *)((uint8_t *)fb +
				(size_t)(py + row) * pitch + px * 4u);
			line[0] = (bits & 0x80u) ? fg : bg;
			line[1] = (bits & 0x40u) ? fg : bg;
			line[2] = (bits & 0x20u) ? fg : bg;
			line[3] = (bits & 0x10u) ? fg : bg;
			line[4] = (bits & 0x08u) ? fg : bg;
			line[5] = (bits & 0x04u) ? fg : bg;
			line[6] = (bits & 0x02u) ? fg : bg;
			line[7] = (bits & 0x01u) ? fg : bg;
		}
		return;
	}

	if (w == 16 && stride == 2) {
		for (uint32_t row = 0; row < h; row++) {
			uint8_t b0 = rows[row * 2u];
			uint8_t b1 = rows[row * 2u + 1u];
			uint32_t *line = (uint32_t *)((uint8_t *)fb +
				(size_t)(py + row) * pitch + px * 4u);
			line[0] = (b0 & 0x80u) ? fg : bg;
			line[1] = (b0 & 0x40u) ? fg : bg;
			line[2] = (b0 & 0x20u) ? fg : bg;
			line[3] = (b0 & 0x10u) ? fg : bg;
			line[4] = (b0 & 0x08u) ? fg : bg;
			line[5] = (b0 & 0x04u) ? fg : bg;
			line[6] = (b0 & 0x02u) ? fg : bg;
			line[7] = (b0 & 0x01u) ? fg : bg;
			line[8] = (b1 & 0x80u) ? fg : bg;
			line[9] = (b1 & 0x40u) ? fg : bg;
			line[10] = (b1 & 0x20u) ? fg : bg;
			line[11] = (b1 & 0x10u) ? fg : bg;
			line[12] = (b1 & 0x08u) ? fg : bg;
			line[13] = (b1 & 0x04u) ? fg : bg;
			line[14] = (b1 & 0x02u) ? fg : bg;
			line[15] = (b1 & 0x01u) ? fg : bg;
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
