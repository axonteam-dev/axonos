#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * Runtime console font. Default is embedded 8x16; GRUB PFF2 (.pf2) can replace it.
 * Glyphs 0..511 are cached as packed bitmaps (MSB-left) for Linux-like fbcon blits.
 */

#define FONT_GLYPH_CACHE 512 /* Linux console max (PSF MODE512 / KDFONTOP) */
#define FONT_MAX_CELL_W  32
#define FONT_MAX_CELL_H  32

struct font {
	uint32_t cwidth;
	uint32_t cheight;
	uint32_t ascent;
	uint32_t descent;
	char name[64];
	/* Packed rows: stride = (cwidth + 7) / 8 bytes per scanline. */
	uint8_t *bits; /* FONT_GLYPH_CACHE * cheight * stride */
	uint32_t stride;
	uint32_t bits_bytes;
	int bits_owned; /* 1 if bits was kmalloc'd (font_set will kfree) */
};

void font_init_default(void);
const struct font *font_current(void);
uint32_t font_cell_width(void);
uint32_t font_cell_height(void);

/* Replace the active font (takes ownership of heap fields inside `f` copy). */
int font_set(const struct font *f);

/* GRUB PFF2 / .pf2 loader. Builds a 0..255 glyph cache; other codepoints ignored. */
int font_load_pf2(const void *data, size_t len);
int font_load_pf2_path(const char *path);

/*
 * Linux KD/console font (setfont/loadfont → ioctl KDFONTOP).
 * `data` layout: charcount glyphs, each vpitch * ceil(width/8) bytes;
 * for KD_FONT_OP_SET, vpitch is 32; for SET_TALL, vpitch == height.
 * Returns 0 or -errno.
 */
int font_load_kd(uint32_t width, uint32_t height, uint32_t charcount,
		 const uint8_t *data, uint32_t vpitch);
/* Export current font into KD layout; data may be NULL to query sizes only. */
int font_export_kd(uint32_t *width, uint32_t *height, uint32_t *charcount,
		   uint8_t *data, size_t data_bytes, uint32_t vpitch);

/* Optional: activate linked ascii.pf2 blob (not used at boot by default). */
void font_try_embedded_pf2(void);
/* After VFS: optional /etc/fonts/console.pf2 or /lib/fonts/console.pf2. */
void font_try_load_console_pf2(void);

/*
 * Fast 32bpp glyph blit into a linear framebuffer (Linux fbcon-style).
 * Fills the full cell with bg, then stamps the glyph in fg.
 */
void font_blit_glyph_32(void *fb, uint32_t pitch, uint32_t px, uint32_t py,
			uint8_t ch, uint32_t fg, uint32_t bg);

/* Generic bpp path (2/3/4 bytes per pixel). */
void font_blit_glyph(void *fb, uint32_t pitch, uint32_t bpp_bytes,
		     uint32_t px, uint32_t py, uint8_t ch,
		     uint32_t fg, uint32_t bg);

/* Notify fbcon backends that metrics changed (recompute cols/rows). */
void font_notify_changed(void);

/* Linux PIO_UNIMAP* — unicode → font glyph index (setfont after KDFONTOP). */
void con_unimap_clear(void);
int con_unimap_set(unsigned entry_ct, const void *entries /* unipair[] */);
int con_unimap_get(unsigned *entry_ct, void *out /* unipair[] */, unsigned out_max);
int con_unimap_lookup(uint32_t unicode); /* fontpos or -1 */
