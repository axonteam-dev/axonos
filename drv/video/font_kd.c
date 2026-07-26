#include <font.h>
#include <heap.h>
#include <string.h>
#include <klog.h>
#include <errno.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

/*
 * Linux KD font payload (kd.h / vt):
 *   bytes_per_row = (width + 7) / 8
 *   KD_FONT_OP_SET:      each glyph is vpitch(=32) * bytes_per_row
 *   KD_FONT_OP_SET_TALL: each glyph is height * bytes_per_row
 * Only the first `height` scanlines are ink; the rest of the 32-row cell is pad.
 */

int font_load_kd(uint32_t width, uint32_t height, uint32_t charcount,
		 const uint8_t *data, uint32_t vpitch)
{
	if (!data || width == 0 || height == 0 || charcount == 0)
		return -EINVAL;
	if (width > FONT_MAX_CELL_W || height > FONT_MAX_CELL_H)
		return -EINVAL;
	if (charcount > 512)
		return -EINVAL;
	if (vpitch < height || vpitch > 32)
		return -EINVAL;

	uint32_t bpr = (width + 7u) / 8u;
	uint32_t stride = bpr;
	uint32_t glyph_bytes = stride * height;
	uint32_t ncache = charcount < FONT_GLYPH_CACHE ? charcount : FONT_GLYPH_CACHE;
	uint32_t total = glyph_bytes * FONT_GLYPH_CACHE;
	uint8_t *bits = (uint8_t *)kmalloc(total);
	if (!bits)
		return -ENOMEM;
	memset(bits, 0, total);

	for (uint32_t c = 0; c < ncache; c++) {
		const uint8_t *src = data + (size_t)c * (size_t)vpitch * bpr;
		uint8_t *dst = bits + (size_t)c * glyph_bytes;
		memcpy(dst, src, (size_t)height * bpr);
	}

	struct font f;
	memset(&f, 0, sizeof(f));
	f.cwidth = width;
	f.cheight = height;
	f.ascent = height > 2 ? height - 2 : height;
	f.descent = height > 2 ? 2 : 0;
	f.bits = bits;
	f.stride = stride;
	f.bits_bytes = total;
	f.bits_owned = 1;
	strncpy(f.name, "kd_console", sizeof(f.name) - 1);

	if (font_set(&f) != 0) {
		kfree(bits);
		return -ENOMEM;
	}
	klogprintf("font: KDFONTOP set cell=%ux%u glyphs=%u (cache %u)\n",
		   (unsigned)width, (unsigned)height, (unsigned)charcount,
		   (unsigned)ncache);
	font_notify_changed();
	return 0;
}

int font_export_kd(uint32_t *width, uint32_t *height, uint32_t *charcount,
		   uint8_t *data, size_t data_bytes, uint32_t vpitch)
{
	const struct font *f = font_current();
	if (!f || !f->bits || !width || !height || !charcount)
		return -EINVAL;

	uint32_t w = f->cwidth;
	uint32_t h = f->cheight;
	uint32_t bpr = f->stride ? f->stride : (w + 7u) / 8u;
	uint32_t n = FONT_GLYPH_CACHE;

	*width = w;
	*height = h;
	*charcount = n;
	if (!data)
		return 0;
	if (vpitch < h || vpitch > 32)
		return -EINVAL;
	size_t need = (size_t)n * (size_t)vpitch * bpr;
	if (data_bytes < need)
		return -EINVAL;
	memset(data, 0, need);
	for (uint32_t c = 0; c < n; c++) {
		const uint8_t *src = f->bits + (size_t)c * bpr * h;
		uint8_t *dst = data + (size_t)c * (size_t)vpitch * bpr;
		memcpy(dst, src, (size_t)h * bpr);
	}
	return 0;
}
