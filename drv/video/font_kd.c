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
	/* Fill box-drawing/identity gaps if the caller skips PIO_UNIMAP. */
	con_unimap_add_default();
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

/*
 * PSF1 (Linux console font) loader.  Layout: magic 0x36 0x04, mode byte
 * (bit0: 512 glyphs, bit1: unicode table follows), then glyph cells (8px wide,
 * 1 byte/row); height is not stored in the header, so it is recovered from the
 * unicode table (which ends with 0xFF 0xFF).  The unicode table is turned into
 * the console unimap (setfont(8) format) so UTF-8 output maps to these glyphs.
 */
/*
 * Debian consolefonts / console-setup store the PSF1 unicode table in one of
 * two layouts:
 *   B16  — a stream of UTF-16LE BMP cells, one U+FFFF after each glyph's row
 *          (this is what every /usr/share/consolefonts/*.psf.gz ships);
 *   UTF8 — classic kbd: rows of UTF-8 strings separated by a single 0xFF,
 *          whole table terminated by 0xFFFF.
 */
static int psf1_uni_rows_b16(const uint8_t *tbl, size_t len, unsigned ngly)
{
	if (len & 1u)
		return 0;
	size_t n = len / 2;
	if (n < ngly)
		return 0;
	unsigned rows = 0;
	for (size_t i = 0; i < n; i++)
		if (tbl[i * 2] == 0xFF && tbl[i * 2 + 1] == 0xFF)
			rows++;
	return rows == ngly && tbl[len - 2] == 0xFF && tbl[len - 1] == 0xFF;
}

static int psf1_uni_rows_utf8(const uint8_t *tbl, size_t len)
{
	size_t i = 0;
	while (i < len) {
		if (tbl[i] == 0xFF) {
			if (i + 1 < len && tbl[i + 1] == 0xFF)
				return i + 2 == len;
			i++; /* end of row for one glyph */
			continue;
		}
		uint8_t b = tbl[i];
		unsigned need;
		if (b < 0x80)
			need = 0;
		else if ((b & 0xE0) == 0xC0 && b >= 0xC2)
			need = 1;
		else if ((b & 0xF0) == 0xE0)
			need = 2;
		else if ((b & 0xF8) == 0xF0 && b <= 0xF4)
			need = 3;
		else
			return 0;
		if (need + i + 1 > len)
			return 0;
		for (unsigned k = 1; k <= need; k++)
			if ((tbl[i + k] & 0xC0) != 0x80)
				return 0;
		i += need + 1;
	}
	return 0; /* no 0xFFFF terminator */
}

static int psf1_uni_table_ok(const uint8_t *tbl, size_t len, unsigned ngly)
{
	return psf1_uni_rows_b16(tbl, len, ngly) || psf1_uni_rows_utf8(tbl, len);
}

static int font_load_psf_uni(const uint8_t *tbl, size_t len, unsigned ngly)
{
	int is_b16 = psf1_uni_rows_b16(tbl, len, ngly);
	if (!is_b16 && !psf1_uni_rows_utf8(tbl, len))
		return -EINVAL;

	/* Entries: codepoint -> font glyph index.  B16 rows and UTF8 rows both map
	 * row k to glyph k.  Cap at the kernel's unimap limit. */
	struct psf_unipair { uint16_t unicode; uint16_t fontpos; } *pairs =
		(struct psf_unipair *)kmalloc(8192 * sizeof(*pairs));
	if (!pairs)
		return -ENOMEM;

	unsigned ct = 0;
	unsigned glyph = 0;
	if (is_b16) {
		for (size_t i = 0; i + 1 < len && glyph < ngly; ) {
			uint16_t cell = (uint16_t)tbl[i] | (uint16_t)(tbl[i + 1] << 8);
			if (cell == 0xFFFF) {
				i += 2;
				glyph++;
				continue;
			}
			if (cell != 0) { /* some fonts start rows with U+0000 */
				if (ct < 8192) {
					pairs[ct].unicode = cell;
					pairs[ct].fontpos = (uint16_t)glyph;
					ct++;
				}
			}
			i += 2;
		}
	} else {
		size_t i = 0;
		while (i < len) {
			if (tbl[i] == 0xFF) {
				if (i + 1 < len && tbl[i + 1] == 0xFF)
					break;
				i++;
				glyph++;
				continue;
			}
			uint8_t b = tbl[i];
			unsigned need;
			uint32_t cp;
			if (b < 0x80) {
				need = 0; cp = b;
			} else if ((b & 0xE0) == 0xC0) {
				need = 1; cp = b & 0x1Fu;
			} else if ((b & 0xF0) == 0xE0) {
				need = 2; cp = b & 0x0Fu;
			} else {
				need = 3; cp = b & 0x07u;
			}
			for (unsigned k = 1; k <= need; k++)
				cp = (cp << 6) | (tbl[i + k] & 0x3Fu);
			if (cp <= 0xFFFFu && glyph < FONT_GLYPH_CACHE && ct < 8192) {
				pairs[ct].unicode = (uint16_t)cp;
				pairs[ct].fontpos = (uint16_t)glyph;
				ct++;
			}
			i += need + 1;
		}
	}

	if (ct > 0)
		con_unimap_set(ct, pairs);
	kfree(pairs);
	return 0;
}

int font_load_psf(const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	if (!p || len < 3 || p[0] != 0x36 || p[1] != 0x04)
		return -EINVAL;

	uint8_t mode = p[2];
	unsigned ngly = (mode & 0x01) ? 512u : 256u;
	int has_uni = (mode & 0x02) != 0;

	unsigned rows = 16;
	if (has_uni) {
		/* Recover height: the unicode table must tail the glyphs exactly. */
		static const unsigned cand[] = { 16u, 8u, 14u };
		int found = 0;
		for (unsigned k = 0; k < sizeof(cand) / sizeof(cand[0]); k++) {
			unsigned h = cand[k];
			size_t gstart = 4 + (size_t)ngly * h;
			if (gstart < len && psf1_uni_table_ok(p + gstart, len - gstart, ngly)) {
				rows = h;
				found = 1;
				break;
			}
		}
		if (!found)
			return -EINVAL;
	} else {
		if (len <= 4 || (len - 4) % ngly != 0)
			return -EINVAL;
		rows = (unsigned)((len - 4) / ngly); /* 8px wide → 1 byte per scanline */
	}
	if (rows == 0 || rows > FONT_MAX_CELL_H)
		return -EINVAL;

	size_t glyph_bytes = rows; /* stride == 1 for 8px wide */
	size_t gstart = 4 + (size_t)ngly * glyph_bytes;
	if (gstart > len)
		return -EINVAL;

	uint32_t stride = 1;
	size_t total = (size_t)FONT_GLYPH_CACHE * rows;
	uint8_t *bits = (uint8_t *)kmalloc(total);
	if (!bits)
		return -ENOMEM;
	memset(bits, 0, total);
	unsigned ncache = ngly < FONT_GLYPH_CACHE ? ngly : FONT_GLYPH_CACHE;
	for (unsigned c = 0; c < ncache; c++)
		memcpy(bits + (size_t)c * rows, p + 4 + (size_t)c * glyph_bytes, rows);

	struct font f;
	memset(&f, 0, sizeof(f));
	f.cwidth = 8;
	f.cheight = rows;
	f.ascent = rows > 2 ? rows - 2 : rows;
	f.descent = rows > 2 ? 2 : 0;
	f.bits = bits;
	f.stride = stride;
	f.bits_bytes = total;
	f.bits_owned = 1;
	strncpy(f.name, "psf_console", sizeof(f.name) - 1);

	if (font_set(&f) != 0) {
		kfree(bits);
		return -ENOMEM;
	}

	if (has_uni && gstart < len)
		(void)font_load_psf_uni(p + gstart, len - gstart, ngly);
	/* Fill box-drawing/identity gaps not covered by the font's own table. */
	con_unimap_add_default();

	klogprintf("font: PSF1 set cell=8x%u glyphs=%u (cache %u)\n",
		   rows, ngly, (unsigned)ncache);
	font_notify_changed();
	return 0;
}
