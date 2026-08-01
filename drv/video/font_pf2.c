#include <font.h>
#include <heap.h>
#include <string.h>
#include <fs.h>
#include <klog.h>
#include <stdint.h>

static uint16_t be16(const uint8_t *p) {
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int pf2_section(const uint8_t *data, size_t len, size_t *off,
		       const uint8_t **body, uint32_t *blen, char name_out[5]) {
	size_t o = *off;
	if (o + 8 > len)
		return -1;
	name_out[0] = (char)data[o];
	name_out[1] = (char)data[o + 1];
	name_out[2] = (char)data[o + 2];
	name_out[3] = (char)data[o + 3];
	name_out[4] = 0;
	uint32_t n = be32(data + o + 4);
	o += 8;
	if (n == 0xFFFFFFFFu) {
		/* DATA terminator: rest of file is glyph payloads. */
		*body = data + o;
		*blen = (uint32_t)(len - o);
		*off = len;
		return 0;
	}
	if (o + n > len)
		return -1;
	*body = data + o;
	*blen = n;
	*off = o + n;
	return 0;
}

/*
 * GRUB PFF2 bitmaps are 1BIT_PACKED: a continuous MSB-first bit stream
 * indexed by (row * width + col), NOT row-aligned bytes (ceil(w/8)*h).
 * See grub_font_blit_glyph / GRUB_VIDEO_BLIT_FORMAT_1BIT_PACKED.
 */
static void stamp_bits(uint8_t *dst, uint32_t dst_stride, uint32_t cell_w,
		       uint32_t cell_h, int dx, int dy, uint32_t gw, uint32_t gh,
		       const uint8_t *src) {
	for (uint32_t row = 0; row < gh; row++) {
		int y = dy + (int)row;
		if (y < 0 || (uint32_t)y >= cell_h)
			continue;
		uint8_t *drow = dst + (uint32_t)y * dst_stride;
		for (uint32_t col = 0; col < gw; col++) {
			int x = dx + (int)col;
			if (x < 0 || (uint32_t)x >= cell_w)
				continue;
			uint32_t bit = row * gw + col;
			if (!(src[bit >> 3] & (uint8_t)(0x80u >> (bit & 7))))
				continue;
			drow[x >> 3] |= (uint8_t)(0x80u >> (x & 7));
		}
	}
}

int font_load_pf2(const void *data, size_t len) {
	if (!data || len < 12)
		return -1;
	const uint8_t *p = (const uint8_t *)data;
	size_t off = 0;
	char name[5];
	const uint8_t *body = NULL;
	uint32_t blen = 0;

	if (pf2_section(p, len, &off, &body, &blen, name) != 0)
		return -1;
	if (name[0] != 'F' || name[1] != 'I' || name[2] != 'L' || name[3] != 'E')
		return -1;
	if (blen != 4 || body[0] != 'P' || body[1] != 'F' || body[2] != 'F' || body[3] != '2')
		return -1;

	uint16_t maxw = 0, maxh = 0, asce = 0, desc = 0;
	const uint8_t *chix = NULL;
	uint32_t chix_len = 0;
	char font_name[64];
	font_name[0] = 0;

	while (off < len) {
		if (pf2_section(p, len, &off, &body, &blen, name) != 0)
			return -1;
		if (name[0] == 'D' && name[1] == 'A' && name[2] == 'T' && name[3] == 'A')
			break;
		if (name[0] == 'N' && name[1] == 'A' && name[2] == 'M' && name[3] == 'E' && blen) {
			size_t n = blen < sizeof(font_name) - 1 ? blen : sizeof(font_name) - 1;
			memcpy(font_name, body, n);
			font_name[n] = 0;
			/* trim trailing NULs/spaces */
			while (n && (font_name[n - 1] == 0 || font_name[n - 1] == ' '))
				font_name[--n] = 0;
		} else if (name[0] == 'M' && name[1] == 'A' && name[2] == 'X' && name[3] == 'W' &&
			   blen >= 2) {
			maxw = be16(body);
		} else if (name[0] == 'M' && name[1] == 'A' && name[2] == 'X' && name[3] == 'H' &&
			   blen >= 2) {
			maxh = be16(body);
		} else if (name[0] == 'A' && name[1] == 'S' && name[2] == 'C' && name[3] == 'E' &&
			   blen >= 2) {
			asce = be16(body);
		} else if (name[0] == 'D' && name[1] == 'E' && name[2] == 'S' && name[3] == 'C' &&
			   blen >= 2) {
			desc = be16(body);
		} else if (name[0] == 'C' && name[1] == 'H' && name[2] == 'I' && name[3] == 'X') {
			chix = body;
			chix_len = blen;
		}
	}

	if (!chix || maxw == 0 || maxh == 0)
		return -1;
	if (maxw > FONT_MAX_CELL_W)
		maxw = FONT_MAX_CELL_W;
	if (maxh > FONT_MAX_CELL_H)
		maxh = FONT_MAX_CELL_H;
	if (asce == 0)
		asce = maxh > desc ? (uint16_t)(maxh - desc) : maxh;

	/*
	 * First pass: device widths for printable ASCII only.
	 * GRUB ascii.pf2 advertises MAXW=16 but Latin glyphs use dwidth=8;
	 * taking max(dwidth) over the whole CHIX (or MAXW) made every fbcon
	 * cell 16px wide while bitmaps stayed ~8px → huge inter-character gaps.
	 */
	uint32_t cell_w = 0;
	if ((chix_len % 9u) != 0)
		return -1;
	uint32_t nent = chix_len / 9u;
	for (uint32_t i = 0; i < nent; i++) {
		const uint8_t *e = chix + i * 9u;
		uint32_t code = be32(e);
		uint32_t goff = be32(e + 5);
		if (code < 0x20u || code > 0x7Eu)
			continue;
		if (code >= FONT_GLYPH_CACHE || goff + 10 > len)
			continue;
		const uint8_t *g = p + goff;
		int16_t dwidth = (int16_t)be16(g + 8);
		uint32_t dw = dwidth > 0 ? (uint32_t)dwidth : 0;
		if (dw > cell_w)
			cell_w = dw;
	}
	if (cell_w == 0) {
		/* Fallback: any glyph, still capped — never trust MAXW alone. */
		for (uint32_t i = 0; i < nent; i++) {
			const uint8_t *e = chix + i * 9u;
			uint32_t code = be32(e);
			uint32_t goff = be32(e + 5);
			if (code >= FONT_GLYPH_CACHE || goff + 10 > len)
				continue;
			const uint8_t *g = p + goff;
			int16_t dwidth = (int16_t)be16(g + 8);
			uint32_t dw = dwidth > 0 ? (uint32_t)dwidth : 0;
			if (dw > 0 && dw <= 8 && dw > cell_w)
				cell_w = dw;
		}
	}
	if (cell_w == 0 || cell_w > maxw)
		cell_w = (maxw >= 8 && maxw <= 16) ? 8 : maxw;

	uint32_t stride = (cell_w + 7u) / 8u;
	uint32_t glyph_bytes = stride * maxh;
	uint32_t total = glyph_bytes * FONT_GLYPH_CACHE;
	uint8_t *bits = (uint8_t *)kmalloc(total);
	if (!bits)
		return -1;
	memset(bits, 0, total);

	/* CHIX: 9-byte entries — BE32 code, u8 flags, BE32 file offset. */
	for (uint32_t i = 0; i < nent; i++) {
		const uint8_t *e = chix + i * 9u;
		uint32_t code = be32(e);
		uint32_t goff = be32(e + 5);
		if (code >= FONT_GLYPH_CACHE)
			continue;
		if (goff + 10 > len)
			continue;
		const uint8_t *g = p + goff;
		uint32_t gw = be16(g + 0);
		uint32_t gh = be16(g + 2);
		int16_t xoff = (int16_t)be16(g + 4);
		int16_t yoff = (int16_t)be16(g + 6);
		size_t bmp_bytes = (size_t)((gw * gh + 7u) / 8u);
		size_t need = 10u + bmp_bytes;
		if (goff + need > len || gw == 0 || gh == 0 || gw > 64 || gh > 64)
			continue;
		const uint8_t *bmp = g + 10;
		/*
		 * GRUB: bitmap_bottom = baseline - offset_y;
		 *       bitmap_top    = bitmap_bottom - height;
		 * baseline at ascent from cell top → dy = ascent - yoff - gh.
		 */
		int dx = (int)xoff;
		int dy = (int)asce - (int)yoff - (int)gh;
		uint8_t *dst = bits + code * glyph_bytes;
		stamp_bits(dst, stride, cell_w, maxh, dx, dy, gw, gh, bmp);
	}

	/* Ensure space glyph is empty (bg fill only). */
	memset(bits + (size_t)' ' * glyph_bytes, 0, glyph_bytes);

	struct font f;
	memset(&f, 0, sizeof(f));
	f.cwidth = cell_w;
	f.cheight = maxh;
	f.ascent = asce;
	f.descent = desc;
	f.bits = bits;
	f.stride = stride;
	f.bits_bytes = total;
	f.bits_owned = 1;
	if (font_name[0])
		strncpy(f.name, font_name, sizeof(f.name) - 1);
	else
		strncpy(f.name, "pf2", sizeof(f.name) - 1);

	if (font_set(&f) != 0) {
		kfree(bits);
		return -1;
	}
	klogprintf("font: loaded pf2 \"%s\" cell=%ux%u (maxw=%u) ascent=%u\n",
		   f.name, (unsigned)cell_w, (unsigned)maxh, (unsigned)maxw,
		   (unsigned)asce);
	font_notify_changed();
	return 0;
}

int font_load_pf2_path(const char *path) {
	if (!path)
		return -1;
	struct fs_file *f = fs_open(path);
	if (!f)
		return -1;
	if (f->size == 0 || f->size > (8u * 1024u * 1024u)) {
		fs_file_free(f);
		return -1;
	}
	size_t sz = f->size;
	void *buf = kmalloc(sz);
	if (!buf) {
		fs_file_free(f);
		return -1;
	}
	ssize_t n = fs_read(f, buf, sz, 0);
	fs_file_free(f);
	if (n != (ssize_t)sz) {
		kfree(buf);
		return -1;
	}
	int rc = font_load_pf2(buf, sz);
	kfree(buf);
	return rc;
}
