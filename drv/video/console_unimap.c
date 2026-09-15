#include <font.h>
#include <heap.h>
#include <string.h>
#include <errno.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EFAULT
#define EFAULT 14
#endif

#ifndef CON_UNIMAP_MAX
#define CON_UNIMAP_MAX 8192
#endif

struct unipair_k {
	uint16_t unicode;
	uint16_t fontpos;
};

static struct unipair_k *g_map;
static unsigned g_ct;

void con_unimap_clear(void)
{
	if (g_map) {
		kfree(g_map);
		g_map = NULL;
	}
	g_ct = 0;
}

int con_unimap_set(unsigned entry_ct, const void *entries_user_copied)
{
	const struct unipair_k *list = (const struct unipair_k *)entries_user_copied;
	if (entry_ct == 0) {
		con_unimap_clear();
		return 0;
	}
	if (!list || entry_ct > CON_UNIMAP_MAX)
		return -EINVAL;

	struct unipair_k *n = (struct unipair_k *)kmalloc(entry_ct * sizeof(*n));
	if (!n)
		return -ENOMEM;
	memcpy(n, list, entry_ct * sizeof(*n));
	/* Drop pairs whose fontpos is outside the glyph cache. */
	unsigned w = 0;
	for (unsigned i = 0; i < entry_ct; i++) {
		if (n[i].fontpos < FONT_GLYPH_CACHE)
			n[w++] = n[i];
	}
	if (g_map)
		kfree(g_map);
	g_map = n;
	g_ct = w;
	return 0;
}

int con_unimap_get(unsigned *entry_ct, void *out, unsigned out_max)
{
	if (!entry_ct)
		return -EINVAL;
	if (!out) {
		*entry_ct = g_ct;
		return 0;
	}
	if (out_max < g_ct)
		return -EINVAL;
	if (g_ct && g_map)
		memcpy(out, g_map, g_ct * sizeof(struct unipair_k));
	*entry_ct = g_ct;
	return 0;
}

int con_unimap_lookup(uint32_t unicode)
{
	if (unicode > 0xFFFFu)
		return -1;
	uint16_t u = (uint16_t)unicode;
	/* Identity for the ASCII / direct-font region when no table. */
	if (!g_map || g_ct == 0) {
		if (unicode < FONT_GLYPH_CACHE)
			return (int)unicode;
		return -1;
	}
	for (unsigned i = 0; i < g_ct; i++) {
		if (g_map[i].unicode == u)
			return (int)g_map[i].fontpos;
	}
	return -1;
}

/*
 * Fill gaps in the console Unicode → glyph map so every codepoint still renders
 * instead of turning into garbage: Latin-1 identity, CP437 line-drawing slots
 * for U+2500..257F box drawing (tmux/ncurses panes), block elements and a few
 * common punctuation.  Entries whose codepoint is already mapped are preserved
 * (the loaded font's own meaning wins).  Idempotent.
 */
void con_unimap_add_default(void)
{
	/* Box drawing U+2500..257F → the classic CP437 cell. */
	static const uint16_t box_to_font[][2] = {
		{ 0x2500, 0xC4 }, { 0x2501, 0xC4 }, { 0x2502, 0xB3 }, { 0x2503, 0xB3 },
		{ 0x250C, 0xDA }, { 0x250D, 0xDA }, { 0x2510, 0xBF }, { 0x2511, 0xBF },
		{ 0x2514, 0xC0 }, { 0x2515, 0xC0 }, { 0x2518, 0xD9 }, { 0x2519, 0xD9 },
		{ 0x251C, 0xC3 }, { 0x251D, 0xC3 }, { 0x2524, 0xB4 }, { 0x2525, 0xB4 },
		{ 0x252C, 0xC2 }, { 0x252D, 0xC2 }, { 0x2534, 0xC1 }, { 0x2535, 0xC1 },
		{ 0x253C, 0xC5 }, { 0x253D, 0xC5 },
		{ 0x2550, 0xCD }, { 0x2551, 0xBA }, { 0x2552, 0xD6 }, { 0x2553, 0xD5 },
		{ 0x2554, 0xD7 }, { 0x2555, 0xD8 }, { 0x2556, 0xDD }, { 0x2557, 0xDE },
		{ 0x2558, 0xCE }, { 0x2559, 0xCF }, { 0x255A, 0xD0 }, { 0x255B, 0xD1 },
		{ 0x255C, 0xD2 }, { 0x255D, 0xD3 }, { 0x255E, 0xD4 },
		/* Block / shading elements. */
		{ 0x2580, 0xDF }, { 0x2584, 0xDC }, { 0x2588, 0xDB }, { 0x258C, 0xDD },
		{ 0x2590, 0xDE }, { 0x2591, 0xB0 }, { 0x2592, 0xB1 }, { 0x2593, 0xB2 },
		{ 0x25A0, 0xFE }, { 0x25AC, 0xFE },
		{ 0x00A0, 0x20 },  /* NBSP → space */
		{ 0x00B7, 0xFA },  /* middle dot */
		{ 0x2022, 0xF9 },  /* bullet */
		{ 0x221A, 0xFB },  /* radical */
		{ 0x2261, 0xF0 },  /* identical to */
	};

	/* Build: existing entries + identity for 0..0xFF + box/block where missing.
	 * (identity is added only once — the map normally has it from PIO_UNIMAP.) */
	unsigned new_ct = 0;
	struct unipair_k *add = NULL;
	{
		unsigned need = 256 + sizeof(box_to_font) / sizeof(box_to_font[0]) + g_ct;
		if (need > CON_UNIMAP_MAX)
			return;
		/* First pass: identity + extras only for codepoints not yet mapped. */
		unsigned pass2 = 0;
		/* count */
		unsigned add_cap = 256 + sizeof(box_to_font) / sizeof(box_to_font[0]);
		add = (struct unipair_k *)kmalloc(add_cap * sizeof(*add));
		if (!add)
			return;
		(void)pass2;
	}

	unsigned n = 0;
	/* identity entries unless already present */
	for (unsigned c = 0; c < 256; c++) {
		int present = 0;
		for (unsigned i = 0; i < g_ct; i++)
			if (g_map[i].unicode == (uint16_t)c) { present = 1; break; }
		if (!present) {
			add[n].unicode = (uint16_t)c;
			add[n].fontpos = (uint16_t)c;
			n++;
		}
	}
	for (unsigned i = 0; i < sizeof(box_to_font) / sizeof(box_to_font[0]); i++) {
		uint16_t u = box_to_font[i][0];
		int present = 0;
		for (unsigned k = 0; k < g_ct; k++)
			if (g_map[k].unicode == u) { present = 1; break; }
		if (!present) {
			add[n].unicode = u;
			add[n].fontpos = box_to_font[i][1];
			n++;
		}
	}

	if (n == 0) {
		kfree(add);
		return;
	}
	struct unipair_k *all = (struct unipair_k *)kmalloc((g_ct + n) * sizeof(*all));
	if (!all) {
		kfree(add);
		return;
	}
	if (g_ct && g_map)
		memcpy(all, g_map, g_ct * sizeof(*all));
	memcpy(all + g_ct, add, n * sizeof(*add));
	kfree(add);
	if (g_map)
		kfree(g_map);
	g_map = all;
	g_ct += n;
}

/* Replace the whole map with just the built-in ASCII/Latin1/box-drawing table. */
void con_unimap_default_only(void)
{
	con_unimap_clear();
	con_unimap_add_default();
}
