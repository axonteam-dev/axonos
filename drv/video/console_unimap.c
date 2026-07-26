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
