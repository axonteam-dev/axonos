/*
 * Minix filesystem (Linux fs/minix layout)
 *
 * Supports Minix V1/V2 with 14- or 30-character names (BusyBox/util-linux
 * mkfs.minix defaults to V1 + 30-char / magic 0x138F).
 *
 * Block device I/O is 512-byte sectors; on-disk zones are typically 1024 bytes.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <heap.h>
#include <fs.h>
#include <ext2.h>
#include <minix.h>
#include <disk.h>
#include <stat.h>
#include <klog.h>
#include <stdio.h>

#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & 0170000) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0170000) == S_IFREG)
#endif

#define MINIX_V1 1
#define MINIX_V2 2

#define MINIX_INODES_PER_BLOCK_V1(bs) ((bs) / 32)
#define MINIX_INODES_PER_BLOCK_V2(bs) ((bs) / 64)

/* On-disk superblock (shared V1/V2 header; V2 uses s_zones). */
struct minix_super_block {
	uint16_t s_ninodes;
	uint16_t s_nzones;          /* V1 zone count; unused on V2 */
	uint16_t s_imap_blocks;
	uint16_t s_zmap_blocks;
	uint16_t s_firstdatazone;
	uint16_t s_log_zone_size;
	uint32_t s_max_size;
	uint16_t s_magic;
	uint16_t s_state;
	uint32_t s_zones;           /* V2 zone count */
} __attribute__((packed));

struct minix_inode_v1 {
	uint16_t i_mode;
	uint16_t i_uid;
	uint32_t i_size;
	uint32_t i_time;
	uint8_t  i_gid;
	uint8_t  i_nlinks;
	uint16_t i_zone[9];
} __attribute__((packed));

struct minix_inode_v2 {
	uint16_t i_mode;
	uint16_t i_nlinks;
	uint16_t i_uid;
	uint16_t i_gid;
	uint32_t i_size;
	uint32_t i_atime;
	uint32_t i_mtime;
	uint32_t i_ctime;
	uint32_t i_zone[10];
} __attribute__((packed));

struct minix_mount {
	int device_id;
	uint32_t start_lba;
	int version;                /* MINIX_V1 / MINIX_V2 */
	unsigned blocksize;
	unsigned sectors_per_block; /* blocksize / 512 */
	unsigned ninodes;
	unsigned nzones;
	unsigned imap_blocks;
	unsigned zmap_blocks;
	unsigned firstdatazone;
	unsigned log_zone_size;
	unsigned dirsize;
	unsigned namelen;
	unsigned max_size;
	uint16_t magic;
	uint8_t *imap;
	uint8_t *zmap;
	size_t imap_bytes;
	size_t zmap_bytes;
};

struct minix_file_handle {
	struct minix_mount *m;
	uint32_t ino;
	uint16_t mode;
	uint32_t size;
	uint32_t zone[10];          /* V1 uses 9; V2 uses 10 */
	int nzones;
};

static struct fs_driver minix_driver;
static struct fs_driver_ops minix_ops;
static struct minix_mount *g_minix;

/* ---------- block I/O ---------- */

static uint32_t zone_to_lba(const struct minix_mount *m, unsigned zone) {
	return m->start_lba + (uint32_t)zone * m->sectors_per_block;
}

static int read_zone(struct minix_mount *m, unsigned zone, void *buf) {
	if (!m || !buf || zone >= m->nzones)
		return -1;
	return disk_read_sectors(m->device_id, zone_to_lba(m, zone), buf, m->sectors_per_block);
}

static int write_zone(struct minix_mount *m, unsigned zone, const void *buf) {
	if (!m || !buf || zone >= m->nzones || zone == 0)
		return -1;
	return disk_write_sectors(m->device_id, zone_to_lba(m, zone), buf, m->sectors_per_block);
}

/* ---------- bitmaps (little-endian, Linux native LE) ---------- */

static int bitmap_test(const uint8_t *map, size_t map_bytes, unsigned bit) {
	unsigned byte = bit / 8;
	if (byte >= map_bytes)
		return 0;
	return (map[byte] >> (bit % 8)) & 1;
}

static void bitmap_set(uint8_t *map, size_t map_bytes, unsigned bit) {
	unsigned byte = bit / 8;
	if (byte >= map_bytes)
		return;
	map[byte] |= (uint8_t)(1u << (bit % 8));
}

static void bitmap_clear(uint8_t *map, size_t map_bytes, unsigned bit) {
	unsigned byte = bit / 8;
	if (byte >= map_bytes)
		return;
	map[byte] &= (uint8_t)~(1u << (bit % 8));
}

static int bitmap_find_zero(const uint8_t *map, size_t map_bytes, unsigned max_bits) {
	unsigned bit;
	for (bit = 0; bit < max_bits; bit++) {
		if (!bitmap_test(map, map_bytes, bit))
			return (int)bit;
	}
	return -1;
}

static int flush_imap(struct minix_mount *m) {
	unsigned z;
	for (z = 0; z < m->imap_blocks; z++) {
		if (write_zone(m, 2 + z, m->imap + z * m->blocksize) != 0)
			return -1;
	}
	return 0;
}

static int flush_zmap(struct minix_mount *m) {
	unsigned z;
	unsigned base = 2 + m->imap_blocks;
	for (z = 0; z < m->zmap_blocks; z++) {
		if (write_zone(m, base + z, m->zmap + z * m->blocksize) != 0)
			return -1;
	}
	return 0;
}

/* ---------- inode R/W ---------- */

static unsigned inode_block(struct minix_mount *m, unsigned ino) {
	unsigned ipb = (m->version == MINIX_V2)
		? MINIX_INODES_PER_BLOCK_V2(m->blocksize)
		: MINIX_INODES_PER_BLOCK_V1(m->blocksize);
	unsigned first_inode_zone = 2 + m->imap_blocks + m->zmap_blocks;
	return first_inode_zone + (ino - 1) / ipb;
}

static unsigned inode_offset(struct minix_mount *m, unsigned ino) {
	unsigned isize = (m->version == MINIX_V2) ? 64u : 32u;
	unsigned ipb = m->blocksize / isize;
	return ((ino - 1) % ipb) * isize;
}

static int read_raw_inode(struct minix_mount *m, unsigned ino, void *raw, size_t raw_sz) {
	uint8_t *blk;
	unsigned zb;
	if (!m || ino == 0 || ino > m->ninodes || !raw || raw_sz == 0)
		return -1;
	blk = (uint8_t *)kmalloc(m->blocksize);
	if (!blk)
		return -1;
	zb = inode_block(m, ino);
	if (read_zone(m, zb, blk) != 0) {
		kfree(blk);
		return -1;
	}
	memcpy(raw, blk + inode_offset(m, ino), raw_sz);
	kfree(blk);
	return 0;
}

static int write_raw_inode(struct minix_mount *m, unsigned ino, const void *raw, size_t raw_sz) {
	uint8_t *blk;
	unsigned zb;
	if (!m || ino == 0 || ino > m->ninodes || !raw || raw_sz == 0)
		return -1;
	blk = (uint8_t *)kmalloc(m->blocksize);
	if (!blk)
		return -1;
	zb = inode_block(m, ino);
	if (read_zone(m, zb, blk) != 0) {
		kfree(blk);
		return -1;
	}
	memcpy(blk + inode_offset(m, ino), raw, raw_sz);
	if (write_zone(m, zb, blk) != 0) {
		kfree(blk);
		return -1;
	}
	kfree(blk);
	return 0;
}

static int load_inode(struct minix_mount *m, unsigned ino, struct minix_file_handle *fh) {
	int i;
	if (!fh)
		return -1;
	memset(fh, 0, sizeof(*fh));
	fh->m = m;
	fh->ino = ino;
	if (m->version == MINIX_V1) {
		struct minix_inode_v1 raw;
		if (read_raw_inode(m, ino, &raw, sizeof(raw)) != 0)
			return -1;
		fh->mode = raw.i_mode;
		fh->size = raw.i_size;
		fh->nzones = 9;
		for (i = 0; i < 9; i++)
			fh->zone[i] = raw.i_zone[i];
	} else {
		struct minix_inode_v2 raw;
		if (read_raw_inode(m, ino, &raw, sizeof(raw)) != 0)
			return -1;
		fh->mode = raw.i_mode;
		fh->size = raw.i_size;
		fh->nzones = 10;
		for (i = 0; i < 10; i++)
			fh->zone[i] = raw.i_zone[i];
	}
	return 0;
}

static int store_inode(struct minix_file_handle *fh) {
	struct minix_mount *m;
	int i;
	if (!fh || !fh->m)
		return -1;
	m = fh->m;
	if (m->version == MINIX_V1) {
		struct minix_inode_v1 raw;
		if (read_raw_inode(m, fh->ino, &raw, sizeof(raw)) != 0)
			return -1;
		raw.i_mode = fh->mode;
		raw.i_size = fh->size;
		for (i = 0; i < 9; i++)
			raw.i_zone[i] = (uint16_t)fh->zone[i];
		return write_raw_inode(m, fh->ino, &raw, sizeof(raw));
	} else {
		struct minix_inode_v2 raw;
		if (read_raw_inode(m, fh->ino, &raw, sizeof(raw)) != 0)
			return -1;
		raw.i_mode = fh->mode;
		raw.i_size = fh->size;
		for (i = 0; i < 10; i++)
			raw.i_zone[i] = fh->zone[i];
		return write_raw_inode(m, fh->ino, &raw, sizeof(raw));
	}
}

/* ---------- zone mapping (get_block) ---------- */

static unsigned ptrs_per_block(struct minix_mount *m) {
	return (m->version == MINIX_V2) ? (m->blocksize / 4) : (m->blocksize / 2);
}

static unsigned read_zone_ptr(struct minix_mount *m, const uint8_t *blk, unsigned idx) {
	if (m->version == MINIX_V2) {
		uint32_t v;
		memcpy(&v, blk + idx * 4, 4);
		return (unsigned)v;
	} else {
		uint16_t v;
		memcpy(&v, blk + idx * 2, 2);
		return (unsigned)v;
	}
}

static void write_zone_ptr(struct minix_mount *m, uint8_t *blk, unsigned idx, unsigned zone) {
	if (m->version == MINIX_V2) {
		uint32_t v = (uint32_t)zone;
		memcpy(blk + idx * 4, &v, 4);
	} else {
		uint16_t v = (uint16_t)zone;
		memcpy(blk + idx * 2, &v, 2);
	}
}

/*
 * Linux fs/minix/bitmap.c mapping:
 *   bit = zone - firstdatazone + 1  (bit 0 reserved)
 *   zone = bit + firstdatazone - 1
 */
static int alloc_zone(struct minix_mount *m) {
	unsigned max_bits;
	int bit;
	unsigned zone;
	uint8_t *zb;

	if (m->nzones <= m->firstdatazone)
		return -1;
	max_bits = m->nzones - m->firstdatazone + 1;
	bit = bitmap_find_zero(m->zmap, m->zmap_bytes, max_bits);
	if (bit <= 0)
		return -1;
	zone = (unsigned)bit + m->firstdatazone - 1;
	if (zone < m->firstdatazone || zone >= m->nzones)
		return -1;
	bitmap_set(m->zmap, m->zmap_bytes, (unsigned)bit);
	if (flush_zmap(m) != 0)
		return -1;
	zb = (uint8_t *)kmalloc(m->blocksize);
	if (!zb)
		return -1;
	memset(zb, 0, m->blocksize);
	if (write_zone(m, zone, zb) != 0) {
		kfree(zb);
		return -1;
	}
	kfree(zb);
	return (int)zone;
}

static void free_zone(struct minix_mount *m, unsigned zone) {
	unsigned bit;
	if (zone < m->firstdatazone || zone >= m->nzones)
		return;
	bit = zone - m->firstdatazone + 1;
	bitmap_clear(m->zmap, m->zmap_bytes, bit);
	(void)flush_zmap(m);
}

/* Resolve file block `blk` → zone. If create!=0, allocate missing zones. */
static int get_zone(struct minix_file_handle *fh, unsigned blk, int create) {
	struct minix_mount *m = fh->m;
	unsigned ppb = ptrs_per_block(m);
	unsigned zone;
	uint8_t *buf;
	int nz;

	/* 7 direct */
	if (blk < 7) {
		zone = fh->zone[blk];
		if (zone == 0 && create) {
			nz = alloc_zone(m);
			if (nz < 0)
				return -1;
			fh->zone[blk] = (uint32_t)nz;
			if (store_inode(fh) != 0)
				return -1;
			zone = (unsigned)nz;
		}
		return zone ? (int)zone : -1;
	}
	blk -= 7;

	/* single indirect */
	if (blk < ppb) {
		if (fh->zone[7] == 0) {
			if (!create)
				return -1;
			nz = alloc_zone(m);
			if (nz < 0)
				return -1;
			fh->zone[7] = (uint32_t)nz;
			if (store_inode(fh) != 0)
				return -1;
		}
		buf = (uint8_t *)kmalloc(m->blocksize);
		if (!buf)
			return -1;
		if (read_zone(m, fh->zone[7], buf) != 0) {
			kfree(buf);
			return -1;
		}
		zone = read_zone_ptr(m, buf, blk);
		if (zone == 0 && create) {
			nz = alloc_zone(m);
			if (nz < 0) {
				kfree(buf);
				return -1;
			}
			write_zone_ptr(m, buf, blk, (unsigned)nz);
			if (write_zone(m, fh->zone[7], buf) != 0) {
				kfree(buf);
				return -1;
			}
			zone = (unsigned)nz;
		}
		kfree(buf);
		return zone ? (int)zone : -1;
	}
	blk -= ppb;

	/* double indirect */
	if (blk < ppb * ppb) {
		unsigned i1 = blk / ppb;
		unsigned i2 = blk % ppb;
		unsigned z1;
		if (fh->zone[8] == 0) {
			if (!create)
				return -1;
			nz = alloc_zone(m);
			if (nz < 0)
				return -1;
			fh->zone[8] = (uint32_t)nz;
			if (store_inode(fh) != 0)
				return -1;
		}
		buf = (uint8_t *)kmalloc(m->blocksize);
		if (!buf)
			return -1;
		if (read_zone(m, fh->zone[8], buf) != 0) {
			kfree(buf);
			return -1;
		}
		z1 = read_zone_ptr(m, buf, i1);
		if (z1 == 0 && create) {
			nz = alloc_zone(m);
			if (nz < 0) {
				kfree(buf);
				return -1;
			}
			write_zone_ptr(m, buf, i1, (unsigned)nz);
			if (write_zone(m, fh->zone[8], buf) != 0) {
				kfree(buf);
				return -1;
			}
			z1 = (unsigned)nz;
		}
		if (z1 == 0) {
			kfree(buf);
			return -1;
		}
		if (read_zone(m, z1, buf) != 0) {
			kfree(buf);
			return -1;
		}
		zone = read_zone_ptr(m, buf, i2);
		if (zone == 0 && create) {
			nz = alloc_zone(m);
			if (nz < 0) {
				kfree(buf);
				return -1;
			}
			write_zone_ptr(m, buf, i2, (unsigned)nz);
			if (write_zone(m, z1, buf) != 0) {
				kfree(buf);
				return -1;
			}
			zone = (unsigned)nz;
		}
		kfree(buf);
		return zone ? (int)zone : -1;
	}

	/* V2 triple indirect — rarely needed for small volumes; reject for now */
	(void)create;
	return -1;
}

/* ---------- path / directory ---------- */

/* Compare on-disk name (padded to namelen) with a C string. */
static int name_eq(const char *disk, const char *cstr, unsigned namelen) {
	unsigned i;
	for (i = 0; i < namelen; i++) {
		char cd = disk[i];
		char cs = cstr[i];
		if (cd == '\0' && cs == '\0')
			return 1;
		if (cd != cs)
			return 0;
		if (cd == '\0' || cs == '\0')
			return 0;
	}
	/* Full namelen match: C string must end here (disk has no terminator). */
	return cstr[namelen] == '\0';
}

/* Find name in directory inode; returns child ino or 0. Optionally slot info for create. */
static unsigned dir_lookup(struct minix_file_handle *dir, const char *name,
                           unsigned *out_blk, unsigned *out_off, int *out_empty_slot) {
	struct minix_mount *m = dir->m;
	unsigned pos = 0;
	unsigned empty_blk = 0, empty_off = 0;
	int have_empty = 0;
	uint8_t *buf;

	if (out_empty_slot)
		*out_empty_slot = 0;
	buf = (uint8_t *)kmalloc(m->blocksize);
	if (!buf)
		return 0;

	while (pos < dir->size) {
		unsigned fblk = pos / m->blocksize;
		unsigned off = pos % m->blocksize;
		int zone = get_zone(dir, fblk, 0);
		if (zone < 0)
			break;
		if (off == 0) {
			if (read_zone(m, (unsigned)zone, buf) != 0)
				break;
		}
		{
			uint16_t ino;
			const char *nmp;
			memcpy(&ino, buf + off, 2);
			nmp = (const char *)(buf + off + 2);
			if (ino == 0) {
				if (!have_empty) {
					empty_blk = fblk;
					empty_off = off;
					have_empty = 1;
				}
			} else if (name_eq(nmp, name, m->namelen)) {
				if (out_blk)
					*out_blk = fblk;
				if (out_off)
					*out_off = off;
				kfree(buf);
				return ino;
			}
		}
		pos += m->dirsize;
	}
	kfree(buf);
	if (out_empty_slot && have_empty) {
		*out_empty_slot = 1;
		if (out_blk)
			*out_blk = empty_blk;
		if (out_off)
			*out_off = empty_off;
	}
	return 0;
}

static int dir_add_entry(struct minix_file_handle *dir, const char *name, unsigned ino) {
	struct minix_mount *m = dir->m;
	unsigned blk = 0, off = 0;
	int empty = 0;
	int zone;
	uint8_t *buf;
	uint16_t ino16;

	if (dir_lookup(dir, name, NULL, NULL, NULL) != 0)
		return -1; /* EEXIST */

	/* Scan for an empty directory slot. */
	{
		unsigned pos = 0;
		empty = 0;
		buf = (uint8_t *)kmalloc(m->blocksize);
		if (!buf)
			return -1;
		while (pos < dir->size) {
			unsigned fblk = pos / m->blocksize;
			unsigned o = pos % m->blocksize;
			int z = get_zone(dir, fblk, 0);
			uint16_t eino;
			if (z < 0)
				break;
			if (o == 0 && read_zone(m, (unsigned)z, buf) != 0)
				break;
			memcpy(&eino, buf + o, 2);
			if (eino == 0) {
				blk = fblk;
				off = o;
				empty = 1;
				break;
			}
			pos += m->dirsize;
		}
		kfree(buf);
	}

	if (!empty) {
		/* append new block slot */
		blk = dir->size / m->blocksize;
		off = dir->size % m->blocksize;
		if (off == 0) {
			/* need new zone */
			zone = get_zone(dir, blk, 1);
		} else {
			zone = get_zone(dir, blk, 0);
		}
		if (zone < 0)
			return -1;
		dir->size += m->dirsize;
		if (store_inode(dir) != 0)
			return -1;
	} else {
		zone = get_zone(dir, blk, 0);
		if (zone < 0)
			return -1;
	}

	buf = (uint8_t *)kmalloc(m->blocksize);
	if (!buf)
		return -1;
	if (read_zone(m, (unsigned)zone, buf) != 0) {
		kfree(buf);
		return -1;
	}
	memset(buf + off, 0, m->dirsize);
	ino16 = (uint16_t)ino;
	memcpy(buf + off, &ino16, 2);
	{
		size_t nlen = strlen(name);
		if (nlen > m->namelen)
			nlen = m->namelen;
		memcpy(buf + off + 2, name, nlen);
	}
	if (write_zone(m, (unsigned)zone, buf) != 0) {
		kfree(buf);
		return -1;
	}
	kfree(buf);
	return 0;
}

static int dir_remove_entry(struct minix_file_handle *dir, const char *name) {
	struct minix_mount *m = dir->m;
	unsigned blk = 0, off = 0;
	unsigned ino;
	int zone;
	uint8_t *buf;
	uint16_t zero = 0;

	ino = dir_lookup(dir, name, &blk, &off, NULL);
	if (ino == 0)
		return -1;
	zone = get_zone(dir, blk, 0);
	if (zone < 0)
		return -1;
	buf = (uint8_t *)kmalloc(m->blocksize);
	if (!buf)
		return -1;
	if (read_zone(m, (unsigned)zone, buf) != 0) {
		kfree(buf);
		return -1;
	}
	memcpy(buf + off, &zero, 2);
	if (write_zone(m, (unsigned)zone, buf) != 0) {
		kfree(buf);
		return -1;
	}
	kfree(buf);
	return (int)ino;
}

static int path_lookup(struct minix_mount *m, const char *rel, struct minix_file_handle *out) {
	struct minix_file_handle cur;
	char comp[64];
	const char *p;

	if (!m || !rel || !out)
		return -1;
	if (load_inode(m, MINIX_ROOT_INO, &cur) != 0)
		return -1;
	if (!S_ISDIR(cur.mode))
		return -1;

	p = rel;
	while (*p == '/')
		p++;
	if (*p == '\0') {
		*out = cur;
		return 0;
	}

	while (*p) {
		size_t n = 0;
		unsigned child;
		struct minix_file_handle next;
		while (p[n] && p[n] != '/') {
			if (n + 1 >= sizeof(comp))
				return -1;
			comp[n] = p[n];
			n++;
		}
		comp[n] = '\0';
		p += n;
		while (*p == '/')
			p++;
		if (!S_ISDIR(cur.mode))
			return -1;
		child = dir_lookup(&cur, comp, NULL, NULL, NULL);
		if (child == 0)
			return -1;
		if (load_inode(m, child, &next) != 0)
			return -1;
		cur = next;
	}
	*out = cur;
	return 0;
}

static int resolve_parent(struct minix_mount *m, const char *rel,
                          struct minix_file_handle *parent, char *basename, size_t baselen) {
	char tmp[256];
	char *slash;
	size_t len;

	if (!rel || !parent || !basename || baselen == 0)
		return -1;
	len = strlen(rel);
	if (len >= sizeof(tmp))
		return -1;
	memcpy(tmp, rel, len + 1);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';
	slash = strrchr(tmp, '/');
	if (!slash) {
		if (strlen(tmp) >= baselen)
			return -1;
		strcpy(basename, tmp);
		return load_inode(m, MINIX_ROOT_INO, parent);
	}
	*slash = '\0';
	if (slash[1] == '\0')
		return -1;
	if (strlen(slash + 1) >= baselen)
		return -1;
	strcpy(basename, slash + 1);
	if (tmp[0] == '\0')
		return load_inode(m, MINIX_ROOT_INO, parent);
	return path_lookup(m, tmp, parent);
}

/* ---------- public FS ops ---------- */

static void strip_mount_prefix(const char *path, char *out, size_t outlen) {
	char mnt[256];
	size_t mlen;
	out[0] = '\0';
	if (!path || !out || outlen == 0)
		return;
	if (fs_get_matching_mount_prefix(path, mnt, sizeof(mnt)) != 0) {
		/* not mounted yet — treat as absolute from root of FS */
		if (path[0] == '/')
			snprintf(out, outlen, "%s", path);
		else
			snprintf(out, outlen, "/%s", path);
		return;
	}
	mlen = strlen(mnt);
	if (strncmp(path, mnt, mlen) != 0) {
		snprintf(out, outlen, "%s", path);
		return;
	}
	path += mlen;
	if (*path == '\0')
		snprintf(out, outlen, "/");
	else if (*path == '/')
		snprintf(out, outlen, "%s", path);
	else
		snprintf(out, outlen, "/%s", path);
}

static int minix_open(const char *path, struct fs_file **out_file) {
	char rel[512];
	struct minix_file_handle fh;
	struct minix_file_handle *h;
	struct fs_file *f;
	char *pp;

	if (!g_minix || !path || !out_file)
		return -1;
	strip_mount_prefix(path, rel, sizeof(rel));
	if (path_lookup(g_minix, rel, &fh) != 0)
		return -1;

	h = (struct minix_file_handle *)kmalloc(sizeof(*h));
	f = (struct fs_file *)kmalloc(sizeof(*f));
	pp = (char *)kmalloc(strlen(path) + 1);
	if (!h || !f || !pp) {
		if (h) kfree(h);
		if (f) kfree(f);
		if (pp) kfree(pp);
		return -1;
	}
	*h = fh;
	memset(f, 0, sizeof(*f));
	strcpy(pp, path);
	f->path = pp;
	f->type = S_ISDIR(fh.mode) ? FS_TYPE_DIR : FS_TYPE_REG;
	f->size = fh.size;
	f->pos = 0;
	f->refcount = 1;
	f->fs_private = &minix_driver;
	f->driver_private = h;
	*out_file = f;
	return 0;
}

static ssize_t minix_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
	struct minix_file_handle *fh;
	struct minix_mount *m;
	uint8_t *out;
	size_t done = 0;
	uint8_t *zbuf;

	if (!file || !file->driver_private || !buf)
		return -1;
	fh = (struct minix_file_handle *)file->driver_private;
	m = fh->m ? fh->m : g_minix;
	if (!m)
		return -1;

	/* Directory: emit Linux/ext2-compatible dirents for getdents. */
	if (file->type == FS_TYPE_DIR || S_ISDIR(fh->mode)) {
		size_t pos = 0, emit = 0, copied = 0;
		uint8_t *dirbuf = (uint8_t *)kmalloc(m->blocksize);
		if (!dirbuf)
			return -1;
		out = (uint8_t *)buf;
		while (pos < fh->size && copied < size) {
			unsigned fblk = (unsigned)(pos / m->blocksize);
			unsigned off = (unsigned)(pos % m->blocksize);
			int zone = get_zone(fh, fblk, 0);
			uint16_t ino;
			char name[64];
			size_t namelen, rec_len, entry_off, tocopy;
			struct ext2_dir_entry de;
			uint8_t tmp[128];

			if (zone < 0)
				break;
			if (off == 0 && read_zone(m, (unsigned)zone, dirbuf) != 0)
				break;
			memcpy(&ino, dirbuf + off, 2);
			memset(name, 0, sizeof(name));
			memcpy(name, dirbuf + off + 2, m->namelen);
			name[m->namelen] = '\0';
			pos += m->dirsize;
			if (ino == 0 || name[0] == '\0')
				continue;
			namelen = strlen(name);
			rec_len = (8 + namelen + 3) & ~3u;
			if (rec_len < 12)
				rec_len = 12;
			if (emit + rec_len <= offset) {
				emit += rec_len;
				continue;
			}
			memset(tmp, 0, sizeof(tmp));
			de.inode = ino;
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = EXT2_FT_UNKNOWN;
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, name, namelen);
			entry_off = (offset > emit) ? (offset - emit) : 0;
			tocopy = rec_len - entry_off;
			if (tocopy > size - copied)
				tocopy = size - copied;
			memcpy(out + copied, tmp + entry_off, tocopy);
			copied += tocopy;
			emit += rec_len;
		}
		kfree(dirbuf);
		return (ssize_t)copied;
	}

	/* Regular file */
	if (offset >= fh->size)
		return 0;
	if (offset + size > fh->size)
		size = fh->size - offset;
	zbuf = (uint8_t *)kmalloc(m->blocksize);
	if (!zbuf)
		return -1;
	out = (uint8_t *)buf;
	while (done < size) {
		unsigned fblk = (unsigned)((offset + done) / m->blocksize);
		unsigned off = (unsigned)((offset + done) % m->blocksize);
		size_t chunk = m->blocksize - off;
		int zone;
		if (chunk > size - done)
			chunk = size - done;
		zone = get_zone(fh, fblk, 0);
		if (zone < 0) {
			memset(out + done, 0, chunk); /* hole */
		} else {
			if (read_zone(m, (unsigned)zone, zbuf) != 0) {
				kfree(zbuf);
				return done ? (ssize_t)done : -1;
			}
			memcpy(out + done, zbuf + off, chunk);
		}
		done += chunk;
	}
	kfree(zbuf);
	return (ssize_t)done;
}

static ssize_t minix_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
	struct minix_file_handle *fh;
	struct minix_mount *m;
	const uint8_t *in;
	size_t done = 0;
	uint8_t *zbuf;

	if (!file || !file->driver_private || !buf)
		return -1;
	fh = (struct minix_file_handle *)file->driver_private;
	m = fh->m ? fh->m : g_minix;
	if (!m || S_ISDIR(fh->mode))
		return -1;
	/* Allow append and in-place overwrite; reject sparse holes beyond EOF. */
	if (offset > fh->size)
		return -1;
	zbuf = (uint8_t *)kmalloc(m->blocksize);
	if (!zbuf)
		return -1;
	in = (const uint8_t *)buf;
	while (done < size) {
		unsigned fblk = (unsigned)((offset + done) / m->blocksize);
		unsigned off = (unsigned)((offset + done) % m->blocksize);
		size_t chunk = m->blocksize - off;
		int zone;
		if (chunk > size - done)
			chunk = size - done;
		zone = get_zone(fh, fblk, 1);
		if (zone < 0) {
			kfree(zbuf);
			return done ? (ssize_t)done : -1;
		}
		if (off != 0 || chunk != m->blocksize) {
			if (read_zone(m, (unsigned)zone, zbuf) != 0) {
				kfree(zbuf);
				return done ? (ssize_t)done : -1;
			}
		} else {
			memset(zbuf, 0, m->blocksize);
		}
		memcpy(zbuf + off, in + done, chunk);
		if (write_zone(m, (unsigned)zone, zbuf) != 0) {
			kfree(zbuf);
			return done ? (ssize_t)done : -1;
		}
		done += chunk;
	}
	kfree(zbuf);
	if (offset + done > fh->size) {
		fh->size = (uint32_t)(offset + done);
		file->size = fh->size;
		if (store_inode(fh) != 0)
			return -1;
	}
	return (ssize_t)done;
}

static int alloc_inode(struct minix_mount *m, uint16_t mode, struct minix_file_handle *out) {
	int bit;
	unsigned ino;
	int i;

	bit = bitmap_find_zero(m->imap, m->imap_bytes, m->ninodes + 1);
	if (bit <= 0)
		return -1;
	ino = (unsigned)bit;
	bitmap_set(m->imap, m->imap_bytes, ino);
	if (flush_imap(m) != 0)
		return -1;

	memset(out, 0, sizeof(*out));
	out->m = m;
	out->ino = ino;
	out->mode = mode;
	out->size = 0;
	out->nzones = (m->version == MINIX_V2) ? 10 : 9;
	for (i = 0; i < 10; i++)
		out->zone[i] = 0;

	if (m->version == MINIX_V1) {
		struct minix_inode_v1 raw;
		memset(&raw, 0, sizeof(raw));
		raw.i_mode = mode;
		raw.i_nlinks = 1;
		raw.i_uid = 0;
		raw.i_gid = 0;
		return write_raw_inode(m, ino, &raw, sizeof(raw));
	} else {
		struct minix_inode_v2 raw;
		memset(&raw, 0, sizeof(raw));
		raw.i_mode = mode;
		raw.i_nlinks = 1;
		return write_raw_inode(m, ino, &raw, sizeof(raw));
	}
}

static void bump_nlink(struct minix_mount *m, unsigned ino, int delta) {
	if (m->version == MINIX_V1) {
		struct minix_inode_v1 raw;
		if (read_raw_inode(m, ino, &raw, sizeof(raw)) != 0)
			return;
		if (delta > 0)
			raw.i_nlinks = (uint8_t)(raw.i_nlinks + (uint8_t)delta);
		else if (raw.i_nlinks > 0)
			raw.i_nlinks = (uint8_t)(raw.i_nlinks - 1);
		(void)write_raw_inode(m, ino, &raw, sizeof(raw));
	} else {
		struct minix_inode_v2 raw;
		if (read_raw_inode(m, ino, &raw, sizeof(raw)) != 0)
			return;
		if (delta > 0)
			raw.i_nlinks = (uint16_t)(raw.i_nlinks + (uint16_t)delta);
		else if (raw.i_nlinks > 0)
			raw.i_nlinks--;
		(void)write_raw_inode(m, ino, &raw, sizeof(raw));
	}
}

static int minix_create(const char *path, struct fs_file **out_file) {
	char rel[512], base[64];
	struct minix_file_handle parent, neu;

	if (!g_minix || !path || !out_file)
		return -1;
	strip_mount_prefix(path, rel, sizeof(rel));
	if (resolve_parent(g_minix, rel, &parent, base, sizeof(base)) != 0)
		return -1;
	if (!S_ISDIR(parent.mode))
		return -1;
	if (dir_lookup(&parent, base, NULL, NULL, NULL) != 0)
		return -1; /* exists */
	if (alloc_inode(g_minix, (uint16_t)(S_IFREG | 0644), &neu) != 0)
		return -1;
	if (dir_add_entry(&parent, base, neu.ino) != 0)
		return -1;
	return minix_open(path, out_file);
}

static int minix_mkdir(const char *path) {
	char rel[512], base[64];
	struct minix_file_handle parent, neu;

	if (!g_minix || !path)
		return -1;
	strip_mount_prefix(path, rel, sizeof(rel));
	if (resolve_parent(g_minix, rel, &parent, base, sizeof(base)) != 0)
		return -1;
	if (!S_ISDIR(parent.mode))
		return -1;
	if (dir_lookup(&parent, base, NULL, NULL, NULL) != 0)
		return -1;
	if (alloc_inode(g_minix, (uint16_t)(S_IFDIR | 0755), &neu) != 0)
		return -1;
	/* . and .. */
	if (dir_add_entry(&neu, ".", neu.ino) != 0)
		return -1;
	if (dir_add_entry(&neu, "..", parent.ino) != 0)
		return -1;
	bump_nlink(g_minix, neu.ino, 1);     /* . */
	bump_nlink(g_minix, parent.ino, 1);  /* .. */
	if (dir_add_entry(&parent, base, neu.ino) != 0)
		return -1;
	return 0;
}

static int minix_unlink(const char *path) {
	char rel[512], base[64];
	struct minix_file_handle parent, victim;
	int ino;

	if (!g_minix || !path)
		return -1;
	strip_mount_prefix(path, rel, sizeof(rel));
	if (resolve_parent(g_minix, rel, &parent, base, sizeof(base)) != 0)
		return -1;
	if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
		return -1;
	ino = dir_remove_entry(&parent, base);
	if (ino <= 0)
		return -1;
	if (load_inode(g_minix, (unsigned)ino, &victim) != 0)
		return -1;
	if (S_ISDIR(victim.mode))
		return -1; /* use rmdir — not implemented as separate; refuse non-empty later */
	/* free data zones (direct only for simplicity — truncate full would be better) */
	{
		unsigned b, maxb = (victim.size + g_minix->blocksize - 1) / g_minix->blocksize;
		for (b = 0; b < maxb && b < 7; b++) {
			if (victim.zone[b]) {
				free_zone(g_minix, victim.zone[b]);
				victim.zone[b] = 0;
			}
		}
	}
	bitmap_clear(g_minix->imap, g_minix->imap_bytes, (unsigned)ino);
	(void)flush_imap(g_minix);
	{
		uint8_t zero[64];
		memset(zero, 0, sizeof(zero));
		(void)write_raw_inode(g_minix, (unsigned)ino, zero,
		                      g_minix->version == MINIX_V2 ? 64 : 32);
	}
	return 0;
}

static void minix_release(struct fs_file *file) {
	if (!file)
		return;
	if (file->driver_private) {
		kfree(file->driver_private);
		file->driver_private = NULL;
	}
	if (file->path) {
		kfree((void *)file->path);
		file->path = NULL;
	}
	kfree(file);
}

int minix_fill_stat(struct fs_file *file, struct stat *st) {
	struct minix_file_handle *fh;
	if (!file || !st || !file->driver_private)
		return -1;
	fh = (struct minix_file_handle *)file->driver_private;
	memset(st, 0, sizeof(*st));
	st->st_ino = fh->ino;
	st->st_mode = fh->mode;
	st->st_nlink = 1;
	st->st_size = (off_t)fh->size;
	return 0;
}

/* ---------- mount / probe ---------- */

static void minix_free_mount(struct minix_mount *m) {
	if (!m)
		return;
	if (m->imap)
		kfree(m->imap);
	if (m->zmap)
		kfree(m->zmap);
	kfree(m);
}

static int minix_bind_device(int device_id, uint32_t start_lba) {
	uint8_t sector[1024];
	struct minix_super_block sb;
	struct minix_mount *m;
	unsigned blocksize;
	unsigned spb;
	unsigned z;
	int version = 0;
	unsigned namelen = 0, dirsize = 0;
	unsigned nzones;

	/* Superblock at byte offset 1024 → LBA start+2 when 512-byte sectors. */
	if (disk_read_sectors(device_id, start_lba + 2, sector, 2) != 0)
		return -1;
	memcpy(&sb, sector, sizeof(sb));

	if (sb.s_magic == MINIX_SUPER_MAGIC) {
		version = MINIX_V1; namelen = 14; dirsize = 16;
	} else if (sb.s_magic == MINIX_SUPER_MAGIC2) {
		version = MINIX_V1; namelen = 30; dirsize = 32;
	} else if (sb.s_magic == MINIX2_SUPER_MAGIC) {
		version = MINIX_V2; namelen = 14; dirsize = 16;
	} else if (sb.s_magic == MINIX2_SUPER_MAGIC2) {
		version = MINIX_V2; namelen = 30; dirsize = 32;
	} else {
		return -1;
	}

	blocksize = 1024u << sb.s_log_zone_size;
	if (blocksize < 512 || blocksize > 4096 || (blocksize % 512) != 0)
		return -1;
	spb = blocksize / 512;
	nzones = (version == MINIX_V2) ? sb.s_zones : sb.s_nzones;
	if (sb.s_ninodes == 0 || nzones < 3 || sb.s_imap_blocks == 0 || sb.s_zmap_blocks == 0)
		return -1;
	if (sb.s_firstdatazone >= nzones)
		return -1;

	m = (struct minix_mount *)kmalloc(sizeof(*m));
	if (!m)
		return -1;
	memset(m, 0, sizeof(*m));
	m->device_id = device_id;
	m->start_lba = start_lba;
	m->version = version;
	m->blocksize = blocksize;
	m->sectors_per_block = spb;
	m->ninodes = sb.s_ninodes;
	m->nzones = nzones;
	m->imap_blocks = sb.s_imap_blocks;
	m->zmap_blocks = sb.s_zmap_blocks;
	m->firstdatazone = sb.s_firstdatazone;
	m->log_zone_size = sb.s_log_zone_size;
	m->dirsize = dirsize;
	m->namelen = namelen;
	m->max_size = sb.s_max_size;
	m->magic = sb.s_magic;
	m->imap_bytes = (size_t)m->imap_blocks * blocksize;
	m->zmap_bytes = (size_t)m->zmap_blocks * blocksize;
	m->imap = (uint8_t *)kmalloc(m->imap_bytes);
	m->zmap = (uint8_t *)kmalloc(m->zmap_bytes);
	if (!m->imap || !m->zmap) {
		minix_free_mount(m);
		return -1;
	}
	for (z = 0; z < m->imap_blocks; z++) {
		if (read_zone(m, 2 + z, m->imap + z * blocksize) != 0) {
			minix_free_mount(m);
			return -1;
		}
	}
	for (z = 0; z < m->zmap_blocks; z++) {
		if (read_zone(m, 2 + m->imap_blocks + z, m->zmap + z * blocksize) != 0) {
			minix_free_mount(m);
			return -1;
		}
	}

	if (g_minix)
		minix_free_mount(g_minix);
	g_minix = m;
	minix_driver.driver_data = m;
	klogprintf("minix: mounted V%d magic=0x%x zones=%u inodes=%u bsize=%u namelen=%u\n",
	           version, (unsigned)m->magic, m->nzones, m->ninodes, m->blocksize, m->namelen);
	return 0;
}

int minix_probe_and_mount(int device_id) {
	if (device_id < 0)
		return -1;
	return minix_bind_device(device_id, 0);
}

int minix_probe_and_mount_geom(int device_id, uint32_t start_lba) {
	if (device_id < 0)
		return -1;
	return minix_bind_device(device_id, start_lba);
}

void minix_unmount_cleanup(void) {
	if (!g_minix)
		return;
	minix_free_mount(g_minix);
	g_minix = NULL;
	minix_driver.driver_data = NULL;
}

struct fs_driver *minix_get_driver(void) {
	return &minix_driver;
}

int minix_register(void) {
	minix_ops.name = "minix";
	minix_ops.create = minix_create;
	minix_ops.mkdir = minix_mkdir;
	minix_ops.open = minix_open;
	minix_ops.read = minix_read;
	minix_ops.write = minix_write;
	minix_ops.release = minix_release;
	minix_ops.unlink = minix_unlink;
	minix_ops.chmod = NULL;
	minix_driver.ops = &minix_ops;
	minix_driver.driver_data = NULL;
	klogprintf("minix: registering filesystem driver\n");
	return fs_register_driver(&minix_driver);
}

int minix_unregister(void) {
	minix_unmount_cleanup();
	return fs_unregister_driver(&minix_driver);
}
