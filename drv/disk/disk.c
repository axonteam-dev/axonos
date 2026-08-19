/*
 * Main kernel disk interface + Linux-style /dev naming.
*/

#include <disk.h>
#include <devfs.h>
#include <axonos.h>
#include <string.h>
#include <stdio.h>
#include <heap.h>
#include <vga.h>
#include <klog.h>

static disk_ops_t *g_disks[DISK_MAX_DEVICES];
static int g_disk_count = 0;

static int g_sd_count = 0;
static int g_sr_count = 0;
static int8_t g_sd_index_by_id[DISK_MAX_DEVICES];
static int8_t g_sr_index_by_id[DISK_MAX_DEVICES];
static uint32_t g_disk_sectors[DISK_MAX_DEVICES];
static int g_name_map_inited = 0;

static void disk_name_map_init(void) {
	if (g_name_map_inited)
		return;
	for (int i = 0; i < DISK_MAX_DEVICES; i++) {
		g_sd_index_by_id[i] = -1;
		g_sr_index_by_id[i] = -1;
		g_disk_sectors[i] = 0;
	}
	g_name_map_inited = 1;
}

int disk_register(disk_ops_t *ops) {
	disk_name_map_init();
	if (!ops || g_disk_count >= DISK_MAX_DEVICES) return -1;
	g_disks[g_disk_count] = ops;
	int id = g_disk_count++;
	if (ops->init) {
		int r = ops->init();
		if (r != 0) {
			klogprintf("disk: fatal: Driver %s init failed\n", ops->name ? ops->name : "unknown");
			g_disks[id] = NULL;
			g_disk_count--;
			return -1;
		}
	}
	klogprintf("disk: Registered device %d -> %s\n", id, ops->name ? ops->name : "unnamed");
	return id;
}

int disk_count(void) {
	return g_disk_count;
}

int disk_read_sectors(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= g_disk_count) return -1;
	disk_ops_t *d = g_disks[device_id];
	if (!d || !d->read) return -1;
	return d->read(device_id, lba, buf, sectors);
}

int disk_write_sectors(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= g_disk_count) return -1;
	disk_ops_t *d = g_disks[device_id];
	if (!d || !d->write) return -1;
	return d->write(device_id, lba, buf, sectors);
}

int disk_sd_index(int device_id) {
	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	return (int)g_sd_index_by_id[device_id];
}

int disk_sr_index(int device_id) {
	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	return (int)g_sr_index_by_id[device_id];
}

void disk_note_capacity(int device_id, uint32_t sectors) {
	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return;
	g_disk_sectors[device_id] = sectors;
}

int disk_get_capacity(int device_id, uint32_t *sectors) {
	disk_name_map_init();
	if (!sectors || device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	if (g_disk_sectors[device_id] == 0)
		return -1;
	*sectors = g_disk_sectors[device_id];
	return 0;
}

static uint32_t disk_le32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t disk_le64(const uint8_t *p) {
	return (uint64_t)disk_le32(p) | ((uint64_t)disk_le32(p + 4) << 32);
}

static int disk_guid_zero(const uint8_t *g) {
	for (int i = 0; i < 16; i++)
		if (g[i])
			return 0;
	return 1;
}

static void disk_part_path(const char *whole, int partno, char *out, size_t cap) {
	const char *base = whole;
	int nvme;

	if (!whole || !out || cap < 8 || partno < 1)
		return;
	if (strncmp(whole, "/dev/", 5) == 0)
		base = whole + 5;
	nvme = (strncmp(base, "nvme", 4) == 0);
	if (nvme)
		snprintf(out, cap, "/dev/%sp%d", base, partno);
	else
		snprintf(out, cap, "/dev/%s%d", base, partno);
}

static void disk_add_part(int device_id, const char *whole, int partno,
			  uint32_t start, uint32_t count, uint32_t disk_sectors) {
	char ppath[40];

	if (!count || start >= disk_sectors)
		return;
	if (start + count < start)
		return;
	if (start + count > disk_sectors)
		count = disk_sectors - start;
	disk_part_path(whole, partno, ppath, sizeof(ppath));
	(void)devfs_create_block_node_lba(ppath, device_id, start, count);
}

static int disk_mbr_is_gpt_protective(const uint8_t *mbr) {
	int seen_ee = 0;
	int data = 0;

	if (mbr[510] != 0x55 || mbr[511] != 0xAA)
		return 0;
	for (int i = 0; i < 4; i++) {
		uint8_t t = mbr[446 + i * 16 + 4];
		if (t == 0x00)
			continue;
		if (t == 0xEE)
			seen_ee = 1;
		else if (t != 0xCD)
			data = 1;
	}
	return seen_ee && !data;
}

static void disk_publish_gpt(int device_id, const char *whole, uint32_t disk_sectors) {
	uint8_t hdr[512];
	uint64_t part_lba;
	uint32_t part_count, ent_sz, i, bytes, nsec;
	uint8_t *ents;

	if (disk_read_sectors(device_id, 1, hdr, 1) != 0)
		return;
	if (memcmp(hdr, "EFI PART", 8) != 0)
		return;
	part_lba = disk_le64(hdr + 72);
	part_count = disk_le32(hdr + 80);
	ent_sz = disk_le32(hdr + 84);
	if (part_lba < 2 || part_count == 0 || part_count > 128 || ent_sz < 128 || ent_sz > 512)
		return;
	bytes = part_count * ent_sz;
	nsec = (bytes + 511u) / 512u;
	if (nsec == 0 || nsec > 32)
		return;
	ents = (uint8_t *)kmalloc(nsec * 512u);
	if (!ents)
		return;
	if (disk_read_sectors(device_id, (uint32_t)part_lba, ents, nsec) != 0) {
		kfree(ents);
		return;
	}
	for (i = 0; i < part_count; i++) {
		const uint8_t *e = ents + i * ent_sz;
		uint64_t first, last;
		uint32_t start, count;

		if (disk_guid_zero(e))
			continue;
		first = disk_le64(e + 32);
		last = disk_le64(e + 40);
		if (last < first || first > 0xffffffffull)
			continue;
		start = (uint32_t)first;
		if (last - first + 1 > 0xffffffffull)
			count = 0xffffffffu;
		else
			count = (uint32_t)(last - first + 1);
		disk_add_part(device_id, whole, (int)i + 1, start, count, disk_sectors);
	}
	kfree(ents);
}

static void disk_publish_ebr(int device_id, const char *whole, uint32_t ebr_lba,
			     uint32_t disk_sectors, int *next_logical) {
	uint32_t cur = ebr_lba;
	int hops = 0;

	while (hops++ < 64) {
		uint8_t ebr[512];
		const uint8_t *e0, *e1;
		uint8_t t0, t1;
		uint32_t rel, nsec, next_rel;

		if (disk_read_sectors(device_id, cur, ebr, 1) != 0)
			return;
		if (ebr[510] != 0x55 || ebr[511] != 0xAA)
			return;
		e0 = ebr + 446;
		e1 = ebr + 462;
		t0 = e0[4];
		rel = disk_le32(e0 + 8);
		nsec = disk_le32(e0 + 12);
		if (t0 && t0 != 0x05 && t0 != 0x0F && t0 != 0x85 && nsec) {
			disk_add_part(device_id, whole, *next_logical, cur + rel, nsec, disk_sectors);
			(*next_logical)++;
		}
		t1 = e1[4];
		next_rel = disk_le32(e1 + 8);
		if (!(t1 == 0x05 || t1 == 0x0F || t1 == 0x85) || next_rel == 0)
			return;
		cur = ebr_lba + next_rel;
	}
}

static void disk_publish_msdos(int device_id, const char *whole, uint32_t disk_sectors,
			       const uint8_t *mbr) {
	int logical = 5;

	for (int i = 0; i < 4; i++) {
		const uint8_t *e = &mbr[446 + i * 16];
		uint8_t part_type = e[4];
		uint32_t start_lba = disk_le32(e + 8);
		uint32_t part_sectors = disk_le32(e + 12);
		if (part_type == 0x00 || part_type == 0xCD)
			continue;
		if (part_type == 0x05 || part_type == 0x0F || part_type == 0x85) {
			disk_publish_ebr(device_id, whole, start_lba, disk_sectors, &logical);
			continue;
		}
		if (part_sectors == 0)
			continue;
		disk_add_part(device_id, whole, i + 1, start_lba, part_sectors, disk_sectors);
	}
}

static void disk_publish_table(int device_id, const char *whole, uint32_t disk_sectors) {
	uint8_t mbr[512];

	if (!whole || disk_read_sectors(device_id, 0, mbr, 1) != 0)
		return;
	if (disk_mbr_is_gpt_protective(mbr)) {
		disk_publish_gpt(device_id, whole, disk_sectors);
		return;
	}
	if (mbr[510] != 0x55 || mbr[511] != 0xAA)
		return;
	disk_publish_msdos(device_id, whole, disk_sectors, mbr);
}

int disk_reread_partitions(int device_id) {
	char whole[40];
	uint32_t secs = 0;

	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	if (devfs_whole_disk_path(device_id, whole, sizeof(whole)) != 0)
		return -1;
	if (strncmp(whole, "/dev/sr", 7) == 0 || strcmp(whole, "/dev/cdrom") == 0)
		return 0;
	if (disk_get_capacity(device_id, &secs) != 0 || secs == 0)
		return -1;
	devfs_remove_partitions_of(whole);
	disk_publish_table(device_id, whole, secs);
	klogprintf("disk: BLKRRPART %s (%u sectors)\n", whole, secs);
	return 0;
}

static void disk_publish_mbr_partitions(int device_id, const char *whole, uint32_t disk_sectors) {
	disk_publish_table(device_id, whole, disk_sectors);
}

int disk_publish_sd(int device_id, uint32_t sectors) {
	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	if (g_sd_count >= 26)
		return -1;
	if (g_sd_index_by_id[device_id] >= 0)
		return (int)g_sd_index_by_id[device_id];

	int idx = g_sd_count++;
	g_sd_index_by_id[device_id] = (int8_t)idx;
	char letter = (char)('a' + idx);
	char path[32];
	snprintf(path, sizeof(path), "/dev/sd%c", letter);
	disk_note_capacity(device_id, sectors);
	if (devfs_create_block_node(path, device_id, sectors) != 0) {
		g_sd_count--;
		g_sd_index_by_id[device_id] = -1;
		return -1;
	}
	disk_publish_mbr_partitions(device_id, path, sectors);
	klogprintf("disk: published /dev/sd%c (disk_id=%d, %u sectors)\n",
	           letter, device_id, sectors);
	return idx;
}

int disk_publish_sr(int device_id, uint32_t sectors) {
	disk_name_map_init();
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES)
		return -1;
	if (g_sr_count >= 32)
		return -1;
	if (g_sr_index_by_id[device_id] >= 0)
		return (int)g_sr_index_by_id[device_id];

	int idx = g_sr_count++;
	g_sr_index_by_id[device_id] = (int8_t)idx;
	char path[32];
	snprintf(path, sizeof(path), "/dev/sr%d", idx);
	if (devfs_create_block_node(path, device_id, sectors) != 0) {
		g_sr_count--;
		g_sr_index_by_id[device_id] = -1;
		return -1;
	}
	disk_note_capacity(device_id, sectors);
	if (idx == 0)
		(void)devfs_create_block_node("/dev/cdrom", device_id, sectors);
	klogprintf("disk: published /dev/sr%d (disk_id=%d, %u sectors)%s\n",
	           idx, device_id, sectors, idx == 0 ? " + /dev/cdrom" : "");
	return idx;
}
