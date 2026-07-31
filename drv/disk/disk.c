/*
 * Main kernel disk interface + Linux-style /dev naming.
*/

#include <disk.h>
#include <devfs.h>
#include <axonos.h>
#include <string.h>
#include <vga.h>
#include <klog.h>

static disk_ops_t *g_disks[DISK_MAX_DEVICES];
static int g_disk_count = 0;

static int g_sd_count = 0;
static int g_sr_count = 0;
static int8_t g_sd_index_by_id[DISK_MAX_DEVICES];
static int8_t g_sr_index_by_id[DISK_MAX_DEVICES];
static int g_name_map_inited = 0;

static void disk_name_map_init(void) {
	if (g_name_map_inited)
		return;
	for (int i = 0; i < DISK_MAX_DEVICES; i++) {
		g_sd_index_by_id[i] = -1;
		g_sr_index_by_id[i] = -1;
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

static uint32_t disk_le32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void disk_publish_mbr_partitions(int device_id, char letter, uint32_t disk_sectors) {
	uint8_t mbr[512];
	if (disk_read_sectors(device_id, 0, mbr, 1) != 0)
		return;
	if (mbr[510] != 0x55 || mbr[511] != 0xAA)
		return;
	for (int i = 0; i < 4; i++) {
		const uint8_t *e = &mbr[446 + i * 16];
		uint8_t part_type = e[4];
		uint32_t start_lba = disk_le32(e + 8);
		uint32_t part_sectors = disk_le32(e + 12);
		if (part_type == 0x00 || part_type == 0xCD)
			continue;
		if (part_sectors == 0)
			continue;
		if (start_lba >= disk_sectors)
			continue;
		if (start_lba + part_sectors < start_lba)
			continue;
		if (start_lba + part_sectors > disk_sectors)
			part_sectors = disk_sectors - start_lba;
		char ppath[32];
		snprintf(ppath, sizeof(ppath), "/dev/sd%c%d", letter, i + 1);
		(void)devfs_create_block_node_lba(ppath, device_id, start_lba, part_sectors);
	}
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
	if (devfs_create_block_node(path, device_id, sectors) != 0) {
		g_sd_count--;
		g_sd_index_by_id[device_id] = -1;
		return -1;
	}
	disk_publish_mbr_partitions(device_id, letter, sectors);
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
	if (idx == 0)
		(void)devfs_create_block_node("/dev/cdrom", device_id, sectors);
	klogprintf("disk: published /dev/sr%d (disk_id=%d, %u sectors)%s\n",
	           idx, device_id, sectors, idx == 0 ? " + /dev/cdrom" : "");
	return idx;
}
