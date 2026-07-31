#pragma once

#include <stdint.h>
#include <stddef.h>

#define DISK_MAX_DEVICES 16
#define DISK_SECTOR_SIZE 512

/* Linux block majors used for /dev nodes and st_rdev. */
#define DISK_MAJOR_SD   8   /* SCSI/SATA disks (sdX) */
#define DISK_MAJOR_SR  11   /* SCSI CD-ROM (srN) */
#define DISK_MAJOR_HD   3   /* legacy IDE (hdN) — unused by modern paths */

typedef struct disk_ops {
	const char *name;
	int (*init)(void);
	int (*read)(int device_id, uint32_t lba, void *buf, uint32_t sectors);
	int (*write)(int device_id, uint32_t lba, const void *buf, uint32_t sectors);
} disk_ops_t;

int disk_register(disk_ops_t *ops);
int disk_count(void);
int disk_read_sectors(int device_id, uint32_t lba, void *buf, uint32_t sectors);
int disk_write_sectors(int device_id, uint32_t lba, const void *buf, uint32_t sectors);

int disk_publish_sd(int device_id, uint32_t sectors);
int disk_publish_sr(int device_id, uint32_t sectors);
int disk_sd_index(int device_id);
int disk_sr_index(int device_id);
