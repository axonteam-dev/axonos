/* Minix filesystem — Linux-compatible on-disk layout (V1/V2). */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

int minix_register(void);
int minix_unregister(void);
int minix_probe_and_mount(int device_id);
void minix_unmount_cleanup(void);
struct fs_driver *minix_get_driver(void);
int minix_fill_stat(struct fs_file *file, struct stat *st);

/* Linux magic numbers (include/uapi/linux/minix_fs.h). */
#define MINIX_SUPER_MAGIC   0x137F  /* V1, 14-char names */
#define MINIX_SUPER_MAGIC2  0x138F  /* V1, 30-char names */
#define MINIX2_SUPER_MAGIC  0x2468  /* V2, 14-char names */
#define MINIX2_SUPER_MAGIC2 0x2478  /* V2, 30-char names */

#define MINIX_ROOT_INO 1
