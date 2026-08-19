/* ISO 9660 / Joliet (Linux isofs) — read-only mount from a block device. */
#pragma once

#include <fs.h>
#include <stddef.h>
#include <stdint.h>

int isofs_register(void);
int isofs_unregister(void);
int isofs_probe_and_mount(int device_id, uint32_t start_lba, uint32_t sectors);
void isofs_unmount_cleanup(void);
struct fs_driver *isofs_get_driver(void);
int isofs_fill_stat(struct fs_file *file, struct stat *st);
