#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

int fat32_register(void);
int fat32_unregister(void);
int fat32_mount_from_device(int device_id);
int fat32_probe_and_mount(int device_id);
int fat32_probe_and_mount_geom(int device_id, uint32_t start_lba);
void fat32_unmount_cleanup(void);
struct fs_driver *fat32_get_driver(void);
int fat32_fill_stat(struct fs_file *file, struct stat *st);
int fat32_ftruncate(struct fs_file *file, off_t length);

/* Minimal Linux-compatible statfs fields for SYS_statfs. */
struct statfs_k {
    long f_type;
    long f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    uint64_t f_fsid;
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};
int fat32_statfs(struct statfs_k *out);

