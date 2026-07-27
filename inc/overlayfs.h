/* Minimal overlayfs: upper=ramfs, lower=squashfs (Linux live-root style). */
#pragma once

#include <fs.h>
#include <stat.h>

#ifdef __cplusplus
extern "C" {
#endif

int overlayfs_register(void);
int overlayfs_unregister(void);

/* Replace the VFS mount at "/" with overlay (upper=ramfs, lower=prepared squashfs).
 * Requires squashfs_prepare_image() and an existing ramfs tree. */
int overlayfs_mount_root(void);

struct fs_driver *overlayfs_get_driver(void);
int overlayfs_fill_stat(struct fs_file *file, struct stat *st);
int overlayfs_ftruncate(struct fs_file *file, off_t length);

#ifdef __cplusplus
}
#endif
