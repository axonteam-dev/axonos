/* SquashFS 4.0 — read-only mount from a memory image (Linux semantics). */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>
#include <stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SQUASHFS_MAGIC 0x73717368u /* "hsqs" little-endian */

/* Register the squashfs VFS driver (does not mount a path). */
int squashfs_register(void);
int squashfs_unregister(void);

/* Prepare a SquashFS image already resident in identity-mapped RAM.
 * Does not install a VFS mount by itself — use overlay or squashfs_mount(). */
int squashfs_prepare_image(const void *image, size_t size);

/* Mount prepared image at path (typically used under overlay, or RO at path). */
int squashfs_mount(const char *path);

/* True if a prepared image is ready. */
int squashfs_is_ready(void);
int squashfs_get_image(const void **ptr, size_t *size);

struct fs_driver *squashfs_get_driver(void);

/* Direct open relative to squashfs root ("/bin/sh"). Used by overlay lower. */
int squashfs_open_path(const char *path, struct fs_file **out_file);
ssize_t squashfs_read_file(struct fs_file *file, void *buf, size_t size, size_t offset);
void squashfs_release_file(struct fs_file *file);
int squashfs_fill_stat(struct fs_file *file, struct stat *st);

/* Probe magic at pointer. */
static inline int squashfs_image_looks_valid(const void *image, size_t size)
{
    const uint8_t *p;
    if (!image || size < 96)
        return 0;
    p = (const uint8_t *)image;
    return p[0] == 'h' && p[1] == 's' && p[2] == 'q' && p[3] == 's';
}

#ifdef __cplusplus
}
#endif
