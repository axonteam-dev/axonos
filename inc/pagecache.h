#pragma once

#include <stdint.h>
#include <fs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAGECACHE_ID_SQUASHFS(ino) (0x5300000000000000ULL | (uint64_t)(uint32_t)(ino))
#define PAGECACHE_ID_RAMFS(ino)    (0x7200000000000000ULL | (uint64_t)(unsigned long)(ino))

/*
 * Linux filemap_get_page: one clean 4 KiB frame for (backing, gen, index).
 * On success *pa_out holds a frame with an extra ref for the caller to consume
 * as PG_SOFT_OWNED (or frame_release if the mapping is not installed).
 */
int pagecache_get(struct fs_file *file, uint64_t file_off, uint64_t *pa_out);

/* Drop every cached frame for this inode (all generations). */
void pagecache_invalidate(uint64_t backing_id);

#ifdef __cplusplus
}
#endif
