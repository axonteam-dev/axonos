/* Linux xattr(7) / *xattr(2) — VFS + ramfs/overlay storage. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>

#ifndef XATTR_CREATE
#define XATTR_CREATE  0x1
#endif
#ifndef XATTR_REPLACE
#define XATTR_REPLACE 0x2
#endif

#define XATTR_NAME_MAX  255
#define XATTR_SIZE_MAX  65536
#define XATTR_LIST_MAX  65536

#ifdef __cplusplus
extern "C" {
#endif

/* follow: 1 = getxattr/listxattr/setxattr/removexattr; 0 = l* variants.
 * Returns byte count (>=0) or negative -errno (Linux). */
ssize_t vfs_getxattr(const char *path, const char *name, void *value, size_t size, int follow);
ssize_t vfs_listxattr(const char *path, char *list, size_t size, int follow);
int vfs_setxattr(const char *path, const char *name, const void *value, size_t size, int flags, int follow);
int vfs_removexattr(const char *path, const char *name, int follow);

ssize_t vfs_fgetxattr(struct fs_file *file, const char *name, void *value, size_t size);
ssize_t vfs_flistxattr(struct fs_file *file, char *list, size_t size);
int vfs_fsetxattr(struct fs_file *file, const char *name, const void *value, size_t size, int flags);
int vfs_fremovexattr(struct fs_file *file, const char *name);

#ifdef __cplusplus
}
#endif
