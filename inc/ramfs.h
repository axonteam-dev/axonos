#ifndef INC_RAMFS_H
#define INC_RAMFS_H

#include <stddef.h>
#include <fs.h>
#include <stat.h>

int ramfs_register(void);
int ramfs_unregister(void);
struct fs_driver *ramfs_get_driver(void);
int ramfs_mkdir(const char *path);
int ramfs_remove(const char *path);
/* create a symbolic link at 'path' pointing to 'target' */
int ramfs_symlink(const char *path, const char *target);
/* create a hard link: newpath points to same inode as oldpath */
int ramfs_link(const char *oldpath, const char *newpath);
/* Linux linkat(olddirfd, "", newpath, AT_EMPTY_PATH): name an open inode. */
int ramfs_link_open_file(struct fs_file *file, const char *newpath);
/* create a regular file backed by immutable boot-time data; copied on first write */
int ramfs_create_borrowed_file(const char *path, const void *data, size_t size);
int ramfs_make_whiteout(const char *path);
int ramfs_path_is_whiteout(const char *path);

#ifdef __cplusplus
extern "C" {
#endif
/* Fill stat for an open ramfs file (driver-specific) */
int ramfs_fill_stat(struct fs_file *file, struct stat *st);
/* Set regular file length (ftruncate). Returns 0 or negative -errno. */
int ramfs_ftruncate(struct fs_file *file, off_t length);
int ramfs_chmod(const char *path, mode_t mode);
int ramfs_chown(const char *path, uid_t uid, gid_t gid);
int ramfs_lchown(const char *path, uid_t uid, gid_t gid);
/* Linux xattr on ramfs/tmpfs inodes (see xattr.h). */
ssize_t ramfs_getxattr(const char *path, const char *name, void *value, size_t size);
ssize_t ramfs_listxattr(const char *path, char *list, size_t size);
int ramfs_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int ramfs_removexattr(const char *path, const char *name);
#ifdef __cplusplus
}
#endif

#endif /* INC_RAMFS_H */
