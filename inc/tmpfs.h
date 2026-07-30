#ifndef INC_TMPFS_H
#define INC_TMPFS_H

/* Linux mount -t tmpfs|ramfs: volatile mount registered in the VFS table.
 * Backed by the same in-memory store as ramfs (root is already ramfs). */
int tmpfs_mount(const char *path);

#endif /* INC_TMPFS_H */
