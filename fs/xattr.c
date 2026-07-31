/*
 * Linux *xattr(2) VFS dispatch.
 * Filesystems without handlers return -EOPNOTSUPP (not ENOSYS).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <xattr.h>
#include <ramfs.h>
#include <overlayfs.h>
#include <heap.h>

#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef ERANGE
#define ERANGE 34
#endif
#ifndef E2BIG
#define E2BIG 7
#endif
#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36
#endif
#ifndef EBADF
#define EBADF 9
#endif

/* Exported from fs.c — open without following a final symlink. */
struct fs_file *fs_open_nofollow(const char *path);

static int xattr_name_ok(const char *name) {
    size_t n;
    const char *dot;
    if (!name || !name[0])
        return 0;
    n = strlen(name);
    if (n > XATTR_NAME_MAX)
        return 0;
    if (name[0] == '.' || name[n - 1] == '.')
        return 0;
    dot = strchr(name, '.');
    if (!dot || dot == name || !dot[1])
        return 0;
    /* Linux namespaces: user / trusted / system / security */
    if (strncmp(name, "user.", 5) == 0)
        return 1;
    if (strncmp(name, "trusted.", 8) == 0)
        return 1;
    if (strncmp(name, "system.", 7) == 0)
        return 1;
    if (strncmp(name, "security.", 9) == 0)
        return 1;
    return 0;
}

static ssize_t vfs_xattr_dispatch_get(const char *path, const char *name,
                                      void *value, size_t size) {
    struct fs_driver *md;
    const char *fsn;
    if (!path || !name)
        return -EFAULT;
    if (!xattr_name_ok(name))
        return -EINVAL;
    if (size > XATTR_SIZE_MAX)
        size = XATTR_SIZE_MAX;
    md = fs_get_mount_driver(path);
    if (!md || !md->ops || !md->ops->name)
        return -EOPNOTSUPP;
    fsn = md->ops->name;
    if (strcmp(fsn, "ramfs") == 0 || strcmp(fsn, "tmpfs") == 0)
        return ramfs_getxattr(path, name, value, size);
    if (strcmp(fsn, "overlay") == 0 || strcmp(fsn, "overlayfs") == 0)
        return overlayfs_getxattr(path, name, value, size);
    return -EOPNOTSUPP;
}

static ssize_t vfs_xattr_dispatch_list(const char *path, char *list, size_t size) {
    struct fs_driver *md;
    const char *fsn;
    if (!path)
        return -EFAULT;
    if (size > XATTR_LIST_MAX)
        size = XATTR_LIST_MAX;
    md = fs_get_mount_driver(path);
    if (!md || !md->ops || !md->ops->name)
        return -EOPNOTSUPP;
    fsn = md->ops->name;
    if (strcmp(fsn, "ramfs") == 0 || strcmp(fsn, "tmpfs") == 0)
        return ramfs_listxattr(path, list, size);
    if (strcmp(fsn, "overlay") == 0 || strcmp(fsn, "overlayfs") == 0)
        return overlayfs_listxattr(path, list, size);
    return -EOPNOTSUPP;
}

static int vfs_xattr_dispatch_set(const char *path, const char *name,
                                  const void *value, size_t size, int flags) {
    struct fs_driver *md;
    const char *fsn;
    if (!path || !name)
        return -EFAULT;
    if (!xattr_name_ok(name))
        return -EINVAL;
    if (size > XATTR_SIZE_MAX)
        return -E2BIG;
    if (flags & ~(XATTR_CREATE | XATTR_REPLACE))
        return -EINVAL;
    if ((flags & XATTR_CREATE) && (flags & XATTR_REPLACE))
        return -EINVAL;
    md = fs_get_mount_driver(path);
    if (!md || !md->ops || !md->ops->name)
        return -EOPNOTSUPP;
    fsn = md->ops->name;
    if (strcmp(fsn, "ramfs") == 0 || strcmp(fsn, "tmpfs") == 0)
        return ramfs_setxattr(path, name, value, size, flags);
    if (strcmp(fsn, "overlay") == 0 || strcmp(fsn, "overlayfs") == 0)
        return overlayfs_setxattr(path, name, value, size, flags);
    return -EOPNOTSUPP;
}

static int vfs_xattr_dispatch_remove(const char *path, const char *name) {
    struct fs_driver *md;
    const char *fsn;
    if (!path || !name)
        return -EFAULT;
    if (!xattr_name_ok(name))
        return -EINVAL;
    md = fs_get_mount_driver(path);
    if (!md || !md->ops || !md->ops->name)
        return -EOPNOTSUPP;
    fsn = md->ops->name;
    if (strcmp(fsn, "ramfs") == 0 || strcmp(fsn, "tmpfs") == 0)
        return ramfs_removexattr(path, name);
    if (strcmp(fsn, "overlay") == 0 || strcmp(fsn, "overlayfs") == 0)
        return overlayfs_removexattr(path, name);
    return -EOPNOTSUPP;
}

static const char *file_xattr_path(struct fs_file *file) {
    return (file && file->path) ? file->path : NULL;
}

ssize_t vfs_getxattr(const char *path, const char *name, void *value, size_t size, int follow) {
    struct fs_file *f;
    const char *p;
    ssize_t r;
    if (!path || !name)
        return -EFAULT;
    f = follow ? fs_open(path) : fs_open_nofollow(path);
    if (!f)
        return -ENOENT;
    p = file_xattr_path(f);
    if (!p) {
        fs_file_free(f);
        return -ENOENT;
    }
    r = vfs_xattr_dispatch_get(p, name, value, size);
    fs_file_free(f);
    return r;
}

ssize_t vfs_listxattr(const char *path, char *list, size_t size, int follow) {
    struct fs_file *f;
    const char *p;
    ssize_t r;
    if (!path)
        return -EFAULT;
    f = follow ? fs_open(path) : fs_open_nofollow(path);
    if (!f)
        return -ENOENT;
    p = file_xattr_path(f);
    if (!p) {
        fs_file_free(f);
        return -ENOENT;
    }
    r = vfs_xattr_dispatch_list(p, list, size);
    fs_file_free(f);
    return r;
}

int vfs_setxattr(const char *path, const char *name, const void *value, size_t size,
                 int flags, int follow) {
    struct fs_file *f;
    const char *p;
    int r;
    if (!path || !name)
        return -EFAULT;
    /* setxattr follows; lsetxattr does not. Path must exist either way. */
    f = follow ? fs_open(path) : fs_open_nofollow(path);
    if (!f)
        return -ENOENT;
    p = file_xattr_path(f);
    if (!p) {
        fs_file_free(f);
        return -ENOENT;
    }
    /* Keep path string: free file before mutating upper/copy-up. */
    {
        char kpath[512];
        size_t n = strlen(p);
        if (n >= sizeof(kpath)) {
            fs_file_free(f);
            return -ENAMETOOLONG;
        }
        memcpy(kpath, p, n + 1);
        fs_file_free(f);
        r = vfs_xattr_dispatch_set(kpath, name, value, size, flags);
    }
    return r;
}

int vfs_removexattr(const char *path, const char *name, int follow) {
    struct fs_file *f;
    const char *p;
    int r;
    char kpath[512];
    size_t n;
    if (!path || !name)
        return -EFAULT;
    f = follow ? fs_open(path) : fs_open_nofollow(path);
    if (!f)
        return -ENOENT;
    p = file_xattr_path(f);
    if (!p) {
        fs_file_free(f);
        return -ENOENT;
    }
    n = strlen(p);
    if (n >= sizeof(kpath)) {
        fs_file_free(f);
        return -ENAMETOOLONG;
    }
    memcpy(kpath, p, n + 1);
    fs_file_free(f);
    return vfs_xattr_dispatch_remove(kpath, name);
}

ssize_t vfs_fgetxattr(struct fs_file *file, const char *name, void *value, size_t size) {
    const char *p = file_xattr_path(file);
    if (!file)
        return -EBADF;
    if (!p || !name)
        return -EFAULT;
    return vfs_xattr_dispatch_get(p, name, value, size);
}

ssize_t vfs_flistxattr(struct fs_file *file, char *list, size_t size) {
    const char *p = file_xattr_path(file);
    if (!file)
        return -EBADF;
    if (!p)
        return -EFAULT;
    return vfs_xattr_dispatch_list(p, list, size);
}

int vfs_fsetxattr(struct fs_file *file, const char *name, const void *value, size_t size, int flags) {
    const char *p = file_xattr_path(file);
    if (!file)
        return -EBADF;
    if (!p || !name)
        return -EFAULT;
    return vfs_xattr_dispatch_set(p, name, value, size, flags);
}

int vfs_fremovexattr(struct fs_file *file, const char *name) {
    const char *p = file_xattr_path(file);
    if (!file)
        return -EBADF;
    if (!p || !name)
        return -EFAULT;
    return vfs_xattr_dispatch_remove(p, name);
}
