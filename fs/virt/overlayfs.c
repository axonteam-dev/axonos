/*
 * Minimal overlayfs for boot root: upper=ramfs, lower=squashfs.
 * Linux live-CD style — squashfs stays mapped; writes go to ramfs (copy-up).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <heap.h>
#include <fs.h>
#include <stat.h>
#include <ext2.h>
#include <ramfs.h>
#include <squashfs.h>
#include <overlayfs.h>
#include <xattr.h>
#include <klog.h>

#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

enum {
    OV_LAYER_UPPER = 1,
    OV_LAYER_LOWER = 2,
    OV_LAYER_MERGED_DIR = 3,
};

struct overlay_file_handle {
    int layer;
    struct fs_file *inner;
    uint8_t *dir_blob;
    size_t dir_blob_len;
};

static struct fs_driver overlay_driver;
static struct fs_driver_ops overlay_ops;
static int overlay_active = 0;
static void overlay_release(struct fs_file *file);

static struct fs_driver *ov_upper(void)
{
    return ramfs_get_driver();
}

static int ov_upper_open(const char *path, struct fs_file **out)
{
    struct fs_driver *u = ov_upper();
    if (!u || !u->ops || !u->ops->open)
        return -1;
    return u->ops->open(path, out);
}

static int ov_upper_create(const char *path, struct fs_file **out)
{
    struct fs_driver *u = ov_upper();
    if (!u || !u->ops || !u->ops->create)
        return -1;
    return u->ops->create(path, out);
}

static void ov_release_inner(struct fs_file *inner)
{
    struct fs_driver *drv;
    if (!inner)
        return;
    drv = ramfs_get_driver();
    if (drv && inner->fs_private == drv->driver_data && drv->ops && drv->ops->release) {
        drv->ops->release(inner);
        return;
    }
    if (squashfs_get_driver() && inner->fs_private == squashfs_get_driver()->driver_data) {
        squashfs_release_file(inner);
        return;
    }
    /* Fallback */
    squashfs_release_file(inner);
}

static int ov_is_upper_file(struct fs_file *inner)
{
    struct fs_driver *u = ov_upper();
    return u && inner && inner->fs_private == u->driver_data;
}

/* True if path is a directory on squashfs lower (merged view without upper). */
static int ov_lower_is_dir(const char *path)
{
    struct fs_file *lo = NULL;
    struct stat st;
    if (!path || squashfs_open_path(path, &lo) != 0)
        return 0;
    int ok = (squashfs_fill_stat(lo, &st) == 0) &&
             ((st.st_mode & S_IFDIR) == S_IFDIR);
    ov_release_inner(lo);
    return ok;
}

/*
 * Ensure every parent of `path` exists as a directory in the ramfs upper.
 * Squashfs-only dirs (e.g. /mnt from the image) are materialized into upper so
 * mkdir /mnt/c works — Linux overlay copy-up of the parent directory.
 */
static int ov_ensure_parent_upper(const char *path)
{
    char tmp[512];
    size_t len;
    char *slash;
    struct fs_file *chk = NULL;

    if (!path || path[0] != '/')
        return -1;
    len = strlen(path);
    if (len >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, len + 1);
    slash = strrchr(tmp, '/');
    if (!slash)
        return -1;
    if (slash == tmp)
        return 0; /* parent is "/" */
    *slash = '\0';

    if (ov_upper_open(tmp, &chk) == 0) {
        int ok = (chk->type == FS_TYPE_DIR);
        ov_release_inner(chk);
        return ok ? 0 : -1;
    }

    /* Recurse first so /a/b materializes /a before /a/b. */
    if (ov_ensure_parent_upper(tmp) != 0)
        return -1;

    /* Materialize lower-only directory into upper (no whiteout). */
    if (ramfs_path_is_whiteout(tmp))
        return -1;
    if (ramfs_mkdir(tmp) == 0)
        return 0;
    /* EEXIST / race: confirm upper dir now. */
    if (ov_upper_open(tmp, &chk) == 0) {
        int ok = (chk->type == FS_TYPE_DIR);
        ov_release_inner(chk);
        if (ok)
            return 0;
        return -1;
    }
    /* Parent missing on upper but present on lower — create empty upper dir. */
    if (ov_lower_is_dir(tmp) && ramfs_mkdir(tmp) == 0)
        return 0;
    return -1;
}

/*
 * O_TRUNC / ftruncate(0): create an empty upper (Linux overlay copy-up for
 * truncate-to-zero). Do NOT full-copy lower then discard — that kmallocs a
 * squashfs block and on failure leaves an orphan empty upper that permanently
 * shadows the good lower file.
 */
static int ov_copy_up_empty(const char *path)
{
    struct fs_file *up = NULL;
    if (!path)
        return -1;
    if (ramfs_path_is_whiteout(path)) {
        if (ramfs_remove(path) != 0)
            return -1;
    }
    if (ov_upper_open(path, &up) == 0) {
        int ok = (up->type == FS_TYPE_REG);
        ov_release_inner(up);
        return ok ? 0 : -1;
    }
    if (ov_ensure_parent_upper(path) != 0)
        return -1;
    if (ov_upper_create(path, &up) != 0)
        return -1;
    ov_release_inner(up);
    /* Match lower mode so sourced scripts stay readable/executable. */
    {
        struct fs_file *lo = NULL;
        struct stat st;
        if (squashfs_open_path(path, &lo) == 0) {
            if (squashfs_fill_stat(lo, &st) == 0)
                (void)ramfs_chmod(path, st.st_mode);
            ov_release_inner(lo);
        }
    }
    return 0;
}

static int ov_copy_up(const char *path)
{
    struct fs_file *lower = NULL;
    struct fs_file *upper = NULL;
    struct stat st;
    uint8_t *buf = NULL;
    size_t sz, off = 0;
    const size_t CHUNK = 64 * 1024;

    if (!path)
        return -1;
    if (ramfs_path_is_whiteout(path))
        return -1;
    if (ov_upper_open(path, &upper) == 0) {
        int ok = (upper->type == FS_TYPE_REG);
        ov_release_inner(upper);
        return ok ? 0 : -1;
    }
    if (squashfs_open_path(path, &lower) != 0)
        return -1;
    if (squashfs_fill_stat(lower, &st) != 0) {
        ov_release_inner(lower);
        return -1;
    }
    if ((st.st_mode & S_IFLNK) == S_IFLNK) {
        char target[512];
        ssize_t n = squashfs_read_file(lower, target, sizeof(target) - 1, 0);
        ov_release_inner(lower);
        if (n < 0)
            return -1;
        target[n] = '\0';
        if (ov_ensure_parent_upper(path) != 0)
            return -1;
        return ramfs_symlink(path, target) == 0 ? 0 : -1;
    }
    if ((st.st_mode & S_IFDIR) == S_IFDIR) {
        ov_release_inner(lower);
        if (ov_ensure_parent_upper(path) != 0)
            return -1;
        return ramfs_mkdir(path) == 0 ? 0 : -1;
    }
    sz = (size_t)st.st_size;
    if (ov_ensure_parent_upper(path) != 0) {
        ov_release_inner(lower);
        return -1;
    }
    if (ov_upper_create(path, &upper) != 0) {
        ov_release_inner(lower);
        return -1;
    }
    if (sz > 0) {
        buf = (uint8_t *)kmalloc(CHUNK);
        if (!buf)
            goto copy_fail;
        while (off < sz) {
            size_t want = sz - off;
            ssize_t nr, nw;
            if (want > CHUNK)
                want = CHUNK;
            nr = squashfs_read_file(lower, buf, want, off);
            if (nr <= 0)
                goto copy_fail;
            nw = ov_upper()->ops->write(upper, buf, (size_t)nr, off);
            if (nw != nr)
                goto copy_fail;
            off += (size_t)nr;
        }
        kfree(buf);
        buf = NULL;
    }
    ov_release_inner(lower);
    ov_release_inner(upper);
    (void)ramfs_chmod(path, st.st_mode);
    return 0;
copy_fail:
    /* Never leave an orphan upper that shadows a good squashfs lower. */
    kfree(buf);
    ov_release_inner(lower);
    ov_release_inner(upper);
    (void)ramfs_remove(path);
    return -1;
}

static int ov_name_in_blob(const uint8_t *blob, size_t len, const char *name)
{
    size_t off = 0;
    size_t nlen = strlen(name);
    while (off + 8 <= len) {
        const struct ext2_dir_entry *de = (const struct ext2_dir_entry *)(blob + off);
        if (de->rec_len < 8)
            break;
        if (off + de->rec_len > len)
            break;
        if (de->name_len == nlen && memcmp(blob + off + 8, name, nlen) == 0)
            return 1;
        off += de->rec_len;
    }
    return 0;
}

static int ov_append_dirent(uint8_t **blob, size_t *len, size_t *cap,
                            const char *name, uint8_t ftype, uint32_t ino)
{
    size_t namelen = strlen(name);
    size_t rec = (8 + namelen + 3) & ~3u;
    struct ext2_dir_entry de;
    if (*len + rec > *cap) {
        size_t ncap = *cap ? *cap * 2 : 512;
        uint8_t *n;
        while (ncap < *len + rec)
            ncap *= 2;
        n = (uint8_t *)kmalloc(ncap);
        if (!n)
            return -1;
        if (*blob)
            memcpy(n, *blob, *len);
        kfree(*blob);
        *blob = n;
        *cap = ncap;
    }
    memset(*blob + *len, 0, rec);
    de.inode = ino ? ino : 1;
    de.rec_len = (uint16_t)rec;
    de.name_len = (uint8_t)namelen;
    de.file_type = ftype;
    memcpy(*blob + *len, &de, 8);
    memcpy(*blob + *len + 8, name, namelen);
    *len += rec;
    return 0;
}

static int ov_merge_readdir(const char *path, uint8_t **out_blob, size_t *out_len)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    uint8_t *blob = NULL;
    size_t len = 0, cap = 0;
    uint8_t tmp[512];
    size_t pos;
    char mnames[8][64];
    int mc, mi;

    *out_blob = NULL;
    *out_len = 0;

    (void)ov_append_dirent(&blob, &len, &cap, ".", EXT2_FT_DIR, 1);
    (void)ov_append_dirent(&blob, &len, &cap, "..", EXT2_FT_DIR, 1);

    if (ov_upper_open(path, &up) == 0 && up->type == FS_TYPE_DIR) {
        pos = 0;
        for (;;) {
            ssize_t nr = ov_upper()->ops->read(up, tmp, sizeof(tmp), pos);
            size_t off = 0;
            if (nr <= 0)
                break;
            while (off + 8 <= (size_t)nr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry *)(tmp + off);
                char name[256];
                char full[512];
                size_t nlen;
                if (de->rec_len < 8)
                    break;
                if (off + de->rec_len > (size_t)nr)
                    break;
                nlen = de->name_len < sizeof(name) - 1 ? de->name_len : sizeof(name) - 1;
                memcpy(name, tmp + off + 8, nlen);
                name[nlen] = '\0';
                if (strcmp(name, ".") && strcmp(name, "..")) {
                    if (strcmp(path, "/") == 0)
                        snprintf(full, sizeof(full), "/%s", name);
                    else
                        snprintf(full, sizeof(full), "%s/%s", path, name);
                    if (!ramfs_path_is_whiteout(full) && !ov_name_in_blob(blob, len, name))
                        (void)ov_append_dirent(&blob, &len, &cap, name, de->file_type, de->inode);
                }
                off += de->rec_len;
            }
            if (off == 0)
                break;
            pos += off;
            if ((size_t)nr < sizeof(tmp))
                break;
        }
        ov_release_inner(up);
    }

    if (squashfs_open_path(path, &lo) == 0 && lo->type == FS_TYPE_DIR) {
        pos = 0;
        for (;;) {
            ssize_t nr = squashfs_read_file(lo, tmp, sizeof(tmp), pos);
            size_t off = 0;
            if (nr <= 0)
                break;
            while (off + 8 <= (size_t)nr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry *)(tmp + off);
                char name[256];
                char full[512];
                size_t nlen;
                if (de->rec_len < 8)
                    break;
                if (off + de->rec_len > (size_t)nr)
                    break;
                nlen = de->name_len < sizeof(name) - 1 ? de->name_len : sizeof(name) - 1;
                memcpy(name, tmp + off + 8, nlen);
                name[nlen] = '\0';
                if (strcmp(name, ".") && strcmp(name, "..")) {
                    if (strcmp(path, "/") == 0)
                        snprintf(full, sizeof(full), "/%s", name);
                    else
                        snprintf(full, sizeof(full), "%s/%s", path, name);
                    if (!ramfs_path_is_whiteout(full) && !ov_name_in_blob(blob, len, name))
                        (void)ov_append_dirent(&blob, &len, &cap, name, de->file_type, de->inode);
                }
                off += de->rec_len;
            }
            if (off == 0)
                break;
            pos += off;
            if ((size_t)nr < sizeof(tmp))
                break;
        }
        ov_release_inner(lo);
    }

    mc = fs_get_mount_children(path, mnames, 8);
    for (mi = 0; mi < mc; mi++) {
        if (mnames[mi][0] && !ov_name_in_blob(blob, len, mnames[mi]))
            (void)ov_append_dirent(&blob, &len, &cap, mnames[mi], EXT2_FT_DIR, 1);
    }

    *out_blob = blob;
    *out_len = len;
    return 0;
}

static struct fs_file *ov_wrap(const char *path, struct fs_file *inner, int layer)
{
    struct fs_file *f;
    struct overlay_file_handle *fh;
    size_t plen;
    char *pp;

    f = (struct fs_file *)kmalloc(sizeof(*f));
    if (!f)
        return NULL;
    memset(f, 0, sizeof(*f));
    plen = strlen(path) + 1;
    pp = (char *)kmalloc(plen);
    if (!pp) {
        kfree(f);
        return NULL;
    }
    memcpy(pp, path, plen);
    fh = (struct overlay_file_handle *)kmalloc(sizeof(*fh));
    if (!fh) {
        kfree(pp);
        kfree(f);
        return NULL;
    }
    memset(fh, 0, sizeof(*fh));
    fh->layer = layer;
    fh->inner = inner;
    f->path = pp;
    f->size = inner ? inner->size : 0;
    f->type = inner ? inner->type : FS_TYPE_DIR;
    f->fs_private = (void *)&overlay_driver;
    f->driver_private = fh;
    return f;
}

static int overlay_open(const char *path, struct fs_file **out_file)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    struct fs_file *f;
    struct overlay_file_handle *fh;
    int upper_dir = 0, lower_dir = 0;
    size_t plen;
    char *pp;

    if (!overlay_active || !path || path[0] != '/' || !out_file)
        return -1;
    if (ramfs_path_is_whiteout(path))
        return -2;

    if (ov_upper_open(path, &up) == 0) {
        if (up->type == FS_TYPE_DIR) {
            upper_dir = 1;
        } else {
            f = ov_wrap(path, up, OV_LAYER_UPPER);
            if (!f) {
                ov_release_inner(up);
                return -4;
            }
            *out_file = f;
            return 0;
        }
    }

    if (squashfs_open_path(path, &lo) == 0) {
        if (lo->type == FS_TYPE_DIR) {
            lower_dir = 1;
        } else if (!upper_dir) {
            f = ov_wrap(path, lo, OV_LAYER_LOWER);
            if (!f) {
                ov_release_inner(lo);
                if (up)
                    ov_release_inner(up);
                return -4;
            }
            if (up)
                ov_release_inner(up);
            *out_file = f;
            return 0;
        }
    }

    if (upper_dir || lower_dir || strcmp(path, "/") == 0) {
        if (up) {
            ov_release_inner(up);
            up = NULL;
        }
        if (lo) {
            ov_release_inner(lo);
            lo = NULL;
        }
        f = (struct fs_file *)kmalloc(sizeof(*f));
        if (!f)
            return -4;
        memset(f, 0, sizeof(*f));
        plen = strlen(path) + 1;
        pp = (char *)kmalloc(plen);
        if (!pp) {
            kfree(f);
            return -4;
        }
        memcpy(pp, path, plen);
        fh = (struct overlay_file_handle *)kmalloc(sizeof(*fh));
        if (!fh) {
            kfree(pp);
            kfree(f);
            return -4;
        }
        memset(fh, 0, sizeof(*fh));
        fh->layer = OV_LAYER_MERGED_DIR;
        if (ov_merge_readdir(path, &fh->dir_blob, &fh->dir_blob_len) != 0) {
            kfree(fh);
            kfree(pp);
            kfree(f);
            return -2;
        }
        f->path = pp;
        f->size = (off_t)fh->dir_blob_len;
        f->type = FS_TYPE_DIR;
        f->fs_private = (void *)&overlay_driver;
        f->driver_private = fh;
        *out_file = f;
        return 0;
    }

    if (up)
        ov_release_inner(up);
    if (lo)
        ov_release_inner(lo);
    return -2;
}

static int overlay_create(const char *path, struct fs_file **out_file)
{
    struct fs_file *inner = NULL;
    struct fs_file *f;
    if (!overlay_active || !path)
        return -1;
    if (ov_ensure_parent_upper(path) != 0)
        return -2;
    if (ov_upper_create(path, &inner) != 0)
        return -2;
    f = ov_wrap(path, inner, OV_LAYER_UPPER);
    if (!f) {
        ov_release_inner(inner);
        return -4;
    }
    if (out_file)
        *out_file = f;
    else
        overlay_release(f);
    return 0;
}

static int overlay_mkdir(const char *path)
{
    int r;
    if (!overlay_active || !path)
        return -1;
    if (ramfs_path_is_whiteout(path)) {
        if (ramfs_remove(path) != 0)
            return -1;
    }
    /* Already a directory in the merged view → EEXIST (Linux). */
    {
        struct fs_file *chk = NULL;
        if (ov_upper_open(path, &chk) == 0) {
            int is_dir = (chk->type == FS_TYPE_DIR);
            ov_release_inner(chk);
            return is_dir ? -4 : -3; /* EEXIST / ENOTDIR */
        }
        if (ov_lower_is_dir(path))
            return -4;
    }
    if (ov_ensure_parent_upper(path) != 0)
        return -2; /* ENOENT — parent missing in merged view */
    r = ramfs_mkdir(path);
    if (r == -4)
        return -4; /* EEXIST */
    if (r == -2)
        return -2;
    if (r == -3)
        return -3;
    return r;
}

static ssize_t overlay_read(struct fs_file *file, void *buf, size_t size, size_t offset)
{
    struct overlay_file_handle *fh;
    if (!file || !file->driver_private || !buf)
        return -1;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh->layer == OV_LAYER_MERGED_DIR) {
        if (!fh->dir_blob)
            return -1;
        if (offset >= fh->dir_blob_len)
            return 0;
        if (offset + size > fh->dir_blob_len)
            size = fh->dir_blob_len - offset;
        memcpy(buf, fh->dir_blob + offset, size);
        return (ssize_t)size;
    }
    if (!fh->inner)
        return -1;
    if (fh->layer == OV_LAYER_UPPER)
        return ov_upper()->ops->read(fh->inner, buf, size, offset);
    return squashfs_read_file(fh->inner, buf, size, offset);
}

static int overlay_promote_for_write(struct fs_file *file)
{
    struct overlay_file_handle *fh;
    struct fs_file *neu = NULL;
    if (!file || !file->path || !file->driver_private)
        return -1;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh->layer == OV_LAYER_UPPER)
        return 0;
    if (fh->layer != OV_LAYER_LOWER)
        return -1;
    if (ov_copy_up(file->path) != 0)
        return -1;
    if (ov_upper_open(file->path, &neu) != 0)
        return -1;
    ov_release_inner(fh->inner);
    fh->inner = neu;
    fh->layer = OV_LAYER_UPPER;
    file->size = neu->size;
    return 0;
}

static ssize_t overlay_write(struct fs_file *file, const void *buf, size_t size, size_t offset)
{
    struct overlay_file_handle *fh;
    ssize_t nw;
    if (!file || !file->driver_private || !buf)
        return -1;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh->layer == OV_LAYER_MERGED_DIR)
        return -1;
    if (overlay_promote_for_write(file) != 0)
        return -1;
    fh = (struct overlay_file_handle *)file->driver_private;
    nw = ov_upper()->ops->write(fh->inner, buf, size, offset);
    if (nw >= 0 && fh->inner)
        file->size = fh->inner->size;
    return nw;
}

static void overlay_release(struct fs_file *file)
{
    struct overlay_file_handle *fh;
    if (!file)
        return;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh) {
        if (fh->inner)
            ov_release_inner(fh->inner);
        if (fh->dir_blob)
            kfree(fh->dir_blob);
        kfree(fh);
    }
    if (file->path)
        kfree((void *)file->path);
    kfree(file);
}

static int overlay_chmod(const char *path, mode_t mode)
{
    if (!overlay_active || !path)
        return -1;
    if (ov_copy_up(path) != 0) {
        /* upper-only path */
        if (ov_ensure_parent_upper(path) != 0)
            return -1;
    }
    return ramfs_chmod(path, mode);
}

static int overlay_link(const char *oldpath, const char *newpath)
{
    if (!overlay_active)
        return -1;
    if (ov_copy_up(oldpath) != 0)
        return -1;
    if (ov_ensure_parent_upper(newpath) != 0)
        return -1;
    return ramfs_link(oldpath, newpath);
}

static int overlay_rename(const char *oldpath, const char *newpath)
{
    struct fs_driver *u = ov_upper();
    if (!overlay_active || !u || !u->ops || !u->ops->rename)
        return -1;
    if (ov_copy_up(oldpath) != 0)
        return -1;
    if (ov_ensure_parent_upper(newpath) != 0)
        return -1;
    return u->ops->rename(oldpath, newpath);
}

static int overlay_unlink(const char *path)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    int in_upper = 0, in_lower = 0;

    if (!overlay_active || !path)
        return -1;
    if (ov_upper_open(path, &up) == 0) {
        in_upper = 1;
        ov_release_inner(up);
    }
    if (squashfs_open_path(path, &lo) == 0) {
        in_lower = 1;
        ov_release_inner(lo);
    }
    if (in_upper) {
        if (ramfs_remove(path) != 0)
            return -1;
        if (in_lower)
            return ramfs_make_whiteout(path);
        return 0;
    }
    if (in_lower) {
        if (ov_ensure_parent_upper(path) != 0)
            return -1;
        return ramfs_make_whiteout(path);
    }
    return -1;
}

int overlayfs_symlink(const char *path, const char *target)
{
    if (!overlay_active || !path || !target)
        return -1;
    if (ramfs_path_is_whiteout(path)) {
        if (ramfs_remove(path) != 0)
            return -1;
    }
    if (ov_ensure_parent_upper(path) != 0)
        return -1;
    return ramfs_symlink(path, target);
}

/*
 * Linux overlay: xattrs live on the layer that owns the inode.
 * Lower (squashfs) has no xattr reader yet → -EOPNOTSUPP.
 * set/remove always copy-up then operate on upper (ramfs).
 */
ssize_t overlayfs_getxattr(const char *path, const char *name, void *value, size_t size)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    if (!overlay_active || !path || !name)
        return -EINVAL;
    if (ramfs_path_is_whiteout(path))
        return -ENOENT;
    if (ov_upper_open(path, &up) == 0) {
        ov_release_inner(up);
        return ramfs_getxattr(path, name, value, size);
    }
    if (squashfs_open_path(path, &lo) == 0) {
        ov_release_inner(lo);
        /* SquashFS may store xattrs on disk; we do not decode them yet. */
        return -EOPNOTSUPP;
    }
    return -ENOENT;
}

ssize_t overlayfs_listxattr(const char *path, char *list, size_t size)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    if (!overlay_active || !path)
        return -EINVAL;
    if (ramfs_path_is_whiteout(path))
        return -ENOENT;
    if (ov_upper_open(path, &up) == 0) {
        ov_release_inner(up);
        return ramfs_listxattr(path, list, size);
    }
    if (squashfs_open_path(path, &lo) == 0) {
        ov_release_inner(lo);
        return -EOPNOTSUPP;
    }
    return -ENOENT;
}

int overlayfs_setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    struct fs_file *up = NULL;
    struct fs_file *lo = NULL;
    if (!overlay_active || !path || !name)
        return -EINVAL;
    if (ramfs_path_is_whiteout(path))
        return -ENOENT;
    if (ov_upper_open(path, &up) == 0) {
        ov_release_inner(up);
        return ramfs_setxattr(path, name, value, size, flags);
    }
    if (squashfs_open_path(path, &lo) != 0)
        return -ENOENT;
    ov_release_inner(lo);
    /* Linux: copy-up the inode, then set xattr on upper. */
    if (ov_copy_up(path) != 0)
        return -ENOENT;
    return ramfs_setxattr(path, name, value, size, flags);
}

int overlayfs_removexattr(const char *path, const char *name)
{
    struct fs_file *up = NULL;
    if (!overlay_active || !path || !name)
        return -EINVAL;
    if (ramfs_path_is_whiteout(path))
        return -ENOENT;
    if (ov_upper_open(path, &up) == 0) {
        ov_release_inner(up);
        return ramfs_removexattr(path, name);
    }
    /* Attr only on lower → unsupported until squashfs xattrs are decoded. */
    {
        struct fs_file *lo = NULL;
        if (squashfs_open_path(path, &lo) == 0) {
            ov_release_inner(lo);
            return -EOPNOTSUPP;
        }
    }
    return -ENOENT;
}

int overlayfs_fill_stat(struct fs_file *file, struct stat *st)
{
    struct overlay_file_handle *fh;
    int rc;
    if (!file || !st || !file->driver_private)
        return -1;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh->layer == OV_LAYER_MERGED_DIR) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        st->st_size = (off_t)fh->dir_blob_len;
        st->st_dev = 1;
        return 0;
    }
    if (!fh->inner)
        return -1;
    if (fh->layer == OV_LAYER_UPPER)
        rc = ramfs_fill_stat(fh->inner, st);
    else
        rc = squashfs_fill_stat(fh->inner, st);
    /*
     * Linux overlayfs exposes one filesystem device ID regardless of which
     * backing layer supplied an inode. Leaking squashfs st_dev here prevents
     * findmnt/df from recognizing lower-layer paths as part of the root mount.
     */
    if (rc == 0)
        st->st_dev = 1;
    return rc;
}

int overlayfs_ftruncate(struct fs_file *file, off_t length)
{
    struct overlay_file_handle *fh;
    struct fs_file *neu = NULL;
    if (!file || !file->driver_private)
        return -9;
    fh = (struct overlay_file_handle *)file->driver_private;
    if (fh->layer == OV_LAYER_MERGED_DIR)
        return -95;
    if (fh->layer == OV_LAYER_LOWER) {
        /* Truncate-to-zero: empty upper only (see ov_copy_up_empty). */
        if (length == 0) {
            if (ov_copy_up_empty(file->path) != 0)
                return -30;
        } else if (ov_copy_up(file->path) != 0) {
            return -30;
        }
        if (ov_upper_open(file->path, &neu) != 0)
            return -30;
        ov_release_inner(fh->inner);
        fh->inner = neu;
        fh->layer = OV_LAYER_UPPER;
        file->size = neu->size;
    } else if (fh->layer != OV_LAYER_UPPER) {
        return -30;
    }
    fh = (struct overlay_file_handle *)file->driver_private;
    if (!fh || !fh->inner)
        return -30;
    return ramfs_ftruncate(fh->inner, length);
}

int overlayfs_mount_root(void)
{
    if (!squashfs_is_ready())
        return -1;
    if (!ramfs_get_driver())
        return -1;
    /* Replace ramfs mount at "/" with overlay. */
    (void)fs_unmount("/");
    overlay_active = 1;
    if (fs_mount("/", &overlay_driver) != 0) {
        overlay_active = 0;
        (void)fs_mount("/", ramfs_get_driver());
        return -1;
    }
    klogprintf("overlayfs: root mounted (upper=ramfs, lower=squashfs)\n");
    return 0;
}

struct fs_driver *overlayfs_get_driver(void)
{
    return &overlay_driver;
}

int overlayfs_register(void)
{
    overlay_ops.name = "overlay";
    overlay_ops.create = overlay_create;
    overlay_ops.mkdir = overlay_mkdir;
    overlay_ops.open = overlay_open;
    overlay_ops.read = overlay_read;
    overlay_ops.write = overlay_write;
    overlay_ops.release = overlay_release;
    overlay_ops.chmod = overlay_chmod;
    overlay_ops.link = overlay_link;
    overlay_ops.rename = overlay_rename;
    overlay_ops.unlink = overlay_unlink;
    overlay_driver.ops = &overlay_ops;
    overlay_driver.driver_data = (void *)&overlay_driver;
    return fs_register_driver(&overlay_driver);
}

int overlayfs_unregister(void)
{
    overlay_active = 0;
    return fs_unregister_driver(&overlay_driver);
}
