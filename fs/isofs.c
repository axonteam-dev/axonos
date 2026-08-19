/*
 * ISO 9660 + Joliet — Linux fs/isofs semantics (read-only).
 *
 * Block layer is 512-byte LBAs; ISO logical blocks are 2048 bytes
 * (4 disk sectors). Joliet (UCS-2) is preferred when a supplementary
 * volume descriptor is present so names like axonos.elf work.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <heap.h>
#include <fs.h>
#include <stat.h>
#include <disk.h>
#include <ext2.h>
#include <isofs.h>
#include <klog.h>

#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#define ISO_SECTOR 2048u
#define ISO_SECSZ_512 4u

struct isofs_mount {
    int device_id;
    uint32_t start_lba; /* 512-byte LBA of volume start */
    uint32_t sectors;
    uint32_t root_lba;  /* ISO 2048-byte LBA */
    uint32_t root_size;
    int joliet;
};

struct isofs_fh {
    uint32_t lba;
    uint32_t size;
    int is_dir;
};

static struct fs_driver isofs_driver;
static struct fs_driver_ops isofs_ops;
static struct isofs_mount *g_iso;

static uint32_t iso_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int iso_read_logical_n(struct isofs_mount *m, uint32_t iso_lba, void *buf, uint32_t n) {
    uint32_t lba512;
    if (!m || !buf || n == 0)
        return -1;
    lba512 = m->start_lba + iso_lba * ISO_SECSZ_512;
    return disk_read_sectors(m->device_id, lba512, buf, n * ISO_SECSZ_512);
}

static int iso_read_logical(struct isofs_mount *m, uint32_t iso_lba, void *buf) {
    return iso_read_logical_n(m, iso_lba, buf, 1);
}

static void iso_strip_version(char *s) {
    char *semi;
    if (!s)
        return;
    semi = strchr(s, ';');
    if (semi)
        *semi = 0;
    /* Linux: trailing dots on ISO names */
    {
        size_t n = strlen(s);
        while (n > 0 && s[n - 1] == '.')
            s[--n] = 0;
    }
}

static void iso_tolower_ascii(char *s) {
    for (; s && *s; s++) {
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
    }
}

static int iso_ucs2be_to_utf8(const uint8_t *in, int nbytes, char *out, int cap) {
    int i, o = 0;
    if (!in || !out || cap < 2)
        return -1;
    for (i = 0; i + 1 < nbytes && o + 1 < cap; i += 2) {
        unsigned cp = ((unsigned)in[i] << 8) | in[i + 1];
        if (cp == 0)
            break;
        if (cp < 0x80u)
            out[o++] = (char)cp;
        else if (cp < 0x800u) {
            if (o + 2 >= cap)
                break;
            out[o++] = (char)(0xC0u | (cp >> 6));
            out[o++] = (char)(0x80u | (cp & 0x3Fu));
        } else {
            if (o + 3 >= cap)
                break;
            out[o++] = (char)(0xE0u | (cp >> 12));
            out[o++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
            out[o++] = (char)(0x80u | (cp & 0x3Fu));
        }
    }
    out[o] = 0;
    iso_strip_version(out);
    return 0;
}

static int iso_decode_name(const uint8_t *rec, int joliet, char *out, int cap) {
    uint8_t nlen = rec[32];
    const uint8_t *nm = rec + 33;
    if (nlen == 0 || cap < 2)
        return -1;
    if (nlen == 1 && (nm[0] == 0 || nm[0] == 1)) {
        out[0] = (nm[0] == 0) ? '.' : '.';
        if (nm[0] == 1) {
            out[0] = '.';
            out[1] = '.';
            out[2] = 0;
        } else {
            out[1] = 0;
        }
        return 0;
    }
    if (joliet)
        return iso_ucs2be_to_utf8(nm, nlen, out, cap);
    {
        int n = nlen < cap - 1 ? nlen : cap - 1;
        memcpy(out, nm, (size_t)n);
        out[n] = 0;
        iso_strip_version(out);
        iso_tolower_ascii(out);
        return 0;
    }
}

static int iso_name_eq(const char *a, const char *b) {
    char aa[256], bb[256];
    size_t i;
    if (!a || !b)
        return 0;
    strncpy(aa, a, sizeof(aa) - 1);
    aa[sizeof(aa) - 1] = 0;
    strncpy(bb, b, sizeof(bb) - 1);
    bb[sizeof(bb) - 1] = 0;
    iso_tolower_ascii(aa);
    iso_tolower_ascii(bb);
    for (i = 0; aa[i] || bb[i]; i++) {
        if (aa[i] != bb[i])
            return 0;
    }
    return 1;
}

static int iso_lookup(struct isofs_mount *m, uint32_t dir_lba, uint32_t dir_size,
                      const char *name, uint32_t *out_lba, uint32_t *out_size, int *out_dir) {
    uint32_t off = 0;
    uint8_t sec[ISO_SECTOR];
    uint32_t cur_lba = (uint32_t)-1;

    if (!name || name[0] == 0)
        return -1;
    while (off < dir_size) {
        uint32_t sec_off = off % ISO_SECTOR;
        uint32_t need_lba = dir_lba + off / ISO_SECTOR;
        const uint8_t *rec;
        uint8_t rec_len;
        char nm[256];
        int flags;

        if (need_lba != cur_lba) {
            if (iso_read_logical(m, need_lba, sec) != 0)
                return -1;
            cur_lba = need_lba;
        }
        rec = sec + sec_off;
        rec_len = rec[0];
        if (rec_len == 0) {
            /* padding to next sector */
            uint32_t skip = ISO_SECTOR - sec_off;
            if (skip == 0)
                skip = 1;
            off += skip;
            continue;
        }
        if (sec_off + rec_len > ISO_SECTOR)
            return -1;
        if (iso_decode_name(rec, m->joliet, nm, sizeof(nm)) == 0 &&
            strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0 &&
            iso_name_eq(nm, name)) {
            flags = rec[25];
            *out_lba = iso_le32(rec + 2);
            *out_size = iso_le32(rec + 10);
            *out_dir = (flags & 0x02) ? 1 : 0;
            return 0;
        }
        off += rec_len;
    }
    return -1;
}

static int iso_walk(struct isofs_mount *m, const char *rel,
                    uint32_t *lba, uint32_t *size, int *is_dir) {
    char tmp[512];
    uint32_t clba = m->root_lba;
    uint32_t csz = m->root_size;
    int cdir = 1;

    if (!rel || rel[0] == 0 || strcmp(rel, "/") == 0) {
        *lba = clba;
        *size = csz;
        *is_dir = 1;
        return 0;
    }
    strncpy(tmp, rel, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    if (tmp[0] == '/')
        memmove(tmp, tmp + 1, strlen(tmp));
    {
        char *p = tmp;
        while (*p) {
            char *slash;
            uint32_t nlba = 0, nsz = 0;
            int ndir = 0;
            while (*p == '/')
                p++;
            if (!*p)
                break;
            slash = strchr(p, '/');
            if (slash)
                *slash = 0;
            if (!cdir)
                return -1;
            if (iso_lookup(m, clba, csz, p, &nlba, &nsz, &ndir) != 0)
                return -1;
            clba = nlba;
            csz = nsz;
            cdir = ndir;
            if (!slash)
                break;
            p = slash + 1;
        }
    }
    *lba = clba;
    *size = csz;
    *is_dir = cdir;
    return 0;
}

static int iso_relpath(const char *path, char *out, size_t cap) {
    char mount_prefix[128];
    const char *name = path;
    size_t mp_len;

    if (fs_get_matching_mount_prefix(path, mount_prefix, sizeof(mount_prefix)) != 0)
        mount_prefix[0] = 0;
    mp_len = strlen(mount_prefix);
    if (mp_len && strncmp(path, mount_prefix, mp_len) == 0)
        name = path + mp_len;
    if (name[0] == 0)
        name = "/";
    if (strlen(name) >= cap)
        return -1;
    strcpy(out, name);
    return 0;
}

static int isofs_open(const char *path, struct fs_file **out_file) {
    char rel[512];
    uint32_t lba = 0, size = 0;
    int is_dir = 0;
    struct fs_file *f;
    struct isofs_fh *fh;

    if (!g_iso || !path || path[0] != '/')
        return -1;
    if (iso_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    if (iso_walk(g_iso, rel, &lba, &size, &is_dir) != 0)
        return -1;
    f = (struct fs_file *)kmalloc(sizeof(*f));
    fh = (struct isofs_fh *)kmalloc(sizeof(*fh));
    if (!f || !fh) {
        kfree(f);
        kfree(fh);
        return -1;
    }
    memset(f, 0, sizeof(*f));
    memset(fh, 0, sizeof(*fh));
    {
        size_t plen = strlen(path) + 1;
        char *pp = (char *)kmalloc(plen);
        if (!pp) {
            kfree(f);
            kfree(fh);
            return -1;
        }
        memcpy(pp, path, plen);
        f->path = pp;
    }
    f->size = size;
    f->type = is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    f->fs_private = isofs_driver.driver_data;
    fh->lba = lba;
    fh->size = size;
    fh->is_dir = is_dir;
    f->driver_private = fh;
    *out_file = f;
    return 0;
}

static ssize_t isofs_read_dir(struct isofs_mount *m, struct isofs_fh *fh,
                              void *buf, size_t size, size_t offset) {
    uint8_t sec[ISO_SECTOR];
    uint8_t *out = (uint8_t *)buf;
    size_t stream = 0, written = 0;
    uint32_t off = 0;
    uint32_t cur_lba = (uint32_t)-1;

    while (off < fh->size && written < size) {
        uint32_t sec_off = off % ISO_SECTOR;
        uint32_t need_lba = fh->lba + off / ISO_SECTOR;
        const uint8_t *rec;
        uint8_t rec_len;
        char nm[256];
        uint8_t nlen;
        uint16_t reclen;
        struct ext2_dir_entry de;

        if (need_lba != cur_lba) {
            if (iso_read_logical(m, need_lba, sec) != 0)
                break;
            cur_lba = need_lba;
        }
        rec = sec + sec_off;
        rec_len = rec[0];
        if (rec_len == 0) {
            uint32_t skip = ISO_SECTOR - sec_off;
            if (skip == 0)
                skip = 1;
            off += skip;
            continue;
        }
        if (sec_off + rec_len > ISO_SECTOR)
            break;
        if (iso_decode_name(rec, m->joliet, nm, sizeof(nm)) != 0) {
            off += rec_len;
            continue;
        }
        nlen = (uint8_t)strlen(nm);
        reclen = (uint16_t)((sizeof(de) + nlen + 3u) & ~3u);
        if (stream + reclen <= offset) {
            stream += reclen;
            off += rec_len;
            continue;
        }
        if (written + reclen > size)
            break;
        memset(&de, 0, sizeof(de));
        de.inode = iso_le32(rec + 2);
        if (de.inode == 0)
            de.inode = 1;
        de.rec_len = reclen;
        de.name_len = nlen;
        de.file_type = (rec[25] & 0x02) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
        memcpy(out + written, &de, sizeof(de));
        memcpy(out + written + sizeof(de), nm, nlen);
        written += reclen;
        stream += reclen;
        off += rec_len;
    }
    return (ssize_t)written;
}

static ssize_t isofs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    struct isofs_fh *fh;
    uint8_t sec[ISO_SECTOR];
    size_t done = 0;

    if (!file || !file->driver_private || !g_iso || !buf)
        return -1;
    fh = (struct isofs_fh *)file->driver_private;
    if (fh->is_dir)
        return isofs_read_dir(g_iso, fh, buf, size, offset);
    if (offset >= fh->size)
        return 0;
    if (offset + size > fh->size)
        size = fh->size - offset;
    while (done < size) {
        uint32_t iso_off = (uint32_t)(offset + done);
        uint32_t lba = fh->lba + iso_off / ISO_SECTOR;
        uint32_t insec = iso_off % ISO_SECTOR;
        size_t chunk;
        if (insec == 0 && (size - done) >= ISO_SECTOR) {
            uint32_t n = (uint32_t)((size - done) / ISO_SECTOR);
            uint8_t *big;
            if (n > 16)
                n = 16;
            big = (uint8_t *)kmalloc((size_t)n * ISO_SECTOR);
            if (big && iso_read_logical_n(g_iso, lba, big, n) == 0) {
                memcpy((uint8_t *)buf + done, big, (size_t)n * ISO_SECTOR);
                done += (size_t)n * ISO_SECTOR;
                kfree(big);
                continue;
            }
            if (big)
                kfree(big);
        }
        chunk = ISO_SECTOR - insec;
        if (chunk > size - done)
            chunk = size - done;
        if (iso_read_logical(g_iso, lba, sec) != 0)
            return done ? (ssize_t)done : -1;
        memcpy((uint8_t *)buf + done, sec + insec, chunk);
        done += chunk;
    }
    return (ssize_t)done;
}

static void isofs_release(struct fs_file *file) {
    if (!file)
        return;
    if (file->driver_private)
        kfree(file->driver_private);
    if (file->path)
        kfree((void *)file->path);
    kfree(file);
}

int isofs_fill_stat(struct fs_file *file, struct stat *st) {
    struct isofs_fh *fh;
    if (!file || !st || !file->driver_private)
        return -1;
    fh = (struct isofs_fh *)file->driver_private;
    memset(st, 0, sizeof(*st));
    st->st_mode = fh->is_dir ? (S_IFDIR | 0555) : (S_IFREG | 0444);
    st->st_nlink = fh->is_dir ? 2 : 1;
    st->st_size = (off_t)fh->size;
    return 0;
}

static int iso_parse_pvd(const uint8_t *vd, int joliet, uint32_t *root_lba, uint32_t *root_size) {
    const uint8_t *root;
    if (memcmp(vd + 1, "CD001", 5) != 0)
        return -1;
    root = vd + 156;
    if (root[0] < 34)
        return -1;
    *root_lba = iso_le32(root + 2);
    *root_size = iso_le32(root + 10);
    (void)joliet;
    return 0;
}

int isofs_probe_and_mount(int device_id, uint32_t start_lba, uint32_t sectors) {
    uint8_t vd[ISO_SECTOR];
    struct isofs_mount *m;
    uint32_t root_lba = 0, root_size = 0;
    int joliet = 0;
    uint32_t pri_lba = 0, pri_size = 0;
    int have_pri = 0;

    if (device_id < 0)
        return -1;
    m = (struct isofs_mount *)kmalloc(sizeof(*m));
    if (!m)
        return -1;
    memset(m, 0, sizeof(*m));
    m->device_id = device_id;
    m->start_lba = start_lba;
    m->sectors = sectors;

    /* Volume descriptors start at ISO LBA 16. */
    for (uint32_t i = 16; i < 32; i++) {
        if (iso_read_logical(m, i, vd) != 0)
            break;
        if (vd[0] == 255)
            break;
        if (memcmp(vd + 1, "CD001", 5) != 0)
            continue;
        if (vd[0] == 1) {
            if (iso_parse_pvd(vd, 0, &pri_lba, &pri_size) == 0)
                have_pri = 1;
        } else if (vd[0] == 2) {
            /* Joliet: escape 0x25 0x2F 0x40/43/45 at offset 88 */
            if (vd[88] == 0x25 && vd[89] == 0x2F &&
                (vd[90] == 0x40 || vd[90] == 0x43 || vd[90] == 0x45)) {
                if (iso_parse_pvd(vd, 1, &root_lba, &root_size) == 0)
                    joliet = 1;
            }
        }
    }
    if (!joliet) {
        if (!have_pri) {
            kfree(m);
            return -1;
        }
        root_lba = pri_lba;
        root_size = pri_size;
    }
    m->root_lba = root_lba;
    m->root_size = root_size;
    m->joliet = joliet;
    if (g_iso)
        kfree(g_iso);
    g_iso = m;
    isofs_driver.driver_data = m;
    klogprintf("isofs: mounted dev=%d lba=%u joliet=%d root=%u size=%u\n",
               device_id, start_lba, joliet, root_lba, root_size);
    return 0;
}

void isofs_unmount_cleanup(void) {
    if (!g_iso)
        return;
    kfree(g_iso);
    g_iso = NULL;
    isofs_driver.driver_data = NULL;
}

struct fs_driver *isofs_get_driver(void) {
    return &isofs_driver;
}

int isofs_register(void) {
    isofs_ops.name = "iso9660";
    isofs_ops.create = NULL;
    isofs_ops.mkdir = NULL;
    isofs_ops.open = isofs_open;
    isofs_ops.read = isofs_read;
    isofs_ops.write = NULL;
    isofs_ops.release = isofs_release;
    isofs_driver.ops = &isofs_ops;
    isofs_driver.driver_data = NULL;
    return fs_register_driver(&isofs_driver);
}

int isofs_unregister(void) {
    isofs_unmount_cleanup();
    return fs_unregister_driver(&isofs_driver);
}
