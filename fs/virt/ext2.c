/*
 * ext2 from a block device or a memory image (Linux mount -t ext2).
 * Read/write regular files and mkdir — enough to copy a boot tree.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <heap.h>
#include <ext2.h>
#include <fs.h>
#include <stat.h>
#include <disk.h>
#include <klog.h>

#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif

struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint32_t bg_reserved[3];
};

struct ext2_mount {
    void *image;
    size_t img_size;
    int device_id;
    uint32_t start_lba;
    uint32_t part_sectors;
    struct ext2_super_block sb;
    uint32_t block_size;
    uint32_t inode_size;
    uint32_t inodes_per_group;
    uint32_t blocks_per_group;
    uint32_t groups;
    uint32_t first_ino;
    uint32_t last_alloc_block;
};

struct ext2_file_handle {
    uint32_t inode_no;
    struct ext2_inode inode;
};

static struct fs_driver ext2_driver;
static struct fs_driver_ops ext2_ops;
static struct ext2_mount *g_ext2;

static uint32_t e2_le32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint16_t e2_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

static int e2_bread(struct ext2_mount *m, uint32_t blk, void *buf) {
    uint64_t off;
    if (!m || !buf || m->block_size == 0)
        return -1;
    off = (uint64_t)blk * m->block_size;
    if (m->image) {
        if (off + m->block_size > m->img_size)
            return -1;
        memcpy(buf, (uint8_t *)m->image + off, m->block_size);
        return 0;
    }
    {
        uint32_t lba = m->start_lba + (uint32_t)(off / 512);
        uint32_t nsec = m->block_size / 512;
        return disk_read_sectors(m->device_id, lba, buf, nsec);
    }
}

static int e2_bwrite(struct ext2_mount *m, uint32_t blk, const void *buf) {
    uint64_t off;
    if (!m || !buf || m->block_size == 0)
        return -1;
    off = (uint64_t)blk * m->block_size;
    if (m->image) {
        if (off + m->block_size > m->img_size)
            return -1;
        memcpy((uint8_t *)m->image + off, buf, m->block_size);
        return 0;
    }
    {
        uint32_t lba = m->start_lba + (uint32_t)(off / 512);
        uint32_t nsec = m->block_size / 512;
        return disk_write_sectors(m->device_id, lba, buf, nsec);
    }
}

static int e2_read_sb(struct ext2_mount *m) {
    uint8_t raw[1024];
    struct ext2_super_block *sb = &m->sb;

    if (m->image) {
        if (m->img_size < 2048)
            return -1;
        memcpy(raw, (uint8_t *)m->image + 1024, 1024);
    } else {
        if (disk_read_sectors(m->device_id, m->start_lba + 2, raw, 2) != 0)
            return -1;
    }
    memcpy(sb, raw, sizeof(*sb));
    if (sb->s_magic != EXT2_SUPER_MAGIC)
        return -1;
    m->block_size = 1024u << sb->s_log_block_size;
    if (m->block_size < 1024 || m->block_size > 4096 || (m->block_size % 512) != 0)
        return -1;
    m->inodes_per_group = sb->s_inodes_per_group;
    m->blocks_per_group = sb->s_blocks_per_group;
    if (!m->inodes_per_group || !m->blocks_per_group)
        return -1;
    m->groups = (sb->s_blocks_count + m->blocks_per_group - 1) / m->blocks_per_group;
    if (m->groups == 0 || m->groups > 1024)
        return -1;
    if (sb->s_rev_level >= 1 && sb->s_inode_size >= 128)
        m->inode_size = sb->s_inode_size;
    else
        m->inode_size = 128;
    if (m->inode_size < 128 || m->inode_size > 256)
        m->inode_size = 128;
    m->first_ino = (sb->s_rev_level >= 1 && sb->s_first_ino) ? sb->s_first_ino : 11;
    return 0;
}

static int e2_read_gd(struct ext2_mount *m, uint32_t group, struct ext2_group_desc *gd) {
    uint32_t gd_block = (m->block_size == 1024) ? 2 : 1;
    uint8_t *buf;
    uint32_t off;

    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, gd_block + (group * (uint32_t)sizeof(*gd)) / m->block_size, buf) != 0) {
        kfree(buf);
        return -1;
    }
    off = (group * (uint32_t)sizeof(*gd)) % m->block_size;
    memcpy(gd, buf + off, sizeof(*gd));
    kfree(buf);
    return 0;
}

static int e2_write_gd(struct ext2_mount *m, uint32_t group, const struct ext2_group_desc *gd) {
    uint32_t gd_block = (m->block_size == 1024) ? 2 : 1;
    uint8_t *buf;
    uint32_t off;

    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, gd_block + (group * (uint32_t)sizeof(*gd)) / m->block_size, buf) != 0) {
        kfree(buf);
        return -1;
    }
    off = (group * (uint32_t)sizeof(*gd)) % m->block_size;
    memcpy(buf + off, gd, sizeof(*gd));
    if (e2_bwrite(m, gd_block + (group * (uint32_t)sizeof(*gd)) / m->block_size, buf) != 0) {
        kfree(buf);
        return -1;
    }
    kfree(buf);
    return 0;
}

static int e2_read_inode(struct ext2_mount *m, uint32_t ino, struct ext2_inode *out) {
    uint32_t group, index, block, off;
    struct ext2_group_desc gd;
    uint8_t *buf;

    if (!ino)
        return -1;
    group = (ino - 1) / m->inodes_per_group;
    index = (ino - 1) % m->inodes_per_group;
    if (e2_read_gd(m, group, &gd) != 0)
        return -1;
    block = gd.bg_inode_table + (index * m->inode_size) / m->block_size;
    off = (index * m->inode_size) % m->block_size;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, block, buf) != 0) {
        kfree(buf);
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, buf + off, sizeof(*out) < m->inode_size ? sizeof(*out) : m->inode_size);
    kfree(buf);
    return 0;
}

static int e2_write_inode(struct ext2_mount *m, uint32_t ino, const struct ext2_inode *in) {
    uint32_t group, index, block, off;
    struct ext2_group_desc gd;
    uint8_t *buf;

    group = (ino - 1) / m->inodes_per_group;
    index = (ino - 1) % m->inodes_per_group;
    if (e2_read_gd(m, group, &gd) != 0)
        return -1;
    block = gd.bg_inode_table + (index * m->inode_size) / m->block_size;
    off = (index * m->inode_size) % m->block_size;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, block, buf) != 0) {
        kfree(buf);
        return -1;
    }
    memcpy(buf + off, in, sizeof(*in) < m->inode_size ? sizeof(*in) : m->inode_size);
    if (e2_bwrite(m, block, buf) != 0) {
        kfree(buf);
        return -1;
    }
    kfree(buf);
    return 0;
}

static uint32_t e2_alloc_block(struct ext2_mount *m);

static int e2_zero_block(struct ext2_mount *m, uint32_t blk)
{
    uint8_t *z;
    int r;
    if (!m || !blk)
        return -1;
    z = (uint8_t *)kmalloc(m->block_size);
    if (!z)
        return -1;
    memset(z, 0, m->block_size);
    r = e2_bwrite(m, blk, z);
    kfree(z);
    return r;
}

static int e2_ptr_get(struct ext2_mount *m, uint32_t table, uint32_t idx, uint32_t *out)
{
    uint8_t *buf;
    uint32_t ptrs;
    if (!m || !table || !out)
        return -1;
    ptrs = m->block_size / 4;
    if (idx >= ptrs)
        return -1;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, table, buf) != 0) {
        kfree(buf);
        return -1;
    }
    *out = ((uint32_t *)buf)[idx];
    kfree(buf);
    return 0;
}

static int e2_ptr_set(struct ext2_mount *m, uint32_t table, uint32_t idx, uint32_t val)
{
    uint8_t *buf;
    uint32_t ptrs;
    int r;
    if (!m || !table)
        return -1;
    ptrs = m->block_size / 4;
    if (idx >= ptrs)
        return -1;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, table, buf) != 0) {
        kfree(buf);
        return -1;
    }
    ((uint32_t *)buf)[idx] = val;
    r = e2_bwrite(m, table, buf);
    kfree(buf);
    return r;
}

static uint32_t e2_get_block(struct ext2_mount *m, struct ext2_inode *ino, uint32_t file_blk) {
    uint32_t ptrs = m->block_size / 4;
    uint32_t b = 0, mid = 0;

    if (file_blk < 12)
        return ino->i_block[file_blk];
    file_blk -= 12;
    if (file_blk < ptrs) {
        if (!ino->i_block[12])
            return 0;
        if (e2_ptr_get(m, ino->i_block[12], file_blk, &b) != 0)
            return 0;
        return b;
    }
    file_blk -= ptrs;
    if (file_blk < ptrs * ptrs) {
        uint32_t hi = file_blk / ptrs;
        uint32_t lo = file_blk % ptrs;
        if (!ino->i_block[13])
            return 0;
        if (e2_ptr_get(m, ino->i_block[13], hi, &mid) != 0 || !mid)
            return 0;
        if (e2_ptr_get(m, mid, lo, &b) != 0)
            return 0;
        return b;
    }
    return 0;
}

static int e2_set_block(struct ext2_mount *m, struct ext2_inode *ino, uint32_t file_blk, uint32_t phys) {
    uint32_t ptrs = m->block_size / 4;
    uint32_t mid = 0;

    if (file_blk < 12) {
        ino->i_block[file_blk] = phys;
        return 0;
    }
    file_blk -= 12;
    if (file_blk < ptrs) {
        if (!ino->i_block[12]) {
            uint32_t ind = e2_alloc_block(m);
            if (!ind)
                return -1;
            if (e2_zero_block(m, ind) != 0)
                return -1;
            ino->i_block[12] = ind;
            ino->i_blocks += m->block_size / 512;
        }
        return e2_ptr_set(m, ino->i_block[12], file_blk, phys);
    }
    file_blk -= ptrs;
    if (file_blk < ptrs * ptrs) {
        uint32_t hi = file_blk / ptrs;
        uint32_t lo = file_blk % ptrs;
        if (!ino->i_block[13]) {
            uint32_t dind = e2_alloc_block(m);
            if (!dind)
                return -1;
            if (e2_zero_block(m, dind) != 0)
                return -1;
            ino->i_block[13] = dind;
            ino->i_blocks += m->block_size / 512;
        }
        if (e2_ptr_get(m, ino->i_block[13], hi, &mid) != 0)
            return -1;
        if (!mid) {
            mid = e2_alloc_block(m);
            if (!mid)
                return -1;
            if (e2_zero_block(m, mid) != 0)
                return -1;
            if (e2_ptr_set(m, ino->i_block[13], hi, mid) != 0)
                return -1;
            ino->i_blocks += m->block_size / 512;
        }
        return e2_ptr_set(m, mid, lo, phys);
    }
    return -1;
}

static uint32_t e2_alloc_block(struct ext2_mount *m) {
    uint8_t *bm;
    uint32_t g, g0 = 0, i0 = 0;
    uint32_t start;

    bm = (uint8_t *)kmalloc(m->block_size);
    if (!bm)
        return 0;
    start = m->last_alloc_block ? m->last_alloc_block + 1 : m->sb.s_first_data_block;
    if (start < m->sb.s_first_data_block)
        start = m->sb.s_first_data_block;
    if (start < m->sb.s_blocks_count) {
        uint32_t rel = start - m->sb.s_first_data_block;
        g0 = rel / m->blocks_per_group;
        i0 = rel % m->blocks_per_group;
        if (g0 >= m->groups) {
            g0 = 0;
            i0 = 0;
        }
    }
    for (g = g0; g < m->groups + g0; g++) {
        struct ext2_group_desc gd;
        uint32_t gi = g % m->groups;
        uint32_t i, first;
        uint32_t from = (gi == g0 && g == g0) ? i0 : 0;
        if (e2_read_gd(m, gi, &gd) != 0)
            continue;
        if (e2_bread(m, gd.bg_block_bitmap, bm) != 0)
            continue;
        first = gi * m->blocks_per_group + m->sb.s_first_data_block;
        for (i = from; i < m->blocks_per_group; i++) {
            uint32_t blk = first + i;
            if (blk >= m->sb.s_blocks_count)
                break;
            if ((bm[i / 8] & (1u << (i % 8))) == 0) {
                bm[i / 8] |= (uint8_t)(1u << (i % 8));
                if (e2_bwrite(m, gd.bg_block_bitmap, bm) != 0)
                    break;
                if (gd.bg_free_blocks_count)
                    gd.bg_free_blocks_count--;
                (void)e2_write_gd(m, gi, &gd);
                if (m->sb.s_free_blocks_count)
                    m->sb.s_free_blocks_count--;
                m->last_alloc_block = blk;
                kfree(bm);
                return blk;
            }
        }
    }
    kfree(bm);
    return 0;
}

static uint32_t e2_alloc_inode(struct ext2_mount *m) {
    uint8_t *bm;
    uint32_t g;

    bm = (uint8_t *)kmalloc(m->block_size);
    if (!bm)
        return 0;
    for (g = 0; g < m->groups; g++) {
        struct ext2_group_desc gd;
        uint32_t i;
        if (e2_read_gd(m, g, &gd) != 0)
            continue;
        if (e2_bread(m, gd.bg_inode_bitmap, bm) != 0)
            continue;
        for (i = 0; i < m->inodes_per_group; i++) {
            uint32_t ino = g * m->inodes_per_group + i + 1;
            if (ino < m->first_ino)
                continue;
            if (ino > m->sb.s_inodes_count)
                break;
            if ((bm[i / 8] & (1u << (i % 8))) == 0) {
                bm[i / 8] |= (uint8_t)(1u << (i % 8));
                if (e2_bwrite(m, gd.bg_inode_bitmap, bm) != 0)
                    break;
                if (gd.bg_free_inodes_count)
                    gd.bg_free_inodes_count--;
                (void)e2_write_gd(m, g, &gd);
                if (m->sb.s_free_inodes_count)
                    m->sb.s_free_inodes_count--;
                kfree(bm);
                return ino;
            }
        }
    }
    kfree(bm);
    return 0;
}

static int e2_dir_lookup(struct ext2_mount *m, struct ext2_inode *dir,
                         const char *name, uint32_t *out_ino, uint8_t *out_ft) {
    uint32_t fb, nblk;
    uint8_t *buf;
    size_t nlen = strlen(name);

    if ((dir->i_mode & 0xF000) != 0x4000)
        return -1;
    nblk = (dir->i_size + m->block_size - 1) / m->block_size;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    for (fb = 0; fb < nblk && fb < 12 + m->block_size / 4; fb++) {
        uint32_t phys = e2_get_block(m, dir, fb);
        uint32_t off = 0;
        if (!phys)
            continue;
        if (e2_bread(m, phys, buf) != 0)
            continue;
        while (off + 8 <= m->block_size) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry *)(buf + off);
            if (de->rec_len < 8)
                break;
            if (de->inode && de->name_len == nlen &&
                memcmp(buf + off + sizeof(*de), name, nlen) == 0) {
                *out_ino = de->inode;
                if (out_ft)
                    *out_ft = de->file_type;
                kfree(buf);
                return 0;
            }
            off += de->rec_len;
        }
    }
    kfree(buf);
    return -1;
}

static int e2_dir_add(struct ext2_mount *m, uint32_t dir_ino, struct ext2_inode *dir,
                      const char *name, uint32_t ino, uint8_t ft) {
    uint32_t nlen = (uint32_t)strlen(name);
    uint16_t need = (uint16_t)((sizeof(struct ext2_dir_entry) + nlen + 3u) & ~3u);
    uint32_t fb, nblk;
    uint8_t *buf;

    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    nblk = (dir->i_size + m->block_size - 1) / m->block_size;
    if (nblk == 0)
        nblk = 1;
    for (fb = 0; fb < nblk && fb < 12; fb++) {
        uint32_t phys = e2_get_block(m, dir, fb);
        uint32_t off = 0;
        if (!phys) {
            phys = e2_alloc_block(m);
            if (!phys) {
                kfree(buf);
                return -1;
            }
            memset(buf, 0, m->block_size);
            {
                struct ext2_dir_entry *de = (struct ext2_dir_entry *)buf;
                de->inode = ino;
                de->rec_len = (uint16_t)m->block_size;
                de->name_len = (uint8_t)nlen;
                de->file_type = ft;
                memcpy(buf + sizeof(*de), name, nlen);
            }
            if (e2_set_block(m, dir, fb, phys) != 0 || e2_bwrite(m, phys, buf) != 0) {
                kfree(buf);
                return -1;
            }
            dir->i_size = (fb + 1) * m->block_size;
            dir->i_blocks += m->block_size / 512;
            kfree(buf);
            return e2_write_inode(m, dir_ino, dir);
        }
        if (e2_bread(m, phys, buf) != 0)
            continue;
        while (off + 8 <= m->block_size) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry *)(buf + off);
            uint16_t minlen;
            if (de->rec_len < 8)
                break;
            minlen = (uint16_t)((sizeof(*de) + de->name_len + 3u) & ~3u);
            if (de->inode == 0 && de->rec_len >= need) {
                de->inode = ino;
                de->name_len = (uint8_t)nlen;
                de->file_type = ft;
                memcpy(buf + off + sizeof(*de), name, nlen);
                if (e2_bwrite(m, phys, buf) != 0) {
                    kfree(buf);
                    return -1;
                }
                kfree(buf);
                return 0;
            }
            if (de->rec_len >= minlen + need) {
                uint16_t old = de->rec_len;
                struct ext2_dir_entry *n;
                de->rec_len = minlen;
                n = (struct ext2_dir_entry *)(buf + off + minlen);
                n->inode = ino;
                n->rec_len = (uint16_t)(old - minlen);
                n->name_len = (uint8_t)nlen;
                n->file_type = ft;
                memcpy(buf + off + minlen + sizeof(*n), name, nlen);
                if (e2_bwrite(m, phys, buf) != 0) {
                    kfree(buf);
                    return -1;
                }
                kfree(buf);
                return 0;
            }
            off += de->rec_len;
        }
    }
    kfree(buf);
    return -1;
}

static int e2_walk(struct ext2_mount *m, const char *rel, uint32_t *ino, struct ext2_inode *out) {
    uint32_t cur = 2;
    char tmp[512];
    char *p;

    if (e2_read_inode(m, cur, out) != 0)
        return -1;
    if (!rel || rel[0] == 0 || strcmp(rel, "/") == 0) {
        *ino = cur;
        return 0;
    }
    strncpy(tmp, rel, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    p = tmp;
    if (*p == '/')
        p++;
    while (*p) {
        char *slash;
        uint32_t next = 0;
        uint8_t ft = 0;
        while (*p == '/')
            p++;
        if (!*p)
            break;
        slash = strchr(p, '/');
        if (slash)
            *slash = 0;
        if (e2_dir_lookup(m, out, p, &next, &ft) != 0)
            return -1;
        if (e2_read_inode(m, next, out) != 0)
            return -1;
        cur = next;
        if (!slash)
            break;
        p = slash + 1;
    }
    *ino = cur;
    return 0;
}

static int e2_relpath(const char *path, char *out, size_t cap) {
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

static int ext2_open(const char *path, struct fs_file **out_file) {
    char rel[512];
    uint32_t ino = 0;
    struct ext2_inode inode;
    struct fs_file *f;
    struct ext2_file_handle *fh;

    if (!g_ext2 || !path)
        return -1;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    if (e2_walk(g_ext2, rel, &ino, &inode) != 0)
        return -1;
    f = (struct fs_file *)kmalloc(sizeof(*f));
    fh = (struct ext2_file_handle *)kmalloc(sizeof(*fh));
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
    f->size = inode.i_size;
    f->type = ((inode.i_mode & 0xF000) == 0x4000) ? FS_TYPE_DIR : FS_TYPE_REG;
    f->fs_private = ext2_driver.driver_data;
    fh->inode_no = ino;
    fh->inode = inode;
    f->driver_private = fh;
    *out_file = f;
    return 0;
}

static ssize_t ext2_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    struct ext2_file_handle *fh;
    uint8_t *bb;
    size_t done = 0;

    if (!g_ext2 || !file || !file->driver_private || !buf)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    if (fh->inode.i_mode & 0x4000) {
        /* Directory: raw ext2 dirents (same as on disk). */
        uint32_t nblk = (fh->inode.i_size + g_ext2->block_size - 1) / g_ext2->block_size;
        size_t want = size;
        if (offset >= fh->inode.i_size)
            return 0;
        if (offset + want > fh->inode.i_size)
            want = fh->inode.i_size - offset;
        bb = (uint8_t *)kmalloc(g_ext2->block_size);
        if (!bb)
            return -1;
        while (done < want) {
            uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
            uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
            uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
            size_t chunk = g_ext2->block_size - inb;
            if (file_blk >= nblk)
                break;
            if (chunk > want - done)
                chunk = want - done;
            if (!phys)
                memset((uint8_t *)buf + done, 0, chunk);
            else {
                if (e2_bread(g_ext2, phys, bb) != 0) {
                    kfree(bb);
                    return done ? (ssize_t)done : -1;
                }
                memcpy((uint8_t *)buf + done, bb + inb, chunk);
            }
            done += chunk;
        }
        kfree(bb);
        return (ssize_t)done;
    }
    if (offset >= fh->inode.i_size)
        return 0;
    if (offset + size > fh->inode.i_size)
        size = fh->inode.i_size - offset;
    bb = (uint8_t *)kmalloc(g_ext2->block_size);
    if (!bb)
        return -1;
    while (done < size) {
        uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
        uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
        uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
        size_t chunk = g_ext2->block_size - inb;
        if (chunk > size - done)
            chunk = size - done;
        if (!phys)
            memset((uint8_t *)buf + done, 0, chunk);
        else {
            if (e2_bread(g_ext2, phys, bb) != 0) {
                kfree(bb);
                return done ? (ssize_t)done : -1;
            }
            memcpy((uint8_t *)buf + done, bb + inb, chunk);
        }
        done += chunk;
    }
    kfree(bb);
    return (ssize_t)done;
}

static ssize_t ext2_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    struct ext2_file_handle *fh;
    uint8_t *bb;
    size_t done = 0;

    if (!g_ext2 || !file || !file->driver_private || !buf)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    if (fh->inode.i_mode & 0x4000)
        return -1;
    bb = (uint8_t *)kmalloc(g_ext2->block_size);
    if (!bb)
        return -1;
    while (done < size) {
        uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
        uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
        uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
        size_t chunk = g_ext2->block_size - inb;
        if (chunk > size - done)
            chunk = size - done;
        if (!phys) {
            phys = e2_alloc_block(g_ext2);
            if (!phys) {
                kfree(bb);
                return done ? (ssize_t)done : -1;
            }
            if (e2_set_block(g_ext2, &fh->inode, file_blk, phys) != 0) {
                kfree(bb);
                return done ? (ssize_t)done : -1;
            }
            fh->inode.i_blocks += g_ext2->block_size / 512;
            if (inb != 0 || chunk != g_ext2->block_size)
                memset(bb, 0, g_ext2->block_size);
        } else if (!(inb == 0 && chunk == g_ext2->block_size) &&
                   e2_bread(g_ext2, phys, bb) != 0) {
            kfree(bb);
            return done ? (ssize_t)done : -1;
        }
        memcpy(bb + inb, (const uint8_t *)buf + done, chunk);
        if (e2_bwrite(g_ext2, phys, bb) != 0) {
            kfree(bb);
            return done ? (ssize_t)done : -1;
        }
        done += chunk;
    }
    kfree(bb);
    if (offset + done > fh->inode.i_size)
        fh->inode.i_size = (uint32_t)(offset + done);
    file->size = fh->inode.i_size;
    (void)e2_write_inode(g_ext2, fh->inode_no, &fh->inode);
    return (ssize_t)done;
}

static void ext2_release(struct fs_file *file) {
    if (!file)
        return;
    if (file->driver_private)
        kfree(file->driver_private);
    if (file->path)
        kfree((void *)file->path);
    kfree(file);
}

static int ext2_create(const char *path, struct fs_file **out_file) {
    char rel[512], parent[512], base[256];
    char *slash;
    uint32_t pino = 0, nino;
    struct ext2_inode pino_i, ni;

    if (!g_ext2 || !path)
        return -1;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    strncpy(parent, rel, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    strncpy(base, slash + 1, sizeof(base) - 1);
    base[sizeof(base) - 1] = 0;
    if (slash == parent)
        parent[1] = 0;
    else
        *slash = 0;
    if (!base[0])
        return -1;
    if (e2_walk(g_ext2, parent, &pino, &pino_i) != 0)
        return -1;
    nino = e2_alloc_inode(g_ext2);
    if (!nino)
        return -1;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (uint16_t)(S_IFREG | 0644);
    ni.i_links_count = 1;
    ni.i_uid = 0;
    ni.i_gid = 0;
    if (e2_write_inode(g_ext2, nino, &ni) != 0)
        return -1;
    if (e2_dir_add(g_ext2, pino, &pino_i, base, nino, EXT2_FT_REG_FILE) != 0)
        return -1;
    {
        struct fs_file *tmp = NULL;
        int rc = ext2_open(path, out_file ? out_file : &tmp);
        if (!out_file && tmp)
            ext2_release(tmp);
        return rc;
    }
}

static int ext2_mkdir(const char *path) {
    char rel[512], parent[512], base[256];
    char *slash;
    uint32_t pino = 0, nino, dblk;
    struct ext2_inode pino_i, ni;
    uint8_t *buf;
    struct ext2_dir_entry *de;

    if (!g_ext2 || !path)
        return -1;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    strncpy(parent, rel, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    strncpy(base, slash + 1, sizeof(base) - 1);
    base[sizeof(base) - 1] = 0;
    if (slash == parent)
        parent[1] = 0;
    else
        *slash = 0;
    if (!base[0])
        return -1;
    if (e2_walk(g_ext2, parent, &pino, &pino_i) != 0)
        return -1;
    nino = e2_alloc_inode(g_ext2);
    dblk = e2_alloc_block(g_ext2);
    if (!nino || !dblk)
        return -1;
    buf = (uint8_t *)kmalloc(g_ext2->block_size);
    if (!buf)
        return -1;
    memset(buf, 0, g_ext2->block_size);
    de = (struct ext2_dir_entry *)buf;
    de->inode = nino;
    de->rec_len = 12;
    de->name_len = 1;
    de->file_type = EXT2_FT_DIR;
    buf[sizeof(*de)] = '.';
    de = (struct ext2_dir_entry *)(buf + 12);
    de->inode = pino;
    de->rec_len = (uint16_t)(g_ext2->block_size - 12);
    de->name_len = 2;
    de->file_type = EXT2_FT_DIR;
    buf[12 + sizeof(*de)] = '.';
    buf[12 + sizeof(*de) + 1] = '.';
    if (e2_bwrite(g_ext2, dblk, buf) != 0) {
        kfree(buf);
        return -1;
    }
    kfree(buf);
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (uint16_t)(S_IFDIR | 0755);
    ni.i_links_count = 2;
    ni.i_size = g_ext2->block_size;
    ni.i_blocks = g_ext2->block_size / 512;
    ni.i_block[0] = dblk;
    if (e2_write_inode(g_ext2, nino, &ni) != 0)
        return -1;
    pino_i.i_links_count++;
    if (e2_dir_add(g_ext2, pino, &pino_i, base, nino, EXT2_FT_DIR) != 0)
        return -1;
    return 0;
}

int ext2_fill_stat(struct fs_file *file, struct stat *st) {
    struct ext2_file_handle *fh;
    if (!file || !st || !file->driver_private)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    memset(st, 0, sizeof(*st));
    st->st_mode = fh->inode.i_mode;
    st->st_uid = fh->inode.i_uid;
    st->st_gid = fh->inode.i_gid;
    st->st_nlink = fh->inode.i_links_count ? fh->inode.i_links_count : 1;
    st->st_size = fh->inode.i_size;
    st->st_ino = fh->inode_no;
    return 0;
}

static int ext2_bind(struct ext2_mount *m) {
    if (e2_read_sb(m) != 0)
        return -1;
    if (g_ext2) {
        kfree(g_ext2);
        g_ext2 = NULL;
    }
    g_ext2 = m;
    ext2_driver.driver_data = m;
    klogprintf("ext2: mounted blocks=%u bsize=%u inodesz=%u groups=%u\n",
               m->sb.s_blocks_count, m->block_size, m->inode_size, m->groups);
    return 0;
}

int ext2_mount_from_memory(void *image, size_t size) {
    struct ext2_mount *m;
    if (!image || size < 2048)
        return -1;
    m = (struct ext2_mount *)kmalloc(sizeof(*m));
    if (!m)
        return -1;
    memset(m, 0, sizeof(*m));
    m->image = image;
    m->img_size = size;
    m->device_id = -1;
    if (ext2_bind(m) != 0) {
        kfree(m);
        return -1;
    }
    return 0;
}

int ext2_probe_and_mount_geom(int device_id, uint32_t start_lba, uint32_t sectors) {
    struct ext2_mount *m;
    if (device_id < 0)
        return -1;
    m = (struct ext2_mount *)kmalloc(sizeof(*m));
    if (!m)
        return -1;
    memset(m, 0, sizeof(*m));
    m->device_id = device_id;
    m->start_lba = start_lba;
    m->part_sectors = sectors;
    m->image = NULL;
    if (ext2_bind(m) != 0) {
        kfree(m);
        return -1;
    }
    return 0;
}

void ext2_unmount_cleanup(void) {
    if (!g_ext2)
        return;
    if (!g_ext2->image && g_ext2->device_id >= 0) {
        uint8_t raw[1024];
        memset(raw, 0, sizeof(raw));
        memcpy(raw, &g_ext2->sb, sizeof(g_ext2->sb) < sizeof(raw) ? sizeof(g_ext2->sb) : sizeof(raw));
        (void)disk_write_sectors(g_ext2->device_id, g_ext2->start_lba + 2, raw, 2);
    }
    kfree(g_ext2);
    g_ext2 = NULL;
    ext2_driver.driver_data = NULL;
}

struct fs_driver *ext2_get_driver(void) {
    return &ext2_driver;
}

void ext2_ls_root(void) { }

int ext2_read_file_root(const char *name, void *out_buf, size_t buf_size) {
    (void)name;
    (void)out_buf;
    (void)buf_size;
    return -1;
}

int ext2_register(void) {
    ext2_ops.name = "ext2";
    ext2_ops.create = ext2_create;
    ext2_ops.mkdir = ext2_mkdir;
    ext2_ops.open = ext2_open;
    ext2_ops.read = ext2_read;
    ext2_ops.write = ext2_write;
    ext2_ops.release = ext2_release;
    ext2_driver.ops = &ext2_ops;
    ext2_driver.driver_data = NULL;
    return fs_register_driver(&ext2_driver);
}

int ext2_unregister(void) {
    ext2_unmount_cleanup();
    return fs_unregister_driver(&ext2_driver);
}
