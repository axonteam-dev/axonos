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
#include <thread.h>

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
    int write_started;
};

struct ext2_file_handle {
    uint32_t inode_no;
    struct ext2_inode inode;
};

static struct fs_driver ext2_driver;
static struct fs_driver_ops ext2_ops;
static struct ext2_mount *g_ext2;

_Static_assert(sizeof(struct ext2_inode) == 128, "ext2 inode layout");

static uint32_t e2_inode_uid(const struct ext2_mount *m, const struct ext2_inode *inode) {
    return inode->i_uid | (m->sb.s_creator_os == 0 ? (uint32_t)inode->i_uid_high << 16 : 0);
}

static uint32_t e2_inode_gid(const struct ext2_mount *m, const struct ext2_inode *inode) {
    return inode->i_gid | (m->sb.s_creator_os == 0 ? (uint32_t)inode->i_gid_high << 16 : 0);
}

static int e2_set_inode_owner(struct ext2_mount *m, struct ext2_inode *inode,
                              uint32_t uid, uint32_t gid) {
    if (m->sb.s_creator_os != 0 && (uid > 65535 || gid > 65535))
        return -1;
    inode->i_uid = (uint16_t)uid;
    inode->i_gid = (uint16_t)gid;
    if (m->sb.s_creator_os == 0) {
        inode->i_uid_high = (uint16_t)(uid >> 16);
        inode->i_gid_high = (uint16_t)(gid >> 16);
    }
    return 0;
}

static uint32_t e2_le32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint16_t e2_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

static int e2_block_lba(struct ext2_mount *m, uint64_t off, uint32_t *lba) {
    uint64_t sector = off / 512;
    uint32_t count = m->block_size / 512;
    uint64_t absolute = (uint64_t)m->start_lba + sector;
    if (!count || (m->part_sectors &&
        (sector >= m->part_sectors || count > m->part_sectors - sector)) ||
        absolute > UINT32_MAX || count - 1 > UINT32_MAX - absolute)
        return -1;
    *lba = (uint32_t)absolute;
    return 0;
}

static int e2_bread(struct ext2_mount *m, uint32_t blk, void *buf) {
    uint64_t off;
    if (!m || !buf || m->block_size == 0 || blk >= m->sb.s_blocks_count)
        return -1;
    off = (uint64_t)blk * m->block_size;
    if (m->image) {
        if (off + m->block_size > m->img_size)
            return -1;
        memcpy(buf, (uint8_t *)m->image + off, m->block_size);
        return 0;
    }
    {
        uint32_t lba;
        uint32_t nsec = m->block_size / 512;
        if (e2_block_lba(m, off, &lba) != 0)
            return -1;
        return disk_read_sectors(m->device_id, lba, buf, nsec);
    }
}

/* Before the first metadata or data write, clear EXT2_VALID_FS on disk.
 * Without a cache flush this is not a crash-ordering guarantee. Never mark
 * the filesystem clean on unmount until a real durability barrier exists. */
static int e2_mark_write_started(struct ext2_mount *m) {
    uint8_t raw[1024];
    if (m->write_started)
        return 0;
    if (m->image) {
        if (m->img_size < 2048)
            return -1;
        memcpy(raw, (uint8_t *)m->image + 1024, sizeof(raw));
    } else {
        if ((m->part_sectors && m->part_sectors < 4) ||
            m->start_lba > UINT32_MAX - 3 ||
            disk_read_sectors(m->device_id, m->start_lba + 2, raw, 2) != 0)
            return -1;
    }
    /* s_state is a little-endian uint16 at byte 58 of the superblock. */
    raw[58] &= (uint8_t)~1u;
    if (m->image)
        memcpy((uint8_t *)m->image + 1024, raw, sizeof(raw));
    else if (disk_write_sectors(m->device_id, m->start_lba + 2, raw, 2) != 0)
        return -1;
    m->sb.s_state &= (uint16_t)~1u;
    m->write_started = 1;
    return 0;
}

static int e2_bwrite(struct ext2_mount *m, uint32_t blk, const void *buf) {
    uint64_t off;
    if (!m || !buf || m->block_size == 0 || blk >= m->sb.s_blocks_count)
        return -1;
    off = (uint64_t)blk * m->block_size;
    if (m->image) {
        if (off + m->block_size > m->img_size)
            return -1;
        if (e2_mark_write_started(m) != 0)
            return -1;
        memcpy((uint8_t *)m->image + off, buf, m->block_size);
        return 0;
    }
    {
        uint32_t lba;
        uint32_t nsec = m->block_size / 512;
        if (e2_block_lba(m, off, &lba) != 0)
            return -1;
        if (e2_mark_write_started(m) != 0)
            return -1;
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
        if ((m->part_sectors && m->part_sectors < 4) ||
            m->start_lba > UINT32_MAX - 3)
            return -1;
        if (disk_read_sectors(m->device_id, m->start_lba + 2, raw, 2) != 0)
            return -1;
    }
    memcpy(sb, raw, sizeof(*sb));
    if (sb->s_magic != EXT2_SUPER_MAGIC)
        return -1;
    /* This driver only understands ext2's directory file-type extension.
     * In particular, treating ext4 extents or a journal as ordinary ext2
     * blocks would corrupt the filesystem on the first write. */
    if (sb->s_rev_level >= 1) {
        uint32_t compat = e2_le32(raw + 92);
        uint32_t incompat = e2_le32(raw + 96);
        uint32_t ro_compat = e2_le32(raw + 100);
        if ((compat & 0x0004u) || (incompat & ~0x0002u) ||
            (ro_compat & ~0x0003u))
            return -1;
    }
    if (sb->s_log_block_size > 2)
        return -1;
    m->block_size = 1024u << sb->s_log_block_size;
    if (m->block_size < 1024 || m->block_size > 4096 || (m->block_size % 512) != 0)
        return -1;
    /* A superblock must not describe storage beyond the actual backing. */
    if ((m->image && (uint64_t)sb->s_blocks_count * m->block_size > m->img_size) ||
        (!m->image && m->part_sectors &&
         (uint64_t)sb->s_blocks_count * (m->block_size / 512) > m->part_sectors))
        return -1;
    m->inodes_per_group = sb->s_inodes_per_group;
    m->blocks_per_group = sb->s_blocks_per_group;
    if (!m->inodes_per_group || !m->blocks_per_group ||
        m->inodes_per_group > m->block_size * 8u ||
        m->blocks_per_group > m->block_size * 8u ||
        sb->s_blocks_count <= sb->s_first_data_block || !sb->s_inodes_count)
        return -1;
    m->groups = (uint32_t)(((uint64_t)sb->s_blocks_count - sb->s_first_data_block +
                            m->blocks_per_group - 1) / m->blocks_per_group);
    if (m->groups == 0 || m->groups > 1024)
        return -1;
    if ((uint64_t)sb->s_inodes_count > (uint64_t)m->groups * m->inodes_per_group)
        return -1;
    if (sb->s_rev_level >= 1)
        m->inode_size = sb->s_inode_size;
    else
        m->inode_size = 128;
    if (m->inode_size < 128 || m->inode_size > 256 ||
        (m->inode_size & (m->inode_size - 1)) != 0 ||
        m->block_size % m->inode_size != 0)
        return -1;
    m->first_ino = (sb->s_rev_level >= 1 && sb->s_first_ino) ? sb->s_first_ino : 11;
    return 0;
}

static int e2_read_gd(struct ext2_mount *m, uint32_t group, struct ext2_group_desc *gd) {
    uint32_t gd_block = (m->block_size == 1024) ? 2 : 1;
    uint8_t *buf;
    uint32_t off;

    if (group >= m->groups)
        return -1;
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

    if (group >= m->groups)
        return -1;
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

    if (!ino || ino > m->sb.s_inodes_count)
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

    if (!ino || ino > m->sb.s_inodes_count)
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

/* UINT32_MAX is an I/O/unsupported error, not a sparse hole. */
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
            return UINT32_MAX;
        return b;
    }
    file_blk -= ptrs;
    if (file_blk < ptrs * ptrs) {
        uint32_t hi = file_blk / ptrs;
        uint32_t lo = file_blk % ptrs;
        if (!ino->i_block[13])
            return 0;
        if (e2_ptr_get(m, ino->i_block[13], hi, &mid) != 0)
            return UINT32_MAX;
        if (!mid)
            return 0;
        if (e2_ptr_get(m, mid, lo, &b) != 0)
            return UINT32_MAX;
        return b;
    }
    return UINT32_MAX;
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
    /* Revisit the beginning of the starting group after wrapping: free blocks
     * before last_alloc_block must remain usable when the rest is full. */
    for (g = g0; g <= m->groups + g0; g++) {
        struct ext2_group_desc gd;
        uint32_t gi = g % m->groups;
        uint32_t i, first;
        uint32_t from = (gi == g0 && g == g0) ? i0 : 0;
        uint32_t end = (g == m->groups + g0) ? i0 : m->blocks_per_group;
        if (from >= end)
            continue;
        if (e2_read_gd(m, gi, &gd) != 0)
            continue;
        if (e2_bread(m, gd.bg_block_bitmap, bm) != 0)
            continue;
        first = gi * m->blocks_per_group + m->sb.s_first_data_block;
        for (i = from; i < end; i++) {
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

/* Free one data block after its inode pointer has been detached on disk. */
static int e2_free_data_block(struct ext2_mount *m, uint32_t block) {
    struct ext2_group_desc gd;
    uint32_t rel, group, bit;
    uint8_t *bitmap;
    if (block < m->sb.s_first_data_block || block >= m->sb.s_blocks_count)
        return -1;
    rel = block - m->sb.s_first_data_block;
    group = rel / m->blocks_per_group;
    bit = rel % m->blocks_per_group;
    if (e2_read_gd(m, group, &gd) != 0)
        return -1;
    bitmap = (uint8_t *)kmalloc(m->block_size);
    if (!bitmap)
        return -1;
    if (e2_bread(m, gd.bg_block_bitmap, bitmap) != 0 ||
        !(bitmap[bit / 8] & (1u << (bit % 8)))) {
        kfree(bitmap);
        return -1;
    }
    bitmap[bit / 8] &= (uint8_t)~(1u << (bit % 8));
    if (e2_bwrite(m, gd.bg_block_bitmap, bitmap) != 0) {
        kfree(bitmap);
        return -1;
    }
    kfree(bitmap);
    gd.bg_free_blocks_count++;
    if (e2_write_gd(m, group, &gd) != 0)
        return -1;
    m->sb.s_free_blocks_count++;
    return 0;
}

static int e2_free_inode_number(struct ext2_mount *m, uint32_t ino) {
    struct ext2_group_desc gd;
    uint32_t group, bit;
    uint8_t *bitmap;
    if (ino < m->first_ino || ino > m->sb.s_inodes_count)
        return -1;
    group = (ino - 1) / m->inodes_per_group;
    bit = (ino - 1) % m->inodes_per_group;
    if (e2_read_gd(m, group, &gd) != 0)
        return -1;
    bitmap = (uint8_t *)kmalloc(m->block_size);
    if (!bitmap)
        return -1;
    if (e2_bread(m, gd.bg_inode_bitmap, bitmap) != 0 ||
        !(bitmap[bit / 8] & (1u << (bit % 8)))) {
        kfree(bitmap);
        return -1;
    }
    bitmap[bit / 8] &= (uint8_t)~(1u << (bit % 8));
    if (e2_bwrite(m, gd.bg_inode_bitmap, bitmap) != 0) {
        kfree(bitmap);
        return -1;
    }
    kfree(bitmap);
    gd.bg_free_inodes_count++;
    if (e2_write_gd(m, group, &gd) != 0)
        return -1;
    m->sb.s_free_inodes_count++;
    return 0;
}

/* Reject corrupt entries before using their name or following rec_len. */
static int e2_valid_dirent(const struct ext2_dir_entry *de, uint32_t remaining) {
    return remaining >= sizeof(*de) && de->rec_len >= sizeof(*de) &&
           (de->rec_len & 3u) == 0 && de->rec_len <= remaining &&
           de->name_len <= de->rec_len - sizeof(*de);
}

static int e2_dir_lookup(struct ext2_mount *m, struct ext2_inode *dir,
                         const char *name, uint32_t *out_ino, uint8_t *out_ft) {
    uint32_t fb, nblk;
    uint8_t *buf;
    size_t nlen = strlen(name);

    if ((dir->i_mode & 0xF000) != 0x4000)
        return -1;
    nblk = (dir->i_size + m->block_size - 1) / m->block_size;
    if (nblk > 12 + m->block_size / 4)
        return -2;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -2;
    for (fb = 0; fb < nblk && fb < 12 + m->block_size / 4; fb++) {
        uint32_t phys = e2_get_block(m, dir, fb);
        uint32_t off = 0;
        if (phys == UINT32_MAX) {
            kfree(buf);
            return -2;
        }
        if (!phys || e2_bread(m, phys, buf) != 0) {
            kfree(buf);
            return -2;
        }
        while (off + 8 <= m->block_size) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry *)(buf + off);
            if (!e2_valid_dirent(de, m->block_size - off)) {
                kfree(buf);
                return -2;
            }
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

    /* HTree directories require index maintenance, not linear insertion. */
    if (!nlen || nlen > 255 || (dir->i_flags & 0x1000u))
        return -1;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    nblk = dir->i_size / m->block_size + (dir->i_size % m->block_size != 0);
    /* e2_get_block/e2_set_block support direct, single- and double-indirect
     * blocks. Large directories (e.g. dpkg/info) cannot stop at block 12. */
    for (fb = 0; fb <= nblk; fb++) {
        uint32_t phys = e2_get_block(m, dir, fb);
        uint32_t off = 0;
        if (phys == UINT32_MAX) {
            kfree(buf);
            return -1;
        }
        if (!phys) {
            if (fb >= 0xffffffffu / m->block_size) {
                kfree(buf);
                return -1;
            }
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
            if (dir->i_size < (fb + 1) * m->block_size)
                dir->i_size = (fb + 1) * m->block_size;
            dir->i_blocks += m->block_size / 512;
            kfree(buf);
            return e2_write_inode(m, dir_ino, dir);
        }
        if (e2_bread(m, phys, buf) != 0) {
            kfree(buf);
            return -1;
        }
        while (off + 8 <= m->block_size) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry *)(buf + off);
            uint16_t minlen;
            if (!e2_valid_dirent(de, m->block_size - off)) {
                kfree(buf);
                return -1;
            }
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
    if (name[0] != '/') {
        size_t len = strlen(name);
        if (len + 2 > cap)
            return -1;
        out[0] = '/';
        memcpy(out + 1, name, len + 1);
    } else {
        if (strlen(name) >= cap)
            return -1;
        strcpy(out, name);
    }
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
    /* For regular ext2 files i_dir_acl stores the high 32 bits of size. The
     * current data path is 32-bit; do not silently truncate large files. */
    if ((inode.i_mode & 0xF000u) == S_IFREG && inode.i_dir_acl)
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
    f->inode_kind_known = 1;
    f->is_symlink = ((inode.i_mode & 0xF000) == S_IFLNK);
    f->fs_private = ext2_driver.driver_data;
    fh->inode_no = ino;
    fh->inode = inode;
    f->driver_private = fh;
    *out_file = f;
    return 0;
}

/* Handles cache an inode at open; refresh it before each operation so a
 * sequential write through another open handle cannot be overwritten by a
 * stale block map or hidden by a stale size. */
static int ext2_refresh_file(struct fs_file *file) {
    struct ext2_file_handle *fh;
    if (!g_ext2 || !file || !file->driver_private)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    if (e2_read_inode(g_ext2, fh->inode_no, &fh->inode) != 0)
        return -1;
    if ((fh->inode.i_mode & 0xF000u) == S_IFREG && fh->inode.i_dir_acl)
        return -1;
    file->size = fh->inode.i_size;
    return 0;
}

/* Collect data and indirect blocks before detaching the inode. The count is
 * bounded by i_blocks and a conservative temporary-memory limit. */
static int e2_collect_truncate_blocks(struct ext2_mount *m, uint32_t block,
                                      unsigned depth, uint32_t *blocks,
                                      size_t *count, size_t capacity) {
    uint8_t *buf;
    if (!block)
        return 0;
    if (block < m->sb.s_first_data_block || block >= m->sb.s_blocks_count ||
        *count >= capacity)
        return -1;
    blocks[(*count)++] = block;
    if (!depth)
        return 0;
    buf = (uint8_t *)kmalloc(m->block_size);
    if (!buf)
        return -1;
    if (e2_bread(m, block, buf) != 0) {
        kfree(buf);
        return -1;
    }
    for (uint32_t i = 0; i < m->block_size / 4; i++) {
        uint32_t child = e2_le32(buf + i * 4);
        if (child && e2_collect_truncate_blocks(m, child, depth - 1,
                                                blocks, count, capacity) != 0) {
            kfree(buf);
            return -1;
        }
    }
    kfree(buf);
    return 0;
}

/* Heapsort avoids quadratic duplicate checks on large files. */
static void e2_sort_truncate_blocks(uint32_t *a, size_t n) {
    for (size_t start = n / 2; start > 0;) {
        size_t root = --start;
        while (root < n / 2) {
            size_t child = root * 2 + 1;
            if (child + 1 < n && a[child] < a[child + 1])
                child++;
            if (a[root] >= a[child])
                break;
            uint32_t tmp = a[root]; a[root] = a[child]; a[child] = tmp;
            root = child;
        }
    }
    for (size_t end = n; end > 1;) {
        uint32_t tmp = a[0]; a[0] = a[end - 1]; a[end - 1] = tmp;
        end--;
        size_t root = 0;
        while (root < end / 2) {
            size_t child = root * 2 + 1;
            if (child + 1 < end && a[child] < a[child + 1])
                child++;
            if (a[root] >= a[child])
                break;
            tmp = a[root]; a[root] = a[child]; a[child] = tmp;
            root = child;
        }
    }
}

/* Growth can remain sparse. Shrinking needs block reclamation, including
 * indirect tables; never report success until that is implemented. */
int ext2_ftruncate(struct fs_file *file, off_t length) {
    struct ext2_file_handle *fh;
    uint64_t ptrs, max_blocks, old_size;
    if (length < 0)
        return -22; /* EINVAL */
    if (ext2_refresh_file(file) != 0)
        return -5; /* EIO */
    fh = (struct ext2_file_handle *)file->driver_private;
    if ((fh->inode.i_mode & 0xF000) != S_IFREG)
        return -22;
    ptrs = g_ext2->block_size / 4;
    max_blocks = 12 + ptrs + ptrs * ptrs;
    if ((uint64_t)length > UINT32_MAX ||
        (uint64_t)length > max_blocks * g_ext2->block_size)
        return -27; /* EFBIG */
    old_size = fh->inode.i_size;
    if ((uint64_t)length < old_size) {
        /* A wholly sparse file has no data or indirect blocks to reclaim. */
        if (fh->inode.i_blocks) {
            uint32_t sectors_per_block = g_ext2->block_size / 512;
            size_t capacity = fh->inode.i_blocks / sectors_per_block, count = 0;
            uint32_t *blocks;
            if (length != 0 || fh->inode.i_block[14])
                return -95; /* nonzero shrink and triple-indirect blocks */
            if (!capacity || capacity > 65536)
                return -95; /* bounded temporary allocation */
            blocks = (uint32_t *)kmalloc(capacity * sizeof(*blocks));
            if (!blocks)
                return -12;
            for (unsigned i = 0; i < 14; i++) {
                unsigned depth = i < 12 ? 0 : i - 11;
                if (e2_collect_truncate_blocks(g_ext2, fh->inode.i_block[i],
                                               depth, blocks, &count, capacity) != 0) {
                    kfree(blocks);
                    return -5;
                }
            }
            e2_sort_truncate_blocks(blocks, count);
            for (size_t i = 1; i < count; i++)
                if (blocks[i] == blocks[i - 1]) {
                    kfree(blocks);
                    return -5;
                }
            for (unsigned i = 0; i < 14; i++)
                fh->inode.i_block[i] = 0;
            fh->inode.i_size = 0;
            fh->inode.i_blocks -= (uint32_t)(count * sectors_per_block);
            /* Detached first: an interrupted free may leak space but cannot
             * leave a live inode pointing at a free block. */
            if (e2_write_inode(g_ext2, fh->inode_no, &fh->inode) != 0) {
                kfree(blocks);
                return -5;
            }
            file->size = 0;
            for (size_t i = 0; i < count; i++)
                if (e2_free_data_block(g_ext2, blocks[i]) != 0) {
                    kfree(blocks);
                    return -5;
                }
            kfree(blocks);
            return 0;
        }
        for (unsigned i = 0; i < 15; i++)
            if (fh->inode.i_block[i])
                return -95;
        fh->inode.i_size = (uint32_t)length;
        if (e2_write_inode(g_ext2, fh->inode_no, &fh->inode) != 0)
            return -5;
        file->size = (size_t)length;
        return 0;
    }
    if ((uint64_t)length == old_size)
        return 0;
    if (old_size % g_ext2->block_size) {
        uint32_t block = e2_get_block(g_ext2, &fh->inode,
                                      (uint32_t)(old_size / g_ext2->block_size));
        if (block == UINT32_MAX)
            return -5;
        if (block) {
            uint8_t *buf = (uint8_t *)kmalloc(g_ext2->block_size);
            if (!buf)
                return -12; /* ENOMEM */
            if (e2_bread(g_ext2, block, buf) != 0) {
                kfree(buf);
                return -5;
            }
            memset(buf + old_size % g_ext2->block_size, 0,
                   g_ext2->block_size - old_size % g_ext2->block_size);
            if (e2_bwrite(g_ext2, block, buf) != 0) {
                kfree(buf);
                return -5;
            }
            kfree(buf);
        }
    }
    fh->inode.i_size = (uint32_t)length;
    if (e2_write_inode(g_ext2, fh->inode_no, &fh->inode) != 0)
        return -5;
    file->size = (size_t)length;
    return 0;
}

static ssize_t ext2_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    struct ext2_file_handle *fh;
    uint8_t *bb;
    size_t done = 0;

    if (!buf || ext2_refresh_file(file) != 0)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    /* Short ext2 symlink targets are stored inline in i_block, not at the
     * block numbers the same bytes would represent for a regular file. */
    if ((fh->inode.i_mode & 0xF000) == S_IFLNK &&
        fh->inode.i_blocks == 0 && fh->inode.i_size <= sizeof(fh->inode.i_block)) {
        if (offset >= fh->inode.i_size)
            return 0;
        if (size > fh->inode.i_size - offset)
            size = fh->inode.i_size - offset;
        memcpy(buf, (const uint8_t *)fh->inode.i_block + offset, size);
        return (ssize_t)size;
    }
    if (fh->inode.i_mode & 0x4000) {
        /* Directory: raw ext2 dirents (same as on disk). */
        uint32_t nblk = (fh->inode.i_size + g_ext2->block_size - 1) / g_ext2->block_size;
        size_t want = size;
        if (offset >= fh->inode.i_size)
            return 0;
        if (want > fh->inode.i_size - offset)
            want = fh->inode.i_size - offset;
        bb = (uint8_t *)kmalloc(g_ext2->block_size);
        if (!bb)
            return -1;
        while (done < want) {
            uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
            uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
            uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
            size_t chunk = g_ext2->block_size - inb;
            if (phys == UINT32_MAX) {
                kfree(bb);
                return done ? (ssize_t)done : -1;
            }
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
    if (size > fh->inode.i_size - offset)
        size = fh->inode.i_size - offset;
    bb = (uint8_t *)kmalloc(g_ext2->block_size);
    if (!bb)
        return -1;
    while (done < size) {
        uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
        uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
        uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
        size_t chunk = g_ext2->block_size - inb;
        if (phys == UINT32_MAX) {
            kfree(bb);
            return done ? (ssize_t)done : -1;
        }
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

    if (!buf || ext2_refresh_file(file) != 0)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    if ((fh->inode.i_mode & 0xF000) != S_IFREG)
        return -1;
    /* The current inode implementation has only a 32-bit file size. */
    if (offset > UINT32_MAX || size > UINT32_MAX - offset)
        return -1;
    bb = (uint8_t *)kmalloc(g_ext2->block_size);
    if (!bb)
        return -1;
    while (done < size) {
        uint32_t file_blk = (uint32_t)((offset + done) / g_ext2->block_size);
        uint32_t inb = (uint32_t)((offset + done) % g_ext2->block_size);
        uint32_t phys = e2_get_block(g_ext2, &fh->inode, file_blk);
        size_t chunk = g_ext2->block_size - inb;
        if (phys == UINT32_MAX)
            goto write_error;
        if (chunk > size - done)
            chunk = size - done;
        if (!phys) {
            phys = e2_alloc_block(g_ext2);
            if (!phys)
                goto write_error;
            if (e2_set_block(g_ext2, &fh->inode, file_blk, phys) != 0)
                goto write_error;
            fh->inode.i_blocks += g_ext2->block_size / 512;
            if (inb != 0 || chunk != g_ext2->block_size)
                memset(bb, 0, g_ext2->block_size);
        } else if (!(inb == 0 && chunk == g_ext2->block_size) &&
                   e2_bread(g_ext2, phys, bb) != 0) {
            goto write_error;
        }
        memcpy(bb + inb, (const uint8_t *)buf + done, chunk);
        if (e2_bwrite(g_ext2, phys, bb) != 0) {
            goto write_error;
        }
        done += chunk;
    }
    goto write_finish;
write_error:
    if (!done) {
        kfree(bb);
        return -1;
    }
write_finish:
    kfree(bb);
    if (offset + done > fh->inode.i_size)
        fh->inode.i_size = (uint32_t)(offset + done);
    file->size = fh->inode.i_size;
    if (done && e2_write_inode(g_ext2, fh->inode_no, &fh->inode) != 0)
        return -1;
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

/* Linux link(2) links the inode itself, including a symbolic-link inode.
 * Parent symlinks have already been resolved by the VFS. */
static int ext2_link(const char *oldpath, const char *newpath) {
    char oldrel[512], newrel[512], parent[512], base[256];
    struct ext2_inode src, dir;
    uint32_t src_ino, dir_ino, existing;
    char *slash;
    int lookup;
    uint8_t type;

    if (!g_ext2 || !oldpath || !newpath ||
        e2_relpath(oldpath, oldrel, sizeof(oldrel)) != 0 ||
        e2_relpath(newpath, newrel, sizeof(newrel)) != 0)
        return -2;
    if (e2_walk(g_ext2, oldrel, &src_ino, &src) != 0)
        return -2;
    if ((src.i_mode & 0xF000u) == S_IFDIR)
        return -1; /* EPERM: hard links to directories are forbidden */
    if ((src.i_mode & 0xF000u) == S_IFREG)
        type = EXT2_FT_REG_FILE;
    else if ((src.i_mode & 0xF000u) == S_IFLNK)
        type = EXT2_FT_SYMLINK;
    else
        return -95; /* unsupported inode type */
    if (src.i_links_count == 0xffffu)
        return -31; /* EMLINK */
    strcpy(parent, newrel);
    slash = strrchr(parent, '/');
    if (!slash || !slash[1] || strlen(slash + 1) >= sizeof(base))
        return -2;
    strcpy(base, slash + 1);
    if (slash == parent)
        parent[1] = 0;
    else
        *slash = 0;
    if (e2_walk(g_ext2, parent, &dir_ino, &dir) != 0)
        return -2;
    if ((dir.i_mode & 0xF000u) != S_IFDIR)
        return -20; /* ENOTDIR */
    if (dir.i_flags & 0x1000u)
        return -95; /* HTree writes are not implemented */
    lookup = e2_dir_lookup(g_ext2, &dir, base, &existing, NULL);
    if (lookup == 0)
        return -17;
    if (lookup != -1)
        return -5;
    src.i_links_count++;
    if (e2_write_inode(g_ext2, src_ino, &src) != 0)
        return -5;
    if (e2_dir_add(g_ext2, dir_ino, &dir, base, src_ino, type) != 0) {
        src.i_links_count--;
        if (e2_write_inode(g_ext2, src_ino, &src) != 0)
            klogprintf("ext2: failed to roll back link count for inode %u\n", src_ino);
        return -5;
    }
    return 0;
}

static int ext2_create(const char *path, struct fs_file **out_file) {
    char rel[512], parent[512], base[256];
    char *slash;
    uint32_t pino = 0, nino;
    struct ext2_inode pino_i, ni;
    thread_t *owner = thread_get_current_user();
    if (!owner)
        owner = thread_current();
    if (owner && g_ext2 && g_ext2->sb.s_creator_os != 0 &&
        (owner->euid > 65535 || owner->egid > 65535))
        return -1;

    if (!g_ext2 || !path)
        return -1;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    strncpy(parent, rel, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    if (strlen(slash + 1) >= sizeof(base))
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
    if (pino_i.i_flags & 0x1000u)
        return -1;
    {
        uint32_t existing;
        if (e2_dir_lookup(g_ext2, &pino_i, base, &existing, NULL) != -1)
            return -1;
    }
    nino = e2_alloc_inode(g_ext2);
    if (!nino)
        return -1;
    memset(&ni, 0, sizeof(ni));
    ni.i_mode = (uint16_t)(S_IFREG | 0644);
    ni.i_links_count = 1;
    (void)e2_set_inode_owner(g_ext2, &ni, owner ? owner->euid : 0,
                             (pino_i.i_mode & 02000) ? e2_inode_gid(g_ext2, &pino_i) :
                             owner ? owner->egid : 0);
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

/* Short links live in the inode; longer targets use direct data blocks. */
int ext2_symlink(const char *path, const char *target, uint32_t uid, uint32_t gid) {
    char rel[512], parent[512], base[256], *slash;
    struct ext2_inode parent_inode, inode;
    uint32_t parent_ino, ino, existing;
    size_t target_len;
    uint32_t allocated = 0;
    int lookup;
    if (!g_ext2 || !path || !target || !target[0])
        return -2; /* ENOENT */
    if (g_ext2->sb.s_creator_os != 0 && (uid > 65535 || gid > 65535))
        return -75;
    target_len = strlen(target);
    /* ext2 symlink targets must fit in one filesystem block, with a
     * terminating NUL available to the kernel pathname implementation. */
    if (target_len >= g_ext2->block_size)
        return -36;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -36; /* ENAMETOOLONG */
    strncpy(parent, rel, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    slash = strrchr(parent, '/');
    if (!slash || !slash[1])
        return -2;
    if (strlen(slash + 1) >= sizeof(base))
        return -36;
    strcpy(base, slash + 1);
    if (slash == parent)
        parent[1] = 0;
    else
        *slash = 0;
    if (e2_walk(g_ext2, parent, &parent_ino, &parent_inode) != 0)
        return -2;
    if ((parent_inode.i_mode & 0xF000) != S_IFDIR)
        return -20; /* ENOTDIR */
    if (parent_inode.i_flags & 0x1000u)
        return -95;
    lookup = e2_dir_lookup(g_ext2, &parent_inode, base, &existing, NULL);
    if (lookup == 0)
        return -17; /* EEXIST */
    if (lookup != -1)
        return -5; /* EIO */
    ino = e2_alloc_inode(g_ext2);
    if (!ino)
        return -28; /* ENOSPC */
    memset(&inode, 0, sizeof(inode));
    inode.i_mode = (uint16_t)(S_IFLNK | 0777);
    (void)e2_set_inode_owner(g_ext2, &inode, uid,
                             (parent_inode.i_mode & 02000) ?
                             e2_inode_gid(g_ext2, &parent_inode) : gid);
    inode.i_links_count = 1;
    inode.i_size = (uint32_t)target_len;
    if (target_len <= sizeof(inode.i_block)) {
        memcpy(inode.i_block, target, target_len);
    } else {
        size_t done = 0;
        uint8_t *buf = (uint8_t *)kmalloc(g_ext2->block_size);
        if (!buf)
            goto fail_unpublished;
        while (done < target_len) {
            size_t chunk = target_len - done;
            uint32_t block;
            if (chunk > g_ext2->block_size)
                chunk = g_ext2->block_size;
            block = e2_alloc_block(g_ext2);
            if (!block) {
                kfree(buf);
                goto fail_unpublished;
            }
            inode.i_block[allocated++] = block;
            inode.i_blocks += g_ext2->block_size / 512;
            memset(buf, 0, g_ext2->block_size);
            memcpy(buf, target + done, chunk);
            if (e2_bwrite(g_ext2, block, buf) != 0) {
                kfree(buf);
                goto fail_unpublished;
            }
            done += chunk;
        }
        kfree(buf);
    }
    if (e2_write_inode(g_ext2, ino, &inode) != 0)
        goto fail_unpublished;
    /* On an ambiguous directory write failure do not free blocks or the inode:
     * the entry may already have reached disk and must never dangle. */
    if (e2_dir_add(g_ext2, parent_ino, &parent_inode, base, ino, EXT2_FT_SYMLINK) != 0)
        return -5;
    return 0;
fail_unpublished:
    {
        struct ext2_inode empty;
        memset(&empty, 0, sizeof(empty));
        if (e2_write_inode(g_ext2, ino, &empty) == 0) {
            for (uint32_t i = 0; i < allocated; i++)
                if (e2_free_data_block(g_ext2, inode.i_block[i]) != 0)
                    return -5;
            (void)e2_free_inode_number(g_ext2, ino);
        }
    }
    return -5;
}

static int ext2_mkdir(const char *path) {
    char rel[512], parent[512], base[256];
    char *slash;
    uint32_t pino = 0, nino, dblk;
    struct ext2_inode pino_i, ni;
    uint8_t *buf;
    struct ext2_dir_entry *de;
    thread_t *owner = thread_get_current_user();
    if (!owner)
        owner = thread_current();
    if (owner && g_ext2 && g_ext2->sb.s_creator_os != 0 &&
        (owner->euid > 65535 || owner->egid > 65535))
        return -1;

    if (!g_ext2 || !path)
        return -1;
    if (e2_relpath(path, rel, sizeof(rel)) != 0)
        return -1;
    strncpy(parent, rel, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    if (strlen(slash + 1) >= sizeof(base))
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
    if (pino_i.i_flags & 0x1000u)
        return -1;
    {
        uint32_t existing;
        int lookup = e2_dir_lookup(g_ext2, &pino_i, base, &existing, NULL);
        if (lookup == 0)
            return -4; /* existing name: VFS mkdir maps this to EEXIST */
        if (lookup != -1)
            return -1;
    }
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
    if (pino_i.i_mode & 02000)
        ni.i_mode |= 02000;
    (void)e2_set_inode_owner(g_ext2, &ni, owner ? owner->euid : 0,
                             (pino_i.i_mode & 02000) ? e2_inode_gid(g_ext2, &pino_i) :
                             owner ? owner->egid : 0);
    ni.i_links_count = 2;
    ni.i_size = g_ext2->block_size;
    ni.i_blocks = g_ext2->block_size / 512;
    ni.i_block[0] = dblk;
    if (e2_write_inode(g_ext2, nino, &ni) != 0)
        return -1;
    pino_i.i_links_count++;
    if (e2_dir_add(g_ext2, pino, &pino_i, base, nino, EXT2_FT_DIR) != 0)
        return -1;
    if (e2_write_inode(g_ext2, pino, &pino_i) != 0)
        return -1;
    {
        uint32_t group = (nino - 1) / g_ext2->inodes_per_group;
        struct ext2_group_desc gd;
        if (e2_read_gd(g_ext2, group, &gd) != 0)
            return -1;
        gd.bg_used_dirs_count++;
        if (e2_write_gd(g_ext2, group, &gd) != 0)
            return -1;
    }
    return 0;
}

static int ext2_chmod(const char *path, mode_t mode) {
    char rel[512];
    uint32_t ino;
    struct ext2_inode inode;
    if (!g_ext2 || !path || e2_relpath(path, rel, sizeof(rel)) != 0 ||
        e2_walk(g_ext2, rel, &ino, &inode) != 0)
        return -1;
    /* chmod follows symlinks; do not accidentally change the link inode when
     * the caller has not resolved the final component. */
    if ((inode.i_mode & 0xF000u) == S_IFLNK)
        return -1;
    inode.i_mode = (uint16_t)((inode.i_mode & 0xF000u) | (mode & 07777u));
    return e2_write_inode(g_ext2, ino, &inode);
}

int ext2_fchmod_file(struct fs_file *file, mode_t mode) {
    struct ext2_file_handle *fh;
    if (ext2_refresh_file(file) != 0)
        return -5;
    fh = (struct ext2_file_handle *)file->driver_private;
    if ((fh->inode.i_mode & 0xF000u) == S_IFLNK)
        return -22;
    fh->inode.i_mode = (uint16_t)((fh->inode.i_mode & 0xF000u) | (mode & 07777u));
    return e2_write_inode(g_ext2, fh->inode_no, &fh->inode) == 0 ? 0 : -5;
}

int ext2_fchown_file(struct fs_file *file, uint32_t uid, uint32_t gid) {
    struct ext2_file_handle *fh;
    int changed;
    if (ext2_refresh_file(file) != 0)
        return -5;
    fh = (struct ext2_file_handle *)file->driver_private;
    uint32_t old_uid = e2_inode_uid(g_ext2, &fh->inode);
    uint32_t old_gid = e2_inode_gid(g_ext2, &fh->inode);
    if (uid == UINT32_MAX) uid = old_uid;
    if (gid == UINT32_MAX) gid = old_gid;
    changed = uid != old_uid || gid != old_gid;
    if (e2_set_inode_owner(g_ext2, &fh->inode, uid, gid) != 0)
        return -75;
    if (changed && (fh->inode.i_mode & 0xF000u) != S_IFDIR)
        fh->inode.i_mode &= (uint16_t)~06000u;
    if (!changed)
        return 0;
    return e2_write_inode(g_ext2, fh->inode_no, &fh->inode) == 0 ? 0 : -5;
}

int ext2_fill_stat(struct fs_file *file, struct stat *st) {
    struct ext2_file_handle *fh;
    if (!st || ext2_refresh_file(file) != 0)
        return -1;
    fh = (struct ext2_file_handle *)file->driver_private;
    memset(st, 0, sizeof(*st));
    st->st_mode = fh->inode.i_mode;
    st->st_uid = e2_inode_uid(g_ext2, &fh->inode);
    st->st_gid = e2_inode_gid(g_ext2, &fh->inode);
    st->st_nlink = fh->inode.i_links_count ? fh->inode.i_links_count : 1;
    st->st_size = fh->inode.i_size;
    st->st_ino = fh->inode_no;
    return 0;
}

static int ext2_bind(struct ext2_mount *m) {
    /* The driver currently has one global mount. Replacing it would redirect
     * all existing open handles to the new filesystem and free their backing. */
    if (g_ext2)
        return -1;
    if (e2_read_sb(m) != 0)
        return -1;
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
    if (g_ext2->image && g_ext2->img_size >= 2048) {
        /* Preserve unmodelled superblock fields just as for a disk mount. */
        memcpy((uint8_t *)g_ext2->image + 1024, &g_ext2->sb, sizeof(g_ext2->sb));
    } else if (!g_ext2->image && g_ext2->device_id >= 0) {
        uint8_t raw[1024];
        /* The in-memory struct covers only the first part of the superblock.
         * Preserve feature flags, UUID and all other fields we do not model. */
        if (disk_read_sectors(g_ext2->device_id, g_ext2->start_lba + 2, raw, 2) == 0) {
            memcpy(raw, &g_ext2->sb, sizeof(g_ext2->sb));
            if (disk_write_sectors(g_ext2->device_id, g_ext2->start_lba + 2, raw, 2) != 0)
                klogprintf("ext2: failed to write superblock on unmount\n");
        } else {
            klogprintf("ext2: failed to read superblock on unmount; not writing\n");
        }
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
    ext2_ops.chmod = ext2_chmod;
    ext2_ops.link = ext2_link;
    ext2_driver.ops = &ext2_ops;
    ext2_driver.driver_data = NULL;
    return fs_register_driver(&ext2_driver);
}

int ext2_unregister(void) {
    ext2_unmount_cleanup();
    return fs_unregister_driver(&ext2_driver);
}
