/*
 * SquashFS 4.0 read-only filesystem — mount from identity-mapped image.
 * Linux-compatible layout: metadata, directories, regular files, symlinks,
 * fragments, gzip (zlib) compression. Hard links share the same inode.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <heap.h>
#include <fs.h>
#include <stat.h>
#include <ext2.h>
#include <squashfs.h>
#include <zlib_inflate.h>
#include <klog.h>

#define SQUASHFS_METADATA_SIZE 8192
#define SQUASHFS_NAME_LEN 256
#define SQUASHFS_INVALID_FRAG 0xffffffffu

#define SQUASHFS_COMPRESSED_BIT 0x8000u
#define SQUASHFS_COMPRESSED_BIT_BLOCK (1u << 24)

#define ZLIB_COMPRESSION 1

#define SQUASHFS_DIR_TYPE 1
#define SQUASHFS_REG_TYPE 2
#define SQUASHFS_SYMLINK_TYPE 3
#define SQUASHFS_LDIR_TYPE 8
#define SQUASHFS_LREG_TYPE 9
#define SQUASHFS_LSYMLINK_TYPE 10

struct squashfs_super_block {
    uint32_t s_magic;
    uint32_t inodes;
    uint32_t mkfs_time;
    uint32_t block_size;
    uint32_t fragments;
    uint16_t compression;
    uint16_t block_log;
    uint16_t flags;
    uint16_t no_ids;
    uint16_t s_major;
    uint16_t s_minor;
    uint64_t root_inode;
    uint64_t bytes_used;
    uint64_t id_table_start;
    uint64_t xattr_id_table_start;
    uint64_t inode_table_start;
    uint64_t directory_table_start;
    uint64_t fragment_table_start;
    uint64_t lookup_table_start;
} __attribute__((packed));

struct squashfs_fragment_entry {
    uint64_t start_block;
    uint32_t size;
    uint32_t unused;
} __attribute__((packed));

/* Parsed inode (subset we need). */
struct squashfs_inode_info {
    uint16_t type;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t mtime;
    uint32_t inode_number;
    uint32_t nlink;
    uint64_t file_size;
    uint64_t start_block; /* data start, or dir table relative for directories */
    uint32_t fragment;
    uint32_t frag_offset;
    uint32_t parent_inode;
    uint16_t offset; /* dir: offset into metadata block */
    uint16_t symlink_size;
    /* Regular file block list follows inode on disk; we store disk cursor. */
    uint64_t block_list_abs; /* absolute byte offset of first block_list u32 */
    uint32_t block_count;
    char *symlink; /* kmalloc'd target for symlinks */
};

struct squashfs_file_handle {
    struct squashfs_inode_info ino;
    /* Merged directory listing cache (ext2 dirents). */
    uint8_t *dir_blob;
    size_t dir_blob_len;
};

struct meta_cache_ent {
    uint64_t abs_pos;
    uint8_t data[SQUASHFS_METADATA_SIZE];
    size_t len;
    int valid;
};

#define META_CACHE_SLOTS 16
#define DATA_CACHE_SLOTS 8

struct data_cache_ent {
    uint64_t abs_pos;
    uint32_t comp_size;
    uint8_t *data;
    size_t len;
    int valid;
};

struct squashfs_sb {
    const uint8_t *image;
    size_t size;
    struct squashfs_super_block sb;
    uint32_t block_size;
    uint64_t *frag_index; /* absolute offsets of fragment metadata blocks */
    uint32_t frag_index_count;
    struct meta_cache_ent meta_cache[META_CACHE_SLOTS];
    int meta_cache_next;
    struct data_cache_ent data_cache[DATA_CACHE_SLOTS];
    int data_cache_next;
    char mount_prefix[64]; /* "" for overlay lower, or "/squash" etc. */
    size_t mount_prefix_len;
};

static struct fs_driver squashfs_driver;
static struct fs_driver_ops squashfs_ops;
static struct squashfs_sb *g_sq = NULL;

static uint16_t rd16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}
static uint32_t rd32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static uint64_t rd64(const void *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32((const uint8_t *)p + 4) << 32);
}

static int sq_in_range(const struct squashfs_sb *s, uint64_t off, size_t n)
{
    if (!s || !s->image)
        return 0;
    if (off > s->size)
        return 0;
    if (n > s->size - (size_t)off)
        return 0;
    return 1;
}

static int sq_read_data_block(struct squashfs_sb *s, uint64_t abs_pos, uint32_t size_field,
                              void *out, size_t out_cap, size_t *out_len, size_t expected_unc)
{
    uint32_t csize;
    int compressed;
    const uint8_t *src;
    size_t got = 0;
    int i;

    if (!s || !out || !out_len)
        return -1;
    compressed = !(size_field & SQUASHFS_COMPRESSED_BIT_BLOCK);
    csize = size_field & ~SQUASHFS_COMPRESSED_BIT_BLOCK;
    if (csize == 0)
        return -1;
    if (!sq_in_range(s, abs_pos, csize))
        return -1;

    /* data cache */
    for (i = 0; i < DATA_CACHE_SLOTS; i++) {
        if (s->data_cache[i].valid && s->data_cache[i].abs_pos == abs_pos &&
            s->data_cache[i].comp_size == csize) {
            if (s->data_cache[i].len > out_cap)
                return -1;
            memcpy(out, s->data_cache[i].data, s->data_cache[i].len);
            *out_len = s->data_cache[i].len;
            return 0;
        }
    }

    src = s->image + abs_pos;
    if (!compressed) {
        if (csize > out_cap)
            return -1;
        memcpy(out, src, csize);
        got = csize;
    } else {
        if (zlib_inflate(out, out_cap, &got, src, csize) != 0)
            return -1;
        if (expected_unc && got != expected_unc && got > expected_unc)
            return -1;
    }
    *out_len = got;

    /* store in cache */
    {
        struct data_cache_ent *e = &s->data_cache[s->data_cache_next];
        s->data_cache_next = (s->data_cache_next + 1) % DATA_CACHE_SLOTS;
        if (e->data)
            kfree(e->data);
        e->data = (uint8_t *)kmalloc(got);
        if (e->data) {
            memcpy(e->data, out, got);
            e->len = got;
            e->abs_pos = abs_pos;
            e->comp_size = csize;
            e->valid = 1;
        } else {
            e->valid = 0;
        }
    }
    return 0;
}

static int sq_read_metadata_block(struct squashfs_sb *s, uint64_t abs_pos,
                                  uint8_t *out, size_t *out_len, uint64_t *next_pos)
{
    uint16_t header;
    uint16_t csize;
    int compressed;
    const uint8_t *src;
    size_t got = 0;
    int i;

    if (!s || !out || !out_len)
        return -1;
    if (!sq_in_range(s, abs_pos, 2))
        return -1;

    for (i = 0; i < META_CACHE_SLOTS; i++) {
        if (s->meta_cache[i].valid && s->meta_cache[i].abs_pos == abs_pos) {
            memcpy(out, s->meta_cache[i].data, s->meta_cache[i].len);
            *out_len = s->meta_cache[i].len;
            if (next_pos) {
                header = rd16(s->image + abs_pos);
                csize = header & ~SQUASHFS_COMPRESSED_BIT;
                *next_pos = abs_pos + 2 + csize;
            }
            return 0;
        }
    }

    header = rd16(s->image + abs_pos);
    compressed = !(header & SQUASHFS_COMPRESSED_BIT);
    csize = header & (uint16_t)~SQUASHFS_COMPRESSED_BIT;
    if (csize == 0 || csize > SQUASHFS_METADATA_SIZE)
        return -1;
    if (!sq_in_range(s, abs_pos + 2, csize))
        return -1;
    src = s->image + abs_pos + 2;
    if (!compressed) {
        memcpy(out, src, csize);
        got = csize;
    } else {
        if (zlib_inflate(out, SQUASHFS_METADATA_SIZE, &got, src, csize) != 0)
            return -1;
        if (got > SQUASHFS_METADATA_SIZE)
            return -1;
    }
    *out_len = got;
    if (next_pos)
        *next_pos = abs_pos + 2 + csize;

    {
        struct meta_cache_ent *e = &s->meta_cache[s->meta_cache_next];
        s->meta_cache_next = (s->meta_cache_next + 1) % META_CACHE_SLOTS;
        e->abs_pos = abs_pos;
        e->len = got;
        memcpy(e->data, out, got);
        e->valid = 1;
    }
    return 0;
}

/* Read `want` bytes from metadata stream starting at (block_abs, offset). */
static int sq_meta_read(struct squashfs_sb *s, uint64_t *block_abs, uint16_t *offset,
                        void *dst, size_t want)
{
    uint8_t *out = (uint8_t *)dst;
    size_t done = 0;
    uint8_t blk[SQUASHFS_METADATA_SIZE];
    size_t blk_len = 0;
    uint64_t next = 0;

    /* dst may be NULL to skip bytes (block-list / dir-index name skip). */
    if (!s || !block_abs || !offset)
        return -1;
    if (want == 0)
        return 0;

    while (done < want) {
        if (sq_read_metadata_block(s, *block_abs, blk, &blk_len, &next) != 0)
            return -1;
        if (*offset > blk_len)
            return -1;
        {
            size_t avail = blk_len - *offset;
            size_t take = want - done;
            if (take > avail)
                take = avail;
            if (take && out)
                memcpy(out + done, blk + *offset, take);
            done += take;
            *offset = (uint16_t)(*offset + take);
            if (*offset >= blk_len && done < want) {
                *block_abs = next;
                *offset = 0;
            }
        }
    }
    return 0;
}

static int sq_load_fragment_table(struct squashfs_sb *s)
{
    uint32_t indexes;
    uint64_t list_off;
    uint32_t i;

    if (!s || s->sb.fragments == 0) {
        s->frag_index = NULL;
        s->frag_index_count = 0;
        return 0;
    }
    if (s->sb.fragment_table_start == ~(uint64_t)0)
        return 0;

    indexes = (s->sb.fragments * sizeof(struct squashfs_fragment_entry) + SQUASHFS_METADATA_SIZE - 1) /
              SQUASHFS_METADATA_SIZE;
    s->frag_index_count = indexes;
    s->frag_index = (uint64_t *)kmalloc(indexes * sizeof(uint64_t));
    if (!s->frag_index)
        return -1;
    list_off = s->sb.fragment_table_start;
    if (!sq_in_range(s, list_off, indexes * 8))
        return -1;
    for (i = 0; i < indexes; i++)
        s->frag_index[i] = rd64(s->image + list_off + (uint64_t)i * 8);
    return 0;
}

static int sq_get_fragment_entry(struct squashfs_sb *s, uint32_t frag,
                                 struct squashfs_fragment_entry *out)
{
    uint32_t meta_i, off;
    uint64_t block_abs;
    uint16_t moff;
    uint8_t tmp[16];

    if (!s || !out || frag == SQUASHFS_INVALID_FRAG)
        return -1;
    if (frag >= s->sb.fragments || !s->frag_index)
        return -1;
    meta_i = (frag * (uint32_t)sizeof(struct squashfs_fragment_entry)) / SQUASHFS_METADATA_SIZE;
    off = (frag * (uint32_t)sizeof(struct squashfs_fragment_entry)) % SQUASHFS_METADATA_SIZE;
    if (meta_i >= s->frag_index_count)
        return -1;
    block_abs = s->frag_index[meta_i];
    moff = (uint16_t)off;
    if (sq_meta_read(s, &block_abs, &moff, tmp, sizeof(struct squashfs_fragment_entry)) != 0)
        return -1;
    out->start_block = rd64(tmp);
    out->size = rd32(tmp + 8);
    out->unused = rd32(tmp + 12);
    return 0;
}

static uint32_t sq_inode_base_size(uint16_t type)
{
    switch (type) {
    case SQUASHFS_DIR_TYPE:
        return 32;
    case SQUASHFS_LDIR_TYPE:
        return 40; /* without index entries */
    case SQUASHFS_REG_TYPE:
        return 32;
    case SQUASHFS_LREG_TYPE:
        return 56;
    case SQUASHFS_SYMLINK_TYPE:
    case SQUASHFS_LSYMLINK_TYPE:
        return 24; /* + symlink bytes */
    default:
        return 16; /* base */
    }
}

static int sq_read_inode(struct squashfs_sb *s, uint64_t inode_ref, struct squashfs_inode_info *out)
{
    uint64_t block_rel = inode_ref >> 16;
    uint16_t offset = (uint16_t)(inode_ref & 0xffffu);
    uint64_t block_abs;
    uint8_t hdr[64];
    uint16_t type, mode, uid_idx, gid_idx;
    uint32_t mtime, ino_no;

    if (!s || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->fragment = SQUASHFS_INVALID_FRAG;
    block_abs = s->sb.inode_table_start + block_rel;

    /* base header 16 bytes */
    if (sq_meta_read(s, &block_abs, &offset, hdr, 16) != 0)
        return -1;
    type = rd16(hdr + 0);
    mode = rd16(hdr + 2);
    uid_idx = rd16(hdr + 4);
    gid_idx = rd16(hdr + 6);
    mtime = rd32(hdr + 8);
    ino_no = rd32(hdr + 12);
    (void)uid_idx;
    (void)gid_idx;

    out->type = type;
    out->mode = mode;
    out->mtime = mtime;
    out->inode_number = ino_no;
    out->nlink = 1;
    out->uid = 0;
    out->gid = 0;

    if (type == SQUASHFS_DIR_TYPE) {
        uint8_t b[16];
        if (sq_meta_read(s, &block_abs, &offset, b, 16) != 0)
            return -1;
        out->start_block = rd32(b + 0);
        out->nlink = rd32(b + 4);
        out->file_size = rd16(b + 8);
        out->offset = rd16(b + 10);
        out->parent_inode = rd32(b + 12);
        return 0;
    }
    if (type == SQUASHFS_LDIR_TYPE) {
        uint8_t b[24];
        if (sq_meta_read(s, &block_abs, &offset, b, 24) != 0)
            return -1;
        out->nlink = rd32(b + 0);
        out->file_size = rd32(b + 4);
        out->start_block = rd32(b + 8);
        out->parent_inode = rd32(b + 12);
        /* i_count at +16, offset at +18, xattr at +20 — skip index entries */
        {
            uint16_t i_count = rd16(b + 16);
            uint16_t di;
            out->offset = rd16(b + 18);
            for (di = 0; di < i_count; di++) {
                uint8_t idx[12];
                uint32_t name_sz;
                if (sq_meta_read(s, &block_abs, &offset, idx, 12) != 0)
                    return -1;
                name_sz = rd32(idx + 8) + 1;
                if (sq_meta_read(s, &block_abs, &offset, NULL, name_sz) != 0)
                    return -1;
            }
        }
        return 0;
    }
    if (type == SQUASHFS_REG_TYPE) {
        uint8_t b[16];
        uint32_t blocks;
        if (sq_meta_read(s, &block_abs, &offset, b, 16) != 0)
            return -1;
        out->start_block = rd32(b + 0);
        out->fragment = rd32(b + 4);
        out->frag_offset = rd32(b + 8);
        out->file_size = rd32(b + 12);
        out->nlink = 1;
        if (out->fragment == SQUASHFS_INVALID_FRAG)
            blocks = (uint32_t)((out->file_size + s->block_size - 1) / s->block_size);
        else
            blocks = (uint32_t)(out->file_size / s->block_size);
        out->block_count = blocks;
        /* Remember absolute location of block list: current metadata cursor.
         * Encode as (block_abs << 16) | offset for later reads. */
        out->block_list_abs = (block_abs << 16) | (uint64_t)offset;
        /* Skip block list in the stream so callers that continue aren't needed */
        if (blocks) {
            if (sq_meta_read(s, &block_abs, &offset, NULL, blocks * 4) != 0)
                return -1;
        }
        return 0;
    }
    if (type == SQUASHFS_LREG_TYPE) {
        uint8_t b[40];
        uint32_t blocks;
        if (sq_meta_read(s, &block_abs, &offset, b, 40) != 0)
            return -1;
        out->start_block = rd64(b + 0);
        out->file_size = rd64(b + 8);
        /* sparse at +16 */
        out->nlink = rd32(b + 24);
        out->fragment = rd32(b + 28);
        out->frag_offset = rd32(b + 32);
        /* xattr at +36 */
        if (out->fragment == SQUASHFS_INVALID_FRAG)
            blocks = (uint32_t)((out->file_size + s->block_size - 1) / s->block_size);
        else
            blocks = (uint32_t)(out->file_size / s->block_size);
        out->block_count = blocks;
        out->block_list_abs = (block_abs << 16) | (uint64_t)offset;
        if (blocks) {
            if (sq_meta_read(s, &block_abs, &offset, NULL, blocks * 4) != 0)
                return -1;
        }
        return 0;
    }
    if (type == SQUASHFS_SYMLINK_TYPE || type == SQUASHFS_LSYMLINK_TYPE) {
        uint8_t b[8];
        uint32_t slen;
        if (sq_meta_read(s, &block_abs, &offset, b, 8) != 0)
            return -1;
        out->nlink = rd32(b + 0);
        slen = rd32(b + 4);
        out->symlink_size = (uint16_t)(slen > 0xffffu ? 0xffffu : slen);
        out->file_size = slen;
        out->symlink = (char *)kmalloc(slen + 1);
        if (!out->symlink)
            return -1;
        if (slen) {
            if (sq_meta_read(s, &block_abs, &offset, out->symlink, slen) != 0) {
                kfree(out->symlink);
                out->symlink = NULL;
                return -1;
            }
        }
        out->symlink[slen] = '\0';
        if (type == SQUASHFS_LSYMLINK_TYPE) {
            /* skip xattr u32 */
            if (sq_meta_read(s, &block_abs, &offset, NULL, 4) != 0)
                return -1;
        }
        return 0;
    }

    /* unsupported types (devices/fifo/socket): still allow as empty nodes */
    out->file_size = 0;
    (void)sq_inode_base_size;
    return 0;
}

static void sq_inode_info_free(struct squashfs_inode_info *ino)
{
    if (!ino)
        return;
    if (ino->symlink) {
        kfree(ino->symlink);
        ino->symlink = NULL;
    }
}

static int sq_lookup_dir(struct squashfs_sb *s, const struct squashfs_inode_info *dir,
                         const char *name, uint64_t *out_inode_ref, uint16_t *out_type)
{
    uint64_t block_abs;
    uint16_t offset;
    uint32_t bytes_left;
    char namebuf[SQUASHFS_NAME_LEN + 1];

    if (!s || !dir || !name || !out_inode_ref)
        return -1;
    if (dir->type != SQUASHFS_DIR_TYPE && dir->type != SQUASHFS_LDIR_TYPE)
        return -1;

    /* file_size includes the leading header accounting; Linux uses size-3. */
    if (dir->file_size < 3)
        return -1;
    bytes_left = (uint32_t)dir->file_size - 3;

    block_abs = s->sb.directory_table_start + dir->start_block;
    offset = dir->offset;

    while (bytes_left >= 12) {
        uint8_t hdr[12];
        uint32_t count, start_block, ino_base;
        uint32_t i;

        if (sq_meta_read(s, &block_abs, &offset, hdr, 12) != 0)
            return -1;
        bytes_left -= 12;
        count = rd32(hdr + 0) + 1; /* stored as count-1 */
        start_block = rd32(hdr + 4);
        ino_base = rd32(hdr + 8);

        for (i = 0; i < count; i++) {
            uint8_t ent[8];
            uint16_t ent_off, ino_delta, ent_type, name_size;
            uint32_t ino_no;
            uint64_t iref;

            if (bytes_left < 8)
                return -1;
            if (sq_meta_read(s, &block_abs, &offset, ent, 8) != 0)
                return -1;
            bytes_left -= 8;
            ent_off = rd16(ent + 0);
            ino_delta = rd16(ent + 2);
            ent_type = rd16(ent + 4);
            name_size = rd16(ent + 6) + 1; /* stored as size-1 */

            if (name_size > SQUASHFS_NAME_LEN || bytes_left < name_size)
                return -1;
            if (sq_meta_read(s, &block_abs, &offset, namebuf, name_size) != 0)
                return -1;
            bytes_left -= name_size;
            namebuf[name_size] = '\0';

            if (strcmp(namebuf, name) == 0) {
                ino_no = ino_base + (int16_t)ino_delta;
                (void)ino_no;
                iref = ((uint64_t)start_block << 16) | (uint64_t)ent_off;
                *out_inode_ref = iref;
                if (out_type)
                    *out_type = ent_type;
                return 0;
            }
        }
    }
    return -1; /* not found */
}

static int sq_path_to_inode(struct squashfs_sb *s, const char *path, struct squashfs_inode_info *out)
{
    struct squashfs_inode_info cur;
    char comp[SQUASHFS_NAME_LEN + 1];
    const char *p;

    if (!s || !path || !out)
        return -1;
    if (path[0] != '/')
        return -1;

    if (sq_read_inode(s, s->sb.root_inode, &cur) != 0)
        return -1;

    p = path;
    while (*p == '/')
        p++;
    if (*p == '\0') {
        *out = cur;
        return 0;
    }

    while (*p) {
        size_t n = 0;
        uint64_t next_ref = 0;
        struct squashfs_inode_info next;

        while (p[n] && p[n] != '/' && n < SQUASHFS_NAME_LEN)
            n++;
        if (n == 0)
            break;
        memcpy(comp, p, n);
        comp[n] = '\0';
        p += n;
        while (*p == '/')
            p++;

        if (sq_lookup_dir(s, &cur, comp, &next_ref, NULL) != 0) {
            sq_inode_info_free(&cur);
            return -1;
        }
        sq_inode_info_free(&cur);
        if (sq_read_inode(s, next_ref, &next) != 0)
            return -1;
        cur = next;
    }
    *out = cur;
    return 0;
}

static int sq_read_blocklist_size(struct squashfs_sb *s, const struct squashfs_inode_info *ino,
                                  uint32_t index, uint32_t *out_size)
{
    uint64_t block_abs = ino->block_list_abs >> 16;
    uint16_t offset = (uint16_t)(ino->block_list_abs & 0xffffu);
    uint8_t tmp[4];
    uint32_t i;

    if (!s || !ino || !out_size)
        return -1;
    if (index >= ino->block_count)
        return -1;
    for (i = 0; i <= index; i++) {
        if (sq_meta_read(s, &block_abs, &offset, tmp, 4) != 0)
            return -1;
    }
    *out_size = rd32(tmp);
    return 0;
}

static int sq_file_read(struct squashfs_sb *s, const struct squashfs_inode_info *ino,
                        void *buf, size_t size, size_t offset, ssize_t *out_n)
{
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    uint8_t *block_buf = NULL;
    size_t block_buf_cap;

    if (!s || !ino || !buf || !out_n)
        return -1;
    *out_n = 0;
    if (offset >= ino->file_size)
        return 0;
    if (offset + size > ino->file_size)
        size = (size_t)(ino->file_size - offset);

    block_buf_cap = s->block_size;
    block_buf = (uint8_t *)kmalloc(block_buf_cap);
    if (!block_buf)
        return -1;

    while (done < size) {
        size_t file_off = offset + done;
        uint32_t block_index = (uint32_t)(file_off / s->block_size);
        uint32_t block_off = (uint32_t)(file_off % s->block_size);
        size_t want = size - done;
        size_t chunk;
        size_t unc_len = 0;

        if (block_index < ino->block_count) {
            /* full / sparse data block */
            uint64_t data_pos = ino->start_block;
            uint32_t bi;
            uint32_t bsize = 0;

            for (bi = 0; bi < block_index; bi++) {
                uint32_t sz = 0;
                if (sq_read_blocklist_size(s, ino, bi, &sz) != 0) {
                    kfree(block_buf);
                    return -1;
                }
                data_pos += (sz & ~SQUASHFS_COMPRESSED_BIT_BLOCK);
            }
            if (sq_read_blocklist_size(s, ino, block_index, &bsize) != 0) {
                kfree(block_buf);
                return -1;
            }
            if (bsize == 0) {
                /* sparse hole */
                chunk = s->block_size - block_off;
                if (chunk > want)
                    chunk = want;
                memset(dst + done, 0, chunk);
                done += chunk;
                continue;
            }
            {
                size_t expected = s->block_size;
                /* last non-fragment block may be short when no fragment */
                if (ino->fragment == SQUASHFS_INVALID_FRAG &&
                    (uint64_t)(block_index + 1) * s->block_size > ino->file_size)
                    expected = (size_t)(ino->file_size - (uint64_t)block_index * s->block_size);
                if (sq_read_data_block(s, data_pos, bsize, block_buf, block_buf_cap, &unc_len, expected) != 0) {
                    kfree(block_buf);
                    return -1;
                }
            }
            if (block_off >= unc_len) {
                kfree(block_buf);
                return -1;
            }
            chunk = unc_len - block_off;
            if (chunk > want)
                chunk = want;
            memcpy(dst + done, block_buf + block_off, chunk);
            done += chunk;
        } else {
            /* fragment tail */
            struct squashfs_fragment_entry fe;
            size_t frag_unc = 0;
            size_t frag_file_off;
            size_t local_off;

            if (ino->fragment == SQUASHFS_INVALID_FRAG) {
                kfree(block_buf);
                break;
            }
            if (sq_get_fragment_entry(s, ino->fragment, &fe) != 0) {
                kfree(block_buf);
                return -1;
            }
            if (sq_read_data_block(s, fe.start_block, fe.size, block_buf, block_buf_cap, &frag_unc, 0) != 0) {
                kfree(block_buf);
                return -1;
            }
            frag_file_off = (size_t)(ino->block_count) * (size_t)s->block_size;
            if (file_off < frag_file_off) {
                kfree(block_buf);
                return -1;
            }
            local_off = (file_off - frag_file_off) + ino->frag_offset;
            if (local_off >= frag_unc) {
                kfree(block_buf);
                break;
            }
            chunk = frag_unc - local_off;
            if (chunk > want)
                chunk = want;
            /* also clamp to remaining file bytes */
            if (chunk > ino->file_size - file_off)
                chunk = (size_t)(ino->file_size - file_off);
            memcpy(dst + done, block_buf + local_off, chunk);
            done += chunk;
        }
    }

    kfree(block_buf);
    *out_n = (ssize_t)done;
    return 0;
}

static int sq_build_dir_blob(struct squashfs_sb *s, const struct squashfs_inode_info *dir,
                             uint8_t **out_blob, size_t *out_len)
{
    uint64_t block_abs;
    uint16_t offset;
    uint32_t bytes_left;
    uint8_t *blob = NULL;
    size_t cap = 0, len = 0;

    if (!s || !dir || !out_blob || !out_len)
        return -1;
    *out_blob = NULL;
    *out_len = 0;
    if (dir->file_size < 3)
        return -1;
    bytes_left = (uint32_t)dir->file_size - 3;
    block_abs = s->sb.directory_table_start + dir->start_block;
    offset = dir->offset;

    /* emit . and .. */
    {
        static const char *dots[] = { ".", ".." };
        int di;
        for (di = 0; di < 2; di++) {
            size_t namelen = strlen(dots[di]);
            size_t rec = (8 + namelen + 3) & ~3u;
            struct ext2_dir_entry de;
            if (len + rec > cap) {
                size_t ncap = cap ? cap * 2 : 512;
                uint8_t *n;
                while (ncap < len + rec)
                    ncap *= 2;
                n = (uint8_t *)kmalloc(ncap);
                if (!n) {
                    kfree(blob);
                    return -1;
                }
                if (blob)
                    memcpy(n, blob, len);
                kfree(blob);
                blob = n;
                cap = ncap;
            }
            memset(blob + len, 0, rec);
            de.inode = 1;
            de.rec_len = (uint16_t)rec;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            memcpy(blob + len, &de, 8);
            memcpy(blob + len + 8, dots[di], namelen);
            len += rec;
        }
    }

    while (bytes_left >= 12) {
        uint8_t hdr[12];
        uint32_t count, start_block, ino_base, i;
        if (sq_meta_read(s, &block_abs, &offset, hdr, 12) != 0) {
            kfree(blob);
            return -1;
        }
        bytes_left -= 12;
        count = rd32(hdr + 0) + 1;
        start_block = rd32(hdr + 4);
        ino_base = rd32(hdr + 8);
        (void)start_block;
        for (i = 0; i < count; i++) {
            uint8_t ent[8];
            uint16_t ent_off, ino_delta, ent_type, name_size;
            char namebuf[SQUASHFS_NAME_LEN + 1];
            size_t namelen, rec;
            struct ext2_dir_entry de;
            uint8_t ft = EXT2_FT_UNKNOWN;
            uint32_t ino_no;

            if (bytes_left < 8) {
                kfree(blob);
                return -1;
            }
            if (sq_meta_read(s, &block_abs, &offset, ent, 8) != 0) {
                kfree(blob);
                return -1;
            }
            bytes_left -= 8;
            ent_off = rd16(ent + 0);
            ino_delta = rd16(ent + 2);
            ent_type = rd16(ent + 4);
            name_size = rd16(ent + 6) + 1;
            (void)ent_off;
            if (name_size > SQUASHFS_NAME_LEN || bytes_left < name_size) {
                kfree(blob);
                return -1;
            }
            if (sq_meta_read(s, &block_abs, &offset, namebuf, name_size) != 0) {
                kfree(blob);
                return -1;
            }
            bytes_left -= name_size;
            namebuf[name_size] = '\0';
            namelen = name_size;
            ino_no = ino_base + (int16_t)ino_delta;

            if (ent_type == SQUASHFS_DIR_TYPE || ent_type == SQUASHFS_LDIR_TYPE)
                ft = EXT2_FT_DIR;
            else if (ent_type == SQUASHFS_SYMLINK_TYPE || ent_type == SQUASHFS_LSYMLINK_TYPE)
                ft = EXT2_FT_SYMLINK;
            else if (ent_type == SQUASHFS_REG_TYPE || ent_type == SQUASHFS_LREG_TYPE)
                ft = EXT2_FT_REG_FILE;

            rec = (8 + namelen + 3) & ~3u;
            if (len + rec > cap) {
                size_t ncap = cap ? cap * 2 : 512;
                uint8_t *n;
                while (ncap < len + rec)
                    ncap *= 2;
                n = (uint8_t *)kmalloc(ncap);
                if (!n) {
                    kfree(blob);
                    return -1;
                }
                if (blob)
                    memcpy(n, blob, len);
                kfree(blob);
                blob = n;
                cap = ncap;
            }
            memset(blob + len, 0, rec);
            de.inode = ino_no ? ino_no : 1;
            de.rec_len = (uint16_t)rec;
            de.name_len = (uint8_t)namelen;
            de.file_type = ft;
            memcpy(blob + len, &de, 8);
            memcpy(blob + len + 8, namebuf, namelen);
            len += rec;
        }
    }

    *out_blob = blob;
    *out_len = len;
    return 0;
}

static mode_t sq_mode_with_type(const struct squashfs_inode_info *ino)
{
    mode_t m = (mode_t)(ino->mode & 07777);
    switch (ino->type) {
    case SQUASHFS_DIR_TYPE:
    case SQUASHFS_LDIR_TYPE:
        return m | S_IFDIR;
    case SQUASHFS_SYMLINK_TYPE:
    case SQUASHFS_LSYMLINK_TYPE:
        return m | S_IFLNK;
    case SQUASHFS_REG_TYPE:
    case SQUASHFS_LREG_TYPE:
    default:
        return m | S_IFREG;
    }
}

static const char *sq_strip_prefix(struct squashfs_sb *s, const char *path)
{
    if (!s || !path)
        return NULL;
    if (s->mount_prefix_len == 0)
        return path;
    if (strncmp(path, s->mount_prefix, s->mount_prefix_len) != 0)
        return NULL;
    if (path[s->mount_prefix_len] == '\0')
        return "/";
    if (path[s->mount_prefix_len] != '/')
        return NULL;
    return path + s->mount_prefix_len;
}

static int squashfs_open_internal(const char *path, struct fs_file **out_file)
{
    struct squashfs_inode_info ino;
    struct squashfs_file_handle *fh;
    struct fs_file *f;
    const char *rel;
    size_t plen;
    char *pp;

    if (!g_sq || !path || !out_file)
        return -1;
    rel = sq_strip_prefix(g_sq, path);
    if (!rel)
        return -1; /* not handled */

    if (sq_path_to_inode(g_sq, rel, &ino) != 0)
        return -2; /* not found / error under our mount */

    f = (struct fs_file *)kmalloc(sizeof(*f));
    if (!f) {
        sq_inode_info_free(&ino);
        return -4;
    }
    memset(f, 0, sizeof(*f));
    plen = strlen(path) + 1;
    pp = (char *)kmalloc(plen);
    if (!pp) {
        kfree(f);
        sq_inode_info_free(&ino);
        return -4;
    }
    memcpy(pp, path, plen);
    fh = (struct squashfs_file_handle *)kmalloc(sizeof(*fh));
    if (!fh) {
        kfree(pp);
        kfree(f);
        sq_inode_info_free(&ino);
        return -4;
    }
    memset(fh, 0, sizeof(*fh));
    fh->ino = ino;

    f->path = pp;
    f->size = (off_t)ino.file_size;
    f->fs_private = (void *)g_sq;
    f->driver_private = fh;
    if (ino.type == SQUASHFS_DIR_TYPE || ino.type == SQUASHFS_LDIR_TYPE)
        f->type = FS_TYPE_DIR;
    else
        f->type = FS_TYPE_REG;

    *out_file = f;
    return 0;
}

int squashfs_open_path(const char *path, struct fs_file **out_file)
{
    /* Overlay lower: paths are absolute from squashfs root. Temporarily clear prefix. */
    size_t saved_len;
    char saved[64];
    int rc;

    if (!g_sq)
        return -1;
    saved_len = g_sq->mount_prefix_len;
    if (saved_len) {
        memcpy(saved, g_sq->mount_prefix, saved_len + 1);
        g_sq->mount_prefix[0] = '\0';
        g_sq->mount_prefix_len = 0;
    }
    rc = squashfs_open_internal(path, out_file);
    if (saved_len) {
        memcpy(g_sq->mount_prefix, saved, saved_len + 1);
        g_sq->mount_prefix_len = saved_len;
    }
    if (rc == 0 && out_file && *out_file)
        (*out_file)->refcount = 1;
    return rc == 0 ? 0 : -1;
}

static int squashfs_vfs_open(const char *path, struct fs_file **out_file)
{
    int rc = squashfs_open_internal(path, out_file);
    if (rc == -1)
        return -1; /* not our mount */
    if (rc != 0)
        return -2;
    return 0;
}

static int squashfs_vfs_create(const char *path, struct fs_file **out_file)
{
    (void)path;
    (void)out_file;
    return -1;
}

ssize_t squashfs_read_file(struct fs_file *file, void *buf, size_t size, size_t offset)
{
    struct squashfs_file_handle *fh;
    ssize_t n = 0;

    if (!file || !file->driver_private || !g_sq || !buf)
        return -1;
    fh = (struct squashfs_file_handle *)file->driver_private;

    if (fh->ino.type == SQUASHFS_DIR_TYPE || fh->ino.type == SQUASHFS_LDIR_TYPE) {
        if (!fh->dir_blob) {
            if (sq_build_dir_blob(g_sq, &fh->ino, &fh->dir_blob, &fh->dir_blob_len) != 0)
                return -1;
        }
        if (offset >= fh->dir_blob_len)
            return 0;
        if (offset + size > fh->dir_blob_len)
            size = fh->dir_blob_len - offset;
        memcpy(buf, fh->dir_blob + offset, size);
        return (ssize_t)size;
    }

    if (fh->ino.type == SQUASHFS_SYMLINK_TYPE || fh->ino.type == SQUASHFS_LSYMLINK_TYPE) {
        if (!fh->ino.symlink)
            return -1;
        if (offset >= fh->ino.file_size)
            return 0;
        if (offset + size > fh->ino.file_size)
            size = (size_t)(fh->ino.file_size - offset);
        memcpy(buf, fh->ino.symlink + offset, size);
        return (ssize_t)size;
    }

    if (sq_file_read(g_sq, &fh->ino, buf, size, offset, &n) != 0)
        return -1;
    return n;
}

static ssize_t squashfs_vfs_read(struct fs_file *file, void *buf, size_t size, size_t offset)
{
    return squashfs_read_file(file, buf, size, offset);
}

void squashfs_release_file(struct fs_file *file)
{
    struct squashfs_file_handle *fh;
    if (!file)
        return;
    fh = (struct squashfs_file_handle *)file->driver_private;
    if (fh) {
        if (fh->dir_blob)
            kfree(fh->dir_blob);
        sq_inode_info_free(&fh->ino);
        kfree(fh);
    }
    if (file->path)
        kfree((void *)file->path);
    kfree(file);
}

static void squashfs_vfs_release(struct fs_file *file)
{
    squashfs_release_file(file);
}

int squashfs_fill_stat(struct fs_file *file, struct stat *st)
{
    struct squashfs_file_handle *fh;
    if (!file || !st || !file->driver_private)
        return -1;
    fh = (struct squashfs_file_handle *)file->driver_private;
    memset(st, 0, sizeof(*st));
    st->st_mode = sq_mode_with_type(&fh->ino);
    st->st_ino = fh->ino.inode_number;
    st->st_nlink = fh->ino.nlink ? fh->ino.nlink : 1;
    st->st_uid = fh->ino.uid;
    st->st_gid = fh->ino.gid;
    st->st_size = (off_t)fh->ino.file_size;
    st->st_mtime = (time_t)fh->ino.mtime;
    st->st_ctime = st->st_mtime;
    st->st_atime = st->st_mtime;
    st->st_dev = (dev_t)2;
    return 0;
}

int squashfs_prepare_image(const void *image, size_t size)
{
    const struct squashfs_super_block *sb;
    struct squashfs_sb *s;
    int i;

    if (!squashfs_image_looks_valid(image, size))
        return -1;
    sb = (const struct squashfs_super_block *)image;
    if (rd32(&sb->s_magic) != SQUASHFS_MAGIC && sb->s_magic != SQUASHFS_MAGIC)
        return -1;
    /* Our struct is packed little-endian on x86_64; accept either. */
    if (sb->s_major != 4)
        return -1;
    if (sb->compression != ZLIB_COMPRESSION) {
        klogprintf("squashfs: unsupported compressor %u (need gzip/zlib)\n",
                   (unsigned)sb->compression);
        return -1;
    }

    if (g_sq) {
        if (g_sq->frag_index)
            kfree(g_sq->frag_index);
        for (i = 0; i < DATA_CACHE_SLOTS; i++) {
            if (g_sq->data_cache[i].data)
                kfree(g_sq->data_cache[i].data);
        }
        kfree(g_sq);
        g_sq = NULL;
    }

    s = (struct squashfs_sb *)kmalloc(sizeof(*s));
    if (!s)
        return -1;
    memset(s, 0, sizeof(*s));
    s->image = (const uint8_t *)image;
    s->size = size;
    memcpy(&s->sb, sb, sizeof(*sb));
    /* Re-read multi-byte fields safely */
    s->sb.s_magic = rd32(image);
    s->sb.inodes = rd32((const uint8_t *)image + 4);
    s->sb.mkfs_time = rd32((const uint8_t *)image + 8);
    s->sb.block_size = rd32((const uint8_t *)image + 12);
    s->sb.fragments = rd32((const uint8_t *)image + 16);
    s->sb.compression = rd16((const uint8_t *)image + 20);
    s->sb.block_log = rd16((const uint8_t *)image + 22);
    s->sb.flags = rd16((const uint8_t *)image + 24);
    s->sb.no_ids = rd16((const uint8_t *)image + 26);
    s->sb.s_major = rd16((const uint8_t *)image + 28);
    s->sb.s_minor = rd16((const uint8_t *)image + 30);
    s->sb.root_inode = rd64((const uint8_t *)image + 32);
    s->sb.bytes_used = rd64((const uint8_t *)image + 40);
    s->sb.id_table_start = rd64((const uint8_t *)image + 48);
    s->sb.xattr_id_table_start = rd64((const uint8_t *)image + 56);
    s->sb.inode_table_start = rd64((const uint8_t *)image + 64);
    s->sb.directory_table_start = rd64((const uint8_t *)image + 72);
    s->sb.fragment_table_start = rd64((const uint8_t *)image + 80);
    s->sb.lookup_table_start = rd64((const uint8_t *)image + 88);
    s->block_size = s->sb.block_size;
    if (s->block_size < 4096 || s->block_size > (1u << 20)) {
        kfree(s);
        return -1;
    }
    if (s->sb.bytes_used > size) {
        kfree(s);
        return -1;
    }
    if (sq_load_fragment_table(s) != 0) {
        if (s->frag_index)
            kfree(s->frag_index);
        kfree(s);
        return -1;
    }
    g_sq = s;
    squashfs_driver.driver_data = (void *)g_sq;
    klogprintf("squashfs: prepared image %zu bytes, block=%u inodes=%u frags=%u\n",
               size, s->block_size, s->sb.inodes, s->sb.fragments);
    return 0;
}

int squashfs_is_ready(void)
{
    return g_sq != NULL;
}

int squashfs_mount(const char *path)
{
    size_t len;
    if (!g_sq || !path || path[0] != '/')
        return -1;
    len = strlen(path);
    if (len >= sizeof(g_sq->mount_prefix))
        return -1;
    memcpy(g_sq->mount_prefix, path, len + 1);
    g_sq->mount_prefix_len = len;
    /* "/" means no strip beyond root */
    if (len == 1 && path[0] == '/') {
        g_sq->mount_prefix[0] = '\0';
        g_sq->mount_prefix_len = 0;
    }
    return fs_mount(path, &squashfs_driver);
}

struct fs_driver *squashfs_get_driver(void)
{
    return &squashfs_driver;
}

int squashfs_register(void)
{
    squashfs_ops.name = "squashfs";
    squashfs_ops.create = squashfs_vfs_create;
    squashfs_ops.mkdir = NULL;
    squashfs_ops.open = squashfs_vfs_open;
    squashfs_ops.read = squashfs_vfs_read;
    squashfs_ops.write = NULL;
    squashfs_ops.release = squashfs_vfs_release;
    squashfs_ops.chmod = NULL;
    squashfs_ops.link = NULL;
    squashfs_ops.rename = NULL;
    squashfs_ops.unlink = NULL;
    squashfs_driver.ops = &squashfs_ops;
    squashfs_driver.driver_data = (void *)g_sq;
    return fs_register_driver(&squashfs_driver);
}

int squashfs_unregister(void)
{
    return fs_unregister_driver(&squashfs_driver);
}
