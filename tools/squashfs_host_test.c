/*
 * Host-side smoke test for SquashFS reader logic.
 * Build: gcc -O2 -Iinc -DHOST_SQUASHFS_TEST -o build/squashfs_host_test \
 *          tools/squashfs_host_test.c
 *
 * This is a minimal reimplementation of path lookup/read using the same
 * on-disk rules, to validate the initfs.squashfs image independently.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define SQUASHFS_METADATA_SIZE 8192
#define SQUASHFS_COMPRESSED_BIT 0x8000u
#define SQUASHFS_COMPRESSED_BIT_BLOCK (1u << 24)
#define SQUASHFS_INVALID_FRAG 0xffffffffu
#define SQUASHFS_DIR_TYPE 1
#define SQUASHFS_REG_TYPE 2
#define SQUASHFS_SYMLINK_TYPE 3
#define SQUASHFS_LDIR_TYPE 8
#define SQUASHFS_LREG_TYPE 9
#define SQUASHFS_LSYMLINK_TYPE 10

static uint16_t rd16(const void *p) {
    const uint8_t *b = p;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}
static uint32_t rd32(const void *p) {
    const uint8_t *b = p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static uint64_t rd64(const void *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32((const uint8_t *)p + 4) << 32);
}

struct sb {
    const uint8_t *img;
    size_t size;
    uint32_t block_size;
    uint32_t fragments;
    uint16_t compression;
    uint64_t root_inode;
    uint64_t inode_table_start;
    uint64_t directory_table_start;
    uint64_t fragment_table_start;
    uint64_t *frag_index;
    uint32_t frag_index_count;
};

static int inflate_zlib(void *out, size_t out_cap, size_t *out_len, const void *in, size_t in_len) {
    uLongf dest = (uLongf)out_cap;
    int rc = uncompress((Bytef *)out, &dest, (const Bytef *)in, (uLong)in_len);
    if (rc != Z_OK)
        return -1;
    *out_len = (size_t)dest;
    return 0;
}

static int read_meta(struct sb *s, uint64_t abs, uint8_t *out, size_t *out_len, uint64_t *next) {
    uint16_t h, csize;
    int compressed;
    if (abs + 2 > s->size)
        return -1;
    h = rd16(s->img + abs);
    compressed = !(h & SQUASHFS_COMPRESSED_BIT);
    csize = h & (uint16_t)~SQUASHFS_COMPRESSED_BIT;
    if (!csize || csize > SQUASHFS_METADATA_SIZE || abs + 2 + csize > s->size)
        return -1;
    if (!compressed) {
        memcpy(out, s->img + abs + 2, csize);
        *out_len = csize;
    } else if (inflate_zlib(out, SQUASHFS_METADATA_SIZE, out_len, s->img + abs + 2, csize) != 0)
        return -1;
    if (next)
        *next = abs + 2 + csize;
    return 0;
}

static int meta_read(struct sb *s, uint64_t *block_abs, uint16_t *offset, void *dst, size_t want) {
    uint8_t *out = dst;
    size_t done = 0;
    while (done < want) {
        uint8_t blk[SQUASHFS_METADATA_SIZE];
        size_t blen = 0;
        uint64_t next = 0;
        size_t avail, take;
        if (read_meta(s, *block_abs, blk, &blen, &next) != 0)
            return -1;
        if (*offset > blen)
            return -1;
        avail = blen - *offset;
        take = want - done;
        if (take > avail)
            take = avail;
        if (take && out)
            memcpy(out + done, blk + *offset, take);
        done += take;
        *offset = (uint16_t)(*offset + take);
        if (*offset >= blen && done < want) {
            *block_abs = next;
            *offset = 0;
        }
    }
    return 0;
}

struct ino {
    uint16_t type, mode;
    uint32_t inode_number, nlink, fragment, frag_offset;
    uint64_t file_size, start_block;
    uint16_t offset;
    uint32_t block_count;
    uint64_t block_list_abs;
    char *symlink;
};

static int read_inode(struct sb *s, uint64_t iref, struct ino *out) {
    uint64_t block_abs = s->inode_table_start + (iref >> 16);
    uint16_t offset = (uint16_t)(iref & 0xffff);
    uint8_t hdr[16];
    memset(out, 0, sizeof(*out));
    out->fragment = SQUASHFS_INVALID_FRAG;
    if (meta_read(s, &block_abs, &offset, hdr, 16) != 0)
        return -1;
    out->type = rd16(hdr);
    out->mode = rd16(hdr + 2);
    out->inode_number = rd32(hdr + 12);
    if (out->type == SQUASHFS_DIR_TYPE) {
        uint8_t b[16];
        if (meta_read(s, &block_abs, &offset, b, 16) != 0)
            return -1;
        out->start_block = rd32(b);
        out->nlink = rd32(b + 4);
        out->file_size = rd16(b + 8);
        out->offset = rd16(b + 10);
        return 0;
    }
    if (out->type == SQUASHFS_LDIR_TYPE) {
        uint8_t b[24];
        uint16_t i_count, di;
        if (meta_read(s, &block_abs, &offset, b, 24) != 0)
            return -1;
        out->nlink = rd32(b);
        out->file_size = rd32(b + 4);
        out->start_block = rd32(b + 8);
        i_count = rd16(b + 16);
        out->offset = rd16(b + 18);
        for (di = 0; di < i_count; di++) {
            uint8_t idx[12];
            uint32_t nsz;
            if (meta_read(s, &block_abs, &offset, idx, 12) != 0)
                return -1;
            nsz = rd32(idx + 8) + 1;
            if (meta_read(s, &block_abs, &offset, NULL, nsz) != 0)
                return -1;
        }
        return 0;
    }
    if (out->type == SQUASHFS_REG_TYPE) {
        uint8_t b[16];
        if (meta_read(s, &block_abs, &offset, b, 16) != 0)
            return -1;
        out->start_block = rd32(b);
        out->fragment = rd32(b + 4);
        out->frag_offset = rd32(b + 8);
        out->file_size = rd32(b + 12);
        out->block_count = (out->fragment == SQUASHFS_INVALID_FRAG)
                               ? (uint32_t)((out->file_size + s->block_size - 1) / s->block_size)
                               : (uint32_t)(out->file_size / s->block_size);
        out->block_list_abs = (block_abs << 16) | offset;
        if (out->block_count && meta_read(s, &block_abs, &offset, NULL, out->block_count * 4) != 0)
            return -1;
        return 0;
    }
    if (out->type == SQUASHFS_LREG_TYPE) {
        uint8_t b[40];
        if (meta_read(s, &block_abs, &offset, b, 40) != 0)
            return -1;
        out->start_block = rd64(b);
        out->file_size = rd64(b + 8);
        out->nlink = rd32(b + 24);
        out->fragment = rd32(b + 28);
        out->frag_offset = rd32(b + 32);
        out->block_count = (out->fragment == SQUASHFS_INVALID_FRAG)
                               ? (uint32_t)((out->file_size + s->block_size - 1) / s->block_size)
                               : (uint32_t)(out->file_size / s->block_size);
        out->block_list_abs = (block_abs << 16) | offset;
        if (out->block_count && meta_read(s, &block_abs, &offset, NULL, out->block_count * 4) != 0)
            return -1;
        return 0;
    }
    if (out->type == SQUASHFS_SYMLINK_TYPE || out->type == SQUASHFS_LSYMLINK_TYPE) {
        uint8_t b[8];
        uint32_t slen;
        if (meta_read(s, &block_abs, &offset, b, 8) != 0)
            return -1;
        out->nlink = rd32(b);
        slen = rd32(b + 4);
        out->file_size = slen;
        out->symlink = calloc(1, slen + 1);
        if (!out->symlink)
            return -1;
        if (slen && meta_read(s, &block_abs, &offset, out->symlink, slen) != 0)
            return -1;
        if (out->type == SQUASHFS_LSYMLINK_TYPE && meta_read(s, &block_abs, &offset, NULL, 4) != 0)
            return -1;
        return 0;
    }
    return 0;
}

static int lookup(struct sb *s, const struct ino *dir, const char *name, uint64_t *iref) {
    uint64_t block_abs = s->directory_table_start + dir->start_block;
    uint16_t offset = dir->offset;
    uint32_t left;
    if (dir->file_size < 3)
        return -1;
    left = (uint32_t)dir->file_size - 3;
    while (left >= 12) {
        uint8_t hdr[12];
        uint32_t count, start_block, i;
        if (meta_read(s, &block_abs, &offset, hdr, 12) != 0)
            return -1;
        left -= 12;
        count = rd32(hdr) + 1;
        start_block = rd32(hdr + 4);
        for (i = 0; i < count; i++) {
            uint8_t ent[8];
            uint16_t ent_off, name_size;
            char nb[256];
            if (left < 8 || meta_read(s, &block_abs, &offset, ent, 8) != 0)
                return -1;
            left -= 8;
            ent_off = rd16(ent);
            name_size = rd16(ent + 6) + 1;
            if (name_size > 255 || left < name_size || meta_read(s, &block_abs, &offset, nb, name_size) != 0)
                return -1;
            left -= name_size;
            nb[name_size] = 0;
            if (strcmp(nb, name) == 0) {
                *iref = ((uint64_t)start_block << 16) | ent_off;
                return 0;
            }
        }
    }
    return -1;
}

static int path_inode(struct sb *s, const char *path, struct ino *out) {
    struct ino cur;
    const char *p = path;
    if (read_inode(s, s->root_inode, &cur) != 0)
        return -1;
    while (*p == '/')
        p++;
    if (!*p) {
        *out = cur;
        return 0;
    }
    while (*p) {
        char comp[256];
        size_t n = 0;
        uint64_t next = 0;
        struct ino nxt;
        while (p[n] && p[n] != '/' && n < 255)
            n++;
        memcpy(comp, p, n);
        comp[n] = 0;
        p += n;
        while (*p == '/')
            p++;
        if (lookup(s, &cur, comp, &next) != 0) {
            free(cur.symlink);
            return -1;
        }
        free(cur.symlink);
        if (read_inode(s, next, &nxt) != 0)
            return -1;
        cur = nxt;
    }
    *out = cur;
    return 0;
}

int main(int argc, char **argv) {
    const char *img_path = argc > 1 ? argv[1] : "iso/boot/initfs.squashfs";
    FILE *f;
    uint8_t *img;
    long sz;
    struct sb s;
    struct ino ino;
    const char *paths[] = { "/", "/bin", "/bin/busybox", "/bin/sh", "/linuxrc", "/init", "/sbin/init", NULL };
    int i, fails = 0;

    f = fopen(img_path, "rb");
    if (!f) {
        perror(img_path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    img = malloc((size_t)sz);
    if (!img || fread(img, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "read fail\n");
        return 1;
    }
    fclose(f);
    if (memcmp(img, "hsqs", 4) != 0) {
        fprintf(stderr, "bad magic\n");
        return 1;
    }
    memset(&s, 0, sizeof(s));
    s.img = img;
    s.size = (size_t)sz;
    s.block_size = rd32(img + 12);
    s.fragments = rd32(img + 16);
    s.compression = rd16(img + 20);
    s.root_inode = rd64(img + 32);
    s.inode_table_start = rd64(img + 64);
    s.directory_table_start = rd64(img + 72);
    s.fragment_table_start = rd64(img + 80);
    printf("squashfs: size=%ld block=%u comp=%u frags=%u\n", sz, s.block_size, s.compression, s.fragments);

    for (i = 0; paths[i]; i++) {
        if (path_inode(&s, paths[i], &ino) != 0) {
            printf("FAIL lookup %s\n", paths[i]);
            fails++;
            continue;
        }
        printf("OK  %-16s type=%u mode=%o size=%llu sym=%s\n", paths[i], ino.type, ino.mode,
               (unsigned long long)ino.file_size, ino.symlink ? ino.symlink : "-");
        free(ino.symlink);
    }
    free(img);
    return fails ? 2 : 0;
}
