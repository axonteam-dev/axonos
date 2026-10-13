#!/usr/bin/env python3
"""Exercise real metadata slice/cache code and measure copied bytes, not timings."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/squashfs.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SQUASHFS_METADATA_SIZE 8192
#define SQUASHFS_COMPRESSED_BIT 0x8000u
#define META_CACHE_SLOTS 16
#define DIR_CACHE_SLOTS 256
#define SQUASHFS_NAME_LEN 256
#define SQUASHFS_DIR_TYPE 1
#define SQUASHFS_LDIR_TYPE 8
struct meta_cache_ent {
    uint64_t abs_pos; uint8_t data[8192]; size_t len; int valid;
};
struct dir_cache_ent {
    uint32_t parent_inode; uint64_t inode_ref; uint16_t type; int valid; char name[257];
};
struct squashfs_sb {
    const uint8_t *image; size_t size;
    struct meta_cache_ent meta_cache[16]; int meta_cache_next;
    struct dir_cache_ent dir_cache[256];
};
struct squashfs_inode_info { uint32_t inode_number; uint16_t type; };
typedef struct { int root; } mm_dm_ctx_t;
static int root = 1, guards;
static size_t copied;
static mm_dm_ctx_t mm_enter_direct_map(void) {
    mm_dm_ctx_t ctx = {root}; root = 0; guards++; return ctx;
}
static void mm_leave_direct_map(mm_dm_ctx_t ctx) { assert(root == 0); root = ctx.root; }
static void *tracked_memcpy(void *to, const void *from, size_t n) {
    assert(root == 0); copied += n; return memcpy(to, from, n);
}
#define memcpy tracked_memcpy
static int zlib_inflate(void *out, size_t cap, size_t *got, const void *in, size_t n) {
    (void)out; (void)cap; (void)got; (void)in; (void)n; return -1;
}
''' + function("static uint16_t rd16(") + function("static int sq_in_range(") + function("static int sq_read_metadata_block_direct(") + function("static int sq_meta_read_direct(") + function("static int sq_meta_read(") + r'''
static int lookups;
static int sq_lookup_dir_uncached(struct squashfs_sb *s, const struct squashfs_inode_info *dir,
                                  const char *name, uint64_t *ref, uint16_t *type) {
    (void)s; assert(root == 0); lookups++;
    if (strcmp(name, "missing") == 0) return -1;
    *ref = ((uint64_t)dir->inode_number << 16) | 42; *type = 2; return 0;
}
''' + function("static int sq_lookup_dir(") + r'''
int main(void) {
    uint8_t image[2 * (8192 + 2)];
    for (unsigned block = 0; block < 2; block++) {
        unsigned start = block * 8194; image[start] = 0; image[start + 1] = 0xa0;
        for (unsigned i = 0; i < 8192; i++) image[start + 2 + i] = (uint8_t)(i + block);
    }
    struct squashfs_sb *s = calloc(1, sizeof(*s)); assert(s);
    s->image = image; s->size = sizeof(image);
    uint64_t block = 0; uint16_t off = 0; uint8_t out[64];
    assert(sq_meta_read(s, &block, &off, out, 8) == 0 && root == 1);
    copied = 0;
    for (unsigned i = 0; i < 1000; i++) {
        assert(sq_meta_read(s, &block, &off, out, 8) == 0);
        for (unsigned j = 0; j < 8; j++) assert(out[j] == (uint8_t)(8 + i * 8 + j));
    }
    assert(copied == 8000); /* previous cache-hit path copied ~8.2 MB */
    block = 0; off = 8180;
    assert(sq_meta_read(s, &block, &off, out, 50) == 0);
    assert(block == 8194 && off == 38);
    for (unsigned i = 0; i < 12; i++) assert(out[i] == (uint8_t)(8180 + i));
    for (unsigned i = 0; i < 38; i++) assert(out[12 + i] == (uint8_t)(i + 1));
    copied = 0; block = 0; off = 8180; int before = guards;
    assert(sq_meta_read(s, &block, &off, out, 50) == 0);
    assert(copied == 50 && guards == before + 1 && root == 1);
    block = 0; off = 8180; copied = 0;
    assert(sq_meta_read(s, &block, &off, NULL, 50) == 0 && copied == 0);
    block = sizeof(image); off = 0;
    assert(sq_meta_read(s, &block, &off, out, 1) == -1 && root == 1);
    struct squashfs_inode_info dir = {.inode_number = 3, .type = 1};
    uint64_t ref; uint16_t type;
    for (unsigned i = 0; i < 1000; i++)
        assert(sq_lookup_dir(s, &dir, "busybox", &ref, &type) == 0 && type == 2 && root == 1);
    assert(lookups == 1);
    dir.inode_number = 4;
    assert(sq_lookup_dir(s, &dir, "busybox", &ref, NULL) == 0 && ref == ((4ULL << 16) | 42));
    assert(lookups == 2);
    assert(sq_lookup_dir(s, &dir, "missing", &ref, NULL) == -1);
    assert(sq_lookup_dir(s, &dir, "missing", &ref, NULL) == -1);
    assert(lookups == 4 && root == 1); /* failures must not be cached */
    free(s);
    puts("PASS: 1000 hot metadata reads copy 8000 bytes, not 8MB; repeated dir lookups scan once");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sq-meta-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
