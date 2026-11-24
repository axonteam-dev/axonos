#!/usr/bin/env python3
"""Write an actual ext2 image using the kernel driver, then run e2fsck."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/ext2.c").read_text()
vfs = (root / "fs/fs.c").read_text()
assert 'return ext2_ftruncate(file, length);' in vfs
source = "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
header = (root / "inc/ext2.h").read_text()
header = header[header.index("struct ext2_super_block {"):header.index("int ext2_mount_from_memory(")]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
''' + header + r'''
#define FS_TYPE_DIR 1
#define FS_TYPE_REG 2
struct fs_file { const char *path; size_t size; int type, inode_kind_known, is_symlink;
    void *fs_private, *driver_private; };
struct fs_driver_ops {
    const char *name;
    int (*create)(const char *, struct fs_file **);
    int (*mkdir)(const char *);
    int (*open)(const char *, struct fs_file **);
    ssize_t (*read)(struct fs_file *, void *, size_t, size_t);
    ssize_t (*write)(struct fs_file *, const void *, size_t, size_t);
    void (*release)(struct fs_file *);
    int (*chmod)(const char *, mode_t);
    int (*link)(const char *, const char *);
};
struct fs_driver { struct fs_driver_ops *ops; void *driver_data; };
typedef struct { uint32_t euid, egid; } thread_t;
static thread_t *current_user;
static thread_t *thread_get_current_user(void) { return current_user; }
static thread_t *thread_current(void) { return current_user; }
static unsigned char *disk; static size_t disk_size;
static int fail_write_after = -1;
static int disk_read_sectors(int id, uint32_t lba, void *out, uint32_t n) {
    (void)id; uint64_t off = (uint64_t)lba * 512, len = (uint64_t)n * 512;
    if (off + len > disk_size) return -1;
    memcpy(out, disk + off, len); return 0;
}
static int disk_write_sectors(int id, uint32_t lba, const void *in, uint32_t n) {
    (void)id; uint64_t off = (uint64_t)lba * 512, len = (uint64_t)n * 512;
    if (fail_write_after > 0 && --fail_write_after == 0) {
        fail_write_after = -1; return -1;
    }
    if (off + len > disk_size) return -1;
    memcpy(disk + off, in, len); return 0;
}
static int fs_get_matching_mount_prefix(const char *p, char *out, size_t n) {
    (void)p; if (n < 2) return -1; strcpy(out, "/"); return 0;
}
static int fs_register_driver(struct fs_driver *d) { (void)d; return 0; }
static int fs_unregister_driver(struct fs_driver *d) { (void)d; return 0; }
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
#define klogprintf(...) ((void)0)
''' + source + r'''
int main(int argc, char **argv) {
    (void)e2_le16;
    if (argc != 3) return 2;
    FILE *f = fopen(argv[1], "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long len = ftell(f); assert(len > 0); rewind(f);
    disk_size = (size_t)len; disk = malloc(disk_size); assert(disk);
    assert(fread(disk, 1, disk_size, f) == disk_size); fclose(f);
    assert(ext2_register() == 0);
    int memory_mount = argv[2][0] == 'm';
    assert((memory_mount ? ext2_mount_from_memory(disk, disk_size) :
            ext2_probe_and_mount_geom(0, 0, (uint32_t)(disk_size / 512))) == 0);
    struct fs_file *file = NULL;
    assert(ext2_create("/axon-test", &file) == 0 && file);
    struct fs_file *duplicate = NULL;
    assert(ext2_create("/axon-test", &duplicate) != 0 && !duplicate);
    assert(ext2_mkdir("/axon-test") == -4);
    assert(ext2_write(file, "hello ext2\n", 11, 0) == 11);
    assert(ext2_chmod("/axon-test", 0750) == 0);
    {
        struct stat st;
        assert(ext2_fill_stat(file, &st) == 0 && (st.st_mode & 07777) == 0750);
        assert((st.st_mode & 0170000) == S_IFREG);
        assert(ext2_fchmod_file(file, 0640) == 0);
        assert(ext2_fill_stat(file, &st) == 0 && (st.st_mode & 07777) == 0640);
        assert(ext2_fchmod_file(file, 06750) == 0);
        assert(ext2_fchown_file(file, 1001, 1002) == 0);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 &&
               st.st_gid == 1002 && (st.st_mode & 07777) == 0750);
        assert(ext2_fchown_file(file, UINT32_MAX, 65536) == 0);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 && st.st_gid == 65536);
    }
    ext2_release(file);
    file = NULL; assert(ext2_open("/axon-test", &file) == 0 && file);
    char out[12] = {0};
    assert(ext2_read(file, out, 11, 0) == 11 && !memcmp(out, "hello ext2\n", 11));
    ext2_release(file);
    assert(ext2_mkdir("/axon-dir") == 0);
    assert(ext2_mkdir("/axon-dir") == -4);
    /* A real Debian dpkg/info directory is far larger than 12 direct blocks.
     * Long unique names force indirect directory growth on 1K and 4K images. */
    for (unsigned i = 0; i < 220; i++) {
        char path[256];
        int prefix = snprintf(path, sizeof path, "/axon-dir/bulk-%04u-", i);
        assert(prefix > 0 && prefix + 220 < (int)sizeof path);
        memset(path + prefix, 'x', 220);
        path[prefix + 220] = 0;
        struct fs_file *bulk = NULL;
        assert(ext2_create(path, &bulk) == 0 && bulk);
        ext2_release(bulk);
    }
    {
        struct fs_file *dir = NULL;
        assert(ext2_open("/axon-dir", &dir) == 0);
        assert(dir->size > 12 * g_ext2->block_size);
        ext2_release(dir);
    }
    assert(ext2_link("/axon-test", "/axon-dir/hard") == 0);
    assert(ext2_link("/axon-test", "/axon-dir/hard") == -17);
    assert(ext2_link("/axon-dir", "/hard-dir") == -1);
    assert(ext2_link("/missing", "/missing-hard") == -2);
    {
        struct stat original, linked;
        struct fs_file *a = NULL, *b = NULL;
        assert(ext2_open("/axon-test", &a) == 0);
        assert(ext2_open("/axon-dir/hard", &b) == 0);
        assert(ext2_fill_stat(a, &original) == 0 && ext2_fill_stat(b, &linked) == 0);
        assert(original.st_ino == linked.st_ino && original.st_nlink == 2);
        assert(ext2_write(b, "H", 1, 0) == 1);
        char ch = 0;
        assert(ext2_read(a, &ch, 1, 0) == 1 && ch == 'H');
        ext2_release(a); ext2_release(b);
    }
    {
        thread_t user = {1001, 1002};
        struct stat st;
        current_user = &user;
        file = NULL; assert(ext2_create("/axon-dir/owned", &file) == 0 && file);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 && st.st_gid == 1002);
        ext2_release(file);
        user.euid = 70001; user.egid = 80002;
        file = NULL; assert(ext2_create("/axon-dir/high-owner", &file) == 0 && file);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 70001 && st.st_gid == 80002);
        ext2_release(file);
        user.euid = 1001; user.egid = 1002;
        assert(ext2_chmod("/axon-dir", 02755) == 0);
        file = NULL; assert(ext2_create("/axon-dir/inherited", &file) == 0 && file);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 && st.st_gid == 0);
        ext2_release(file);
        assert(ext2_symlink("/axon-dir/inherited-link", "owned", 1001, 1002) == 0);
        file = NULL; assert(ext2_open("/axon-dir/inherited-link", &file) == 0 && file);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 && st.st_gid == 0);
        ext2_release(file);
        assert(ext2_mkdir("/axon-dir/subdir") == 0);
        file = NULL; assert(ext2_open("/axon-dir/subdir", &file) == 0 && file);
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1001 &&
               st.st_gid == 0 && (st.st_mode & 02000));
        ext2_release(file);
        assert(ext2_chmod("/axon-dir", 0755) == 0);
        current_user = NULL;
    }
    if (!memory_mount) {
        char failed_target[100]; memset(failed_target, 'x', sizeof failed_target - 1);
        failed_target[sizeof failed_target - 1] = 0;
        uint32_t free_inodes = g_ext2->sb.s_free_inodes_count;
        uint32_t free_blocks = g_ext2->sb.s_free_blocks_count;
        fail_write_after = 5; /* inode bitmap+group, block bitmap+group, data */
        assert(ext2_symlink("/axon-dir/failed-link", failed_target, 0, 0) == -5);
        assert(g_ext2->sb.s_free_inodes_count == free_inodes);
        assert(g_ext2->sb.s_free_blocks_count == free_blocks);
        struct fs_file *missing = NULL;
        assert(ext2_open("/axon-dir/failed-link", &missing) != 0);
    }
    assert(ext2_symlink("/axon-dir/link", "large", 1000, 1000) == 0);
    assert(ext2_symlink("/axon-dir/link", "other", 0, 0) == -17);
    assert(ext2_chmod("/axon-dir/link", 0600) != 0);
    {
        char target[4097], out_target[4096];
        size_t target_len = g_ext2->block_size - 1;
        memset(target, 'a', target_len); target[target_len] = 0;
        assert(ext2_symlink("/axon-dir/long-link", target, 0, 0) == 0);
        struct fs_file *link = NULL;
        assert(ext2_open("/axon-dir/long-link", &link) == 0 && link);
        assert(ext2_read(link, out_target, target_len, 0) == (ssize_t)target_len);
        assert(!memcmp(target, out_target, target_len));
        ext2_release(link);
        target[target_len] = 'a'; target[target_len + 1] = 0;
        assert(ext2_symlink("/axon-dir/too-long-link", target, 0, 0) == -36);
        assert(ext2_symlink("/axon-dir/uid-link", "x", 65536, 70000) == 0);
        link = NULL; assert(ext2_open("/axon-dir/uid-link", &link) == 0 && link);
        struct stat owner_stat;
        assert(ext2_fill_stat(link, &owner_stat) == 0 &&
               owner_stat.st_uid == 65536 && owner_stat.st_gid == 70000);
        ext2_release(link);
    }
    file = NULL; assert(ext2_open("/axon-dir/link", &file) == 0 && file);
    assert(file->inode_kind_known && file->is_symlink);
    {
        char target[6] = {0};
        struct stat st;
        assert(ext2_read(file, target, 5, 0) == 5 && !memcmp(target, "large", 5));
        assert(ext2_fill_stat(file, &st) == 0 && st.st_uid == 1000 && st.st_gid == 1000);
    }
    ext2_release(file);
    file = NULL; assert(ext2_create("/axon-dir/large", &file) == 0 && file);
    size_t data_len = 400000;
    char *data = malloc(data_len); assert(data); memset(data, 'A', data_len);
    assert(ext2_write(file, data, data_len, 0) == (ssize_t)data_len);
    free(data);
    ext2_release(file);
    file = NULL; assert(ext2_open("/axon-dir/large", &file) == 0 && file);
    char check[512];
    assert(ext2_read(file, check, sizeof check, 300000) == sizeof check);
    for (size_t i = 0; i < sizeof check; i++) assert(check[i] == 'A');
    ext2_release(file);
    {
        struct ext2_inode dir_inode; uint32_t dir_ino;
        assert(e2_walk(g_ext2, "/axon-dir", &dir_ino, &dir_inode) == 0);
        uint32_t block = e2_get_block(g_ext2, &dir_inode, 0);
        size_t pos = (size_t)block * g_ext2->block_size;
        unsigned char old_len[2] = {disk[pos + 4], disk[pos + 5]};
        uint32_t free_inodes = g_ext2->sb.s_free_inodes_count;
        disk[pos + 4] = disk[pos + 5] = 0;
        file = NULL;
        assert(ext2_create("/axon-dir/no-create", &file) != 0 && !file);
        assert(g_ext2->sb.s_free_inodes_count == free_inodes);
        disk[pos + 4] = old_len[0]; disk[pos + 5] = old_len[1];
    }
    for (int i = 0; i < 40; i++) {
        char path[256];
        memcpy(path, "/axon-dir/", 10);
        memset(path + 10, 'a' + i % 26, 220);
        snprintf(path + 230, sizeof path - 230, "-%03d", i);
        file = NULL; assert(ext2_create(path, &file) == 0 && file);
        ext2_release(file);
    }
    file = NULL; assert(ext2_create("/axon-dir/sparse", &file) == 0 && file);
    assert(ext2_write(file, "abc", 3, 0) == 3);
    assert(ext2_ftruncate(file, 8192) == 0);
    memset(check, 1, sizeof check);
    assert(ext2_read(file, check, sizeof check, 3) == sizeof check);
    for (size_t i = 0; i < sizeof check; i++) assert(check[i] == 0);
    assert(ext2_ftruncate(file, 0) == 0);
    ext2_release(file);
    file = NULL; assert(ext2_create("/axon-dir/empty-sparse", &file) == 0 && file);
    assert(ext2_ftruncate(file, 8192) == 0);
    assert(ext2_ftruncate(file, 17) == 0);
    assert(file->size == 17);
    ext2_release(file);
    file = NULL; assert(ext2_create("/axon-dir/direct", &file) == 0 && file);
    {
        char direct[8192]; memset(direct, 'd', sizeof direct);
        assert(ext2_write(file, direct, sizeof direct, 0) == sizeof direct);
        assert(ext2_ftruncate(file, 0) == 0);
        assert(ext2_write(file, "new", 3, 0) == 3);
    }
    ext2_release(file);
    ext2_unmount_cleanup();
    assert((memory_mount ? ext2_mount_from_memory(disk, disk_size) :
            ext2_probe_and_mount_geom(0, 0, (uint32_t)(disk_size / 512))) == 0);
    file = NULL; assert(ext2_open("/axon-dir/large", &file) == 0 && file);
    assert(ext2_read(file, check, sizeof check, 300000) == sizeof check);
    for (size_t i = 0; i < sizeof check; i++) assert(check[i] == 'A');
    {
        struct ext2_file_handle *h = file->driver_private;
        struct ext2_inode saved = h->inode, corrupt = saved;
        uint32_t free_before = g_ext2->sb.s_free_blocks_count;
        corrupt.i_block[1] = corrupt.i_block[0];
        assert(e2_write_inode(g_ext2, h->inode_no, &corrupt) == 0);
        assert(ext2_ftruncate(file, 0) == -5);
        assert(g_ext2->sb.s_free_blocks_count == free_before);
        assert(e2_write_inode(g_ext2, h->inode_no, &saved) == 0);
    }
    assert(ext2_ftruncate(file, 0) == 0);
    assert(file->size == 0);
    ext2_release(file); ext2_unmount_cleanup();
    f = fopen(argv[1], "wb"); assert(f);
    assert(fwrite(disk, 1, disk_size, f) == disk_size); fclose(f); free(disk);
    puts("PASS: kernel ext2 driver created, wrote and reopened a real image");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-write-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    for block_size in (1024, 4096):
        for mode in ("disk", "memory"):
            image = path / f"ext2-{block_size}-{mode}.img"
            with image.open("wb") as f:
                f.truncate(32 * 1024 * 1024)
            subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2",
                            "-b", str(block_size), str(image)], check=True)
            subprocess.run([str(path / "test"), str(image), mode], check=True)
            subprocess.run(["e2fsck", "-fn", str(image)], check=True)
            info = subprocess.run(["debugfs", "-R", "stat /axon-dir/high-owner",
                                   str(image)], check=True, capture_output=True, text=True).stdout
            assert re.search(r"User:\s*70001\s+Group:\s*80002", info), info
            print(f"PASS: e2fsck accepts {mode} image, {block_size}-byte blocks")
