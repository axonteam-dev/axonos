#!/usr/bin/env python3
"""Run the actual syscall removal helper with a mocked VFS on the host."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static uint64_t syscall_remove_path(")
helper = source[start:source.index("\n}\n", start) + 3]
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
struct fs_file { int dummy; };
struct fs_driver_ops { const char *name; };
struct fs_driver { struct fs_driver_ops *ops; };
struct ext2_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len, file_type;
};
static mode_t mode;
static int scenario, unlinks, opens, closes, cgroup_removes;
static struct fs_file file;
static struct fs_driver_ops cgroup_ops = {"cgroup2"};
static struct fs_driver cgroup_driver = {&cgroup_ops};
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int vfs_lstat(const char *p, struct stat *st) {
    (void)p; st->st_mode = mode; return scenario == 4 ? -1 : 0;
}
static void *fs_get_mount_driver_exact(const char *p) {
    (void)p; return scenario == 5 ? &file : NULL;
}
static struct fs_driver *fs_get_mount_driver(const char *p) {
    (void)p; return scenario == 7 || scenario == 8 ? &cgroup_driver : NULL;
}
static int cgroupfs_rmdir(const char *p) {
    (void)p; cgroup_removes++; return scenario == 7 ? 0 : -ENOTEMPTY;
}
static struct fs_file *fs_open(const char *p) { (void)p; opens++; return &file; }
static void fs_file_free(struct fs_file *f) { (void)f; closes++; }
static int fs_unlink(const char *p) { (void)p; unlinks++; return 0; }
static ssize_t fs_read(struct fs_file *f, void *buf, size_t size, size_t pos) {
    (void)f; (void)size;
    if (scenario == 3) return -1;
    if (pos && scenario != 2) return 0;
    if (pos > 24) return 0;
    unsigned char *b = buf;
    memset(b, 0, 36);
    struct ext2_dir_entry dot = {1, 12, 1, 2}, dotdot = {1, 12, 2, 2};
    memcpy(b, &dot, 8); b[8] = '.';
    memcpy(b + 12, &dotdot, 8); b[20] = '.'; b[21] = '.';
    if (scenario == 6) { b[4] = 0; return 24; }
    if (scenario == 1 || (scenario == 2 && pos == 24)) {
        struct ext2_dir_entry child = {2, 12, 2, 1};
        memcpy(b + 24, &child, 8); memcpy(b + 32, "sh", 2);
        return 36;
    }
    return 24;
}
'''
tests = r'''
static void check(mode_t m, int s, int remove_dir, int error) {
    mode = m; scenario = s; unlinks = opens = closes = 0;
    assert(syscall_remove_path("/usr/bin", remove_dir) == ret_err(error));
    assert(unlinks == (error == 0));
    assert(opens == closes);
}
int main(void) {
    check(S_IFDIR, 1, 1, ENOTEMPTY); /* apk unlinkat(AT_REMOVEDIR) */
    check(S_IFDIR, 2, 1, ENOTEMPTY); /* child after first read */
    check(S_IFDIR, 0, 1, 0);
    check(S_IFDIR, 0, 0, EISDIR);
    check(S_IFLNK, 0, 1, ENOTDIR);
    check(S_IFLNK, 0, 0, 0);
    check(S_IFREG, 0, 1, ENOTDIR);
    check(S_IFREG, 0, 0, 0);
    check(S_IFDIR, 3, 1, EIO);
    check(S_IFDIR, 4, 1, ENOENT);
    check(S_IFDIR, 5, 1, EBUSY);
    check(S_IFDIR, 6, 1, EIO);
    mode = S_IFDIR; scenario = 7; cgroup_removes = unlinks = 0;
    assert(syscall_remove_path("/sys/fs/cgroup/system.slice", 1) == 0);
    assert(cgroup_removes == 1 && unlinks == 0);
    scenario = 8;
    assert(syscall_remove_path("/sys/fs/cgroup/system.slice", 1) == ret_err(ENOTEMPTY));
    assert(cgroup_removes == 2 && unlinks == 0);
    assert(syscall_remove_path("/", 1) == ret_err(EBUSY));
    assert(syscall_remove_path("", 0) == ret_err(ENOENT));
    puts("PASS: unlink/rmdir semantics (16 cases)");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-unlink-") as tmp:
    src = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    src.write_text(prefix + helper + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
