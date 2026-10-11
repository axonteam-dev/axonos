#!/usr/bin/env python3
"""Exercise the real VFS mount/unmount and regular-file bind functions."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/fs.c").read_text()


def function(name):
    start = source.index(f"int {name}(")
    return source[start:source.index("\n}\n", start) + 3]


mount = function("fs_mount")
bind = function("fs_bind_mount_file")
unmount = function("fs_unmount")
exact = source[source.index("struct fs_driver *fs_get_mount_driver_exact("):]
exact = exact[:exact.index("\n}\n") + 3]

program = r'''
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#define MAX_FS_MOUNTS 16
struct fs_driver { int id; };
struct mount_entry {
    char path[64];
    size_t path_len;
    struct fs_driver *driver;
    unsigned int refs;
    char bind_source[64];
};
static struct mount_entry g_mounts[MAX_FS_MOUNTS];
static int g_mount_count;
static struct fs_driver tmpfs = {3};
static void fs_ensure_ramfs_mountpoint_dir(const char *path) { (void)path; }
static int vfs_stat(const char *path, struct stat *st) {
    if (strcmp(path, "/run/machine-id") != 0 &&
        strcmp(path, "/etc/machine-id") != 0) return -1;
    st->st_mode = S_IFREG | 0644;
    return 0;
}
static struct fs_driver *fs_get_mount_driver(const char *path) {
    return strcmp(path, "/run/machine-id") == 0 ? &tmpfs : NULL;
}
''' + exact + mount + bind + unmount + r'''
int main(void) {
    struct fs_driver proc = {1}, overlay = {2};
    assert(fs_mount("/", &overlay) == 0);
    assert(fs_mount("/proc", &proc) == 0);
    assert(fs_mount("/proc", &proc) == 0);
    assert(g_mount_count == 2);
    assert(fs_mount("/proc", &overlay) == -1);
    assert(fs_unmount("/proc") == 0);
    assert(fs_get_mount_driver_exact("/proc") == &proc);
    assert(fs_unmount("/proc") == 0);
    assert(fs_get_mount_driver_exact("/proc") == NULL);
    assert(fs_unmount("/proc") == -1);
    assert(fs_get_mount_driver_exact("/") == &overlay);
    assert(fs_bind_mount_file("/run/machine-id", "/etc/machine-id") == 0);
    assert(fs_get_mount_driver_exact("/etc/machine-id") == &tmpfs);
    assert(strcmp(g_mounts[g_mount_count - 1].bind_source, "/run/machine-id") == 0);
    assert(fs_unmount("/etc/machine-id") == 0);
    assert(fs_get_mount_driver_exact("/etc/machine-id") == NULL);
    puts("PASS: stacked proc mount and regular-file bind mount");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-mount-stack-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
