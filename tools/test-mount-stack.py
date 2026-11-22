#!/usr/bin/env python3
"""Exercise the real VFS mount/unmount and regular-file bind functions."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/fs.c").read_text()


def function(name):
    try:
        start = source.index(f"int {name}(")
    except ValueError:
        start = source.index(f"uint64_t {name}(")
    return source[start:source.index("\n}\n", start) + 3]


mount = function("fs_mount")
bind = function("fs_bind_mount_file")
bind_dir = function("fs_bind_mount_dir")
move_mount = function("fs_mount_move")
mount_contains = source[source.index("static int fs_mount_path_contains("):]
mount_contains = mount_contains[:mount_contains.index("\n}") + 3]
private_tmpfs = function("fs_mount_private_tmpfs")
unmount = function("fs_unmount")
get_source = function("fs_mount_get_source")
set_source = function("fs_mount_set_source")
mount_flags = function("fs_mount_flags")
set_flags = function("fs_mount_set_flags")
update_flags = function("fs_mount_update_flags")
is_readonly = function("fs_mount_is_readonly")
translate = source[source.index("static int fs_translate_mount_path("):]
translate = translate[:translate.index("\n}") + 3]
private_check = source[source.index("static int fs_private_source_denied("):]
private_check = private_check[:private_check.index("\n}") + 3]
exact = source[source.index("struct fs_driver *fs_get_mount_driver_exact("):]
exact = exact[:exact.index("\n}\n") + 3]

program = (r'''
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#define MAX_FS_MOUNTS 16
#define FS_MOUNT_RDONLY 1ULL
struct fs_driver_ops { const char *name; };
struct fs_driver { int id; struct fs_driver_ops *ops; };
struct mount_entry {
    char path[64];
    size_t path_len;
    struct fs_driver *driver;
    unsigned int refs;
    uint64_t flags;
    uint8_t bind_directory;
    char bind_source[64];
    char source[256];
};
static struct mount_entry init_mounts[MAX_FS_MOUNTS], child_mounts[MAX_FS_MOUNTS];
static int init_mount_count, child_mount_count;
static struct mount_entry *active_mounts = init_mounts;
static int *active_mount_count = &init_mount_count;
#define g_mounts active_mounts
#define g_mount_count (*active_mount_count)
static struct fs_driver_ops proc_ops = {"proc"}, overlay_ops = {"overlay"},
                            tmpfs_ops = {"tmpfs"}, ext2_ops = {"ext2"};
static struct fs_driver tmpfs = {3, &tmpfs_ops};
static struct fs_driver ext2 = {4, &ext2_ops};
static int fs_path_is_private_mount_backing(const char *path) {
    return path && strncmp(path, "/run/.axon-private-tmpfs-", 25) == 0;
}
static void fs_ensure_ramfs_mountpoint_dir(const char *path) { (void)path; }
static int ramfs_mkdir(const char *path) { (void)path; return 0; }
static int ramfs_chmod(const char *path, mode_t mode) { (void)path; (void)mode; return 0; }
static int ramfs_remove(const char *path) { (void)path; return 0; }
static int vfs_stat(const char *path, struct stat *st) {
    if (strcmp(path, "/run/machine-id") == 0 || strcmp(path, "/etc/machine-id") == 0)
        st->st_mode = S_IFREG | 0644;
    else if (strcmp(path, "/source") == 0 || strcmp(path, "/target") == 0 ||
             strcmp(path, "/run") == 0 || strcmp(path, "/tmp") == 0 ||
             strncmp(path, "/run/.axon-private-tmpfs-", 25) == 0)
        st->st_mode = S_IFDIR | 0755;
    else
        return -1;
    return 0;
}
static struct fs_driver *fs_get_mount_driver(const char *path) {
    if (strcmp(path, "/run/machine-id") == 0) return &tmpfs;
    if (strncmp(path, "/run/", 5) == 0) return &tmpfs;
    if (strncmp(path, "/source", 7) == 0) return &ext2;
    return NULL;
}
''' + exact + get_source + set_source + mount_flags + set_flags + update_flags + is_readonly +
    translate + private_check + mount + bind + bind_dir + mount_contains + move_mount + private_tmpfs + unmount + r'''
int main(void) {
    struct fs_driver proc = {1, &proc_ops}, overlay = {2, &overlay_ops};
    char source[256];
    assert(fs_mount("/", &overlay) == 0);
    assert(fs_mount_update_flags("/plain/path", 8, 0, 0) == 0);
    assert(fs_mount_flags("/another/path") == 8); /* operate on containing root mount */
    assert(fs_mount_update_flags("/plain/path", 0, 8, 0) == 0);
    assert(fs_mount_flags("/another/path") == 0);
    assert(fs_mount_get_source(0, source, sizeof(source)) == 0);
    assert(strcmp(source, "") == 0);
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
    assert(fs_mount("/mnt", &ext2) == 0);
    assert(fs_mount_set_source("/mnt", "/dev/sda1") == 0);
    assert(fs_mount_get_source(1, source, sizeof(source)) == 0);
    assert(strcmp(source, "/dev/sda1") == 0);
    assert(fs_unmount("/mnt") == 0);
    assert(fs_bind_mount_file("/run/machine-id", "/etc/machine-id") == 0);
    assert(fs_get_mount_driver_exact("/etc/machine-id") == &tmpfs);
    assert(strcmp(g_mounts[g_mount_count - 1].bind_source, "/run/machine-id") == 0);
    assert(fs_mount_get_source(g_mount_count - 1, source, sizeof(source)) == 0);
    assert(strcmp(source, "/run/machine-id") == 0);
    assert(fs_unmount("/etc/machine-id") == 0);
    assert(fs_get_mount_driver_exact("/etc/machine-id") == NULL);
    assert(fs_mount("/source", &ext2) == 0);
    assert(fs_mount_set_flags("/source", 1 | 4 | 8) == 0);
    assert(fs_bind_mount_dir("/source", "/target", 0) == 0);
    assert(g_mounts[g_mount_count - 1].bind_directory);
    assert(fs_mount_set_flags("/target", 4096 | 16384) == 0);
    assert((fs_mount_flags("/target") & (1 | 4 | 8)) == (1 | 4 | 8));
    assert(fs_mount_set_flags("/target", 32 | 4096) == 0); /* bind remount,rw */
    assert(!fs_mount_is_readonly("/target/sub/file"));
    assert(fs_mount_set_flags("/target", 32 | 4096 | 1) == 0); /* bind remount,ro */
    assert(fs_mount_is_readonly("/target/sub/file"));
    char translated[128];
    assert(fs_translate_mount_path("/target/sub/file", translated, sizeof(translated)) == 0);
    assert(strcmp(translated, "/source/sub/file") == 0);
    assert(fs_unmount("/target") == 0);
    assert(!fs_mount_is_readonly("/target/sub/file"));
    assert(fs_mount("/source", &ext2) == 0);
    assert(fs_mount("/source/nested", &proc) == 0);
    assert(fs_mount("/target", &tmpfs) == 0);
    assert(fs_mount("/target/old", &proc) == 0);
    assert(fs_mount_move("/source", "/target") == 0);
    assert(fs_get_mount_driver_exact("/source") == NULL);
    assert(fs_get_mount_driver_exact("/source/nested") == NULL);
    assert(fs_get_mount_driver_exact("/target") == &ext2);
    assert(fs_get_mount_driver_exact("/target/nested") == &proc);
    assert(fs_get_mount_driver_exact("/target/old") == NULL);
    assert(fs_mount("/run", &tmpfs) == 0);
    memcpy(child_mounts, init_mounts, sizeof(init_mounts));
    child_mount_count = init_mount_count;
    active_mounts = child_mounts;
    active_mount_count = &child_mount_count;
    assert(fs_mount_private_tmpfs("/tmp", 2, 1, S_IFDIR | 01777) == 0);
    assert(fs_translate_mount_path("/tmp/a", translated, sizeof(translated)) == 0);
    assert(strcmp(translated, "/run/.axon-private-tmpfs-00000002-00000001/a") == 0);
    assert(fs_private_source_denied(translated));
    active_mounts = init_mounts;
    active_mount_count = &init_mount_count;
    assert(fs_get_mount_driver_exact("/tmp") == NULL); /* sibling namespace cannot see it */
    assert(fs_private_source_denied("/run/.axon-private-tmpfs-00000002-00000001/a"));
    puts("PASS: namespace mount tables, private tmpfs source isolation, bind translation and RO flags");
}
''')

with tempfile.TemporaryDirectory(prefix="axon-mount-stack-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
