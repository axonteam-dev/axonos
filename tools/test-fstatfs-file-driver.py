#!/usr/bin/env python3
"""Test that fstatfs can identify the filesystem owning an open handle."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
fs_source = (root / "fs/fs.c").read_text()
start = fs_source.index("static int fs_file_matches_driver(")
end = fs_source.index("\nint fs_get_mount_path(", start)
implementation = fs_source[start:end]

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define FS_TYPE_PIPE 4
#define FS_TYPE_SOCKET 5
struct fs_file {
    const char *path;
    void *fs_private;
    int type;
};
struct fs_driver_ops { const char *name; };
struct fs_driver { struct fs_driver_ops *ops; void *driver_data; };
static struct fs_driver *g_drivers[4];
static int g_drivers_count;
''' + implementation + r'''
int main(void) {
    struct fs_driver_ops sysfs_ops = {.name = "sysfs"};
    struct fs_driver_ops tmpfs_ops = {.name = "tmpfs"};
    int sysfs_root, tmpfs_root;
    struct fs_driver sysfs = {.ops = &sysfs_ops, .driver_data = &sysfs_root};
    struct fs_driver tmpfs = {.ops = &tmpfs_ops, .driver_data = &tmpfs_root};
    g_drivers[0] = &sysfs;
    g_drivers[1] = &tmpfs;
    g_drivers_count = 2;

    /* The remembered pathname may no longer describe the open mount. */
    struct fs_file link_fd = {
        .path = "/sys/class/net/eth0",
        .fs_private = &sysfs_root,
    };
    assert(fs_get_file_driver(&link_fd) == &sysfs);

    struct fs_file other_fd = {.fs_private = &tmpfs_root};
    assert(fs_get_file_driver(&other_fd) == &tmpfs);
    struct fs_file no_driver_fd = {0};
    assert(fs_get_file_driver(&no_driver_fd) == NULL);
    struct fs_file pipe_fd = {.fs_private = &sysfs_root, .type = FS_TYPE_PIPE};
    assert(fs_get_file_driver(&pipe_fd) == NULL);
    struct fs_file socket_fd = {.fs_private = &sysfs_root, .type = FS_TYPE_SOCKET};
    assert(fs_get_file_driver(&socket_fd) == NULL);
    puts("PASS: fstatfs file-driver lookup uses the opened filesystem");
}
'''

dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = dispatch.index("case 137: /* statfs */")
end = dispatch.index("case SYS_setxattr:", start)
fstatfs = dispatch[start:end]
assert "fs_get_file_driver(ff)" in fstatfs
assert 'ksf.f_type = 0x62656572;' in fstatfs

with tempfile.TemporaryDirectory(prefix="axon-fstatfs-", dir="/tmp/opencode") as tmp:
    source_path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source_path.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(source_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
