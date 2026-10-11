#!/usr/bin/env python3
"""Exercise the kernel's overlay symlink operation with mocked layer storage."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/overlayfs.c").read_text()
start = source.index("int overlayfs_symlink(")
function = source[start:source.index("\n}\n", start) + 3]
fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
struct fs_file { int type; };
static struct fs_file inode;
static int overlay_active = 1, exists, whiteout, created, released;
#define kprintf(...) ((void)0)
static int ramfs_path_is_whiteout(const char *p) { (void)p; return whiteout; }
static int overlay_open(const char *p, struct fs_file **out) {
    (void)p; *out = exists && !whiteout ? &inode : NULL;
    return *out ? 0 : -1;
}
static void overlay_release(struct fs_file *f) { assert(f == &inode); released++; }
static void ov_release_inner(struct fs_file *f) { overlay_release(f); }
static int ov_upper_open(const char *p, struct fs_file **f) { return overlay_open(p, f); }
static int squashfs_open_path(const char *p, struct fs_file **f) { return overlay_open(p, f); }
static int ramfs_remove(const char *p) { (void)p; whiteout = 0; return 0; }
static int ov_ensure_parent_upper(const char *p) { (void)p; return 0; }
static int ramfs_symlink(const char *p, const char *t) { (void)p; (void)t; created++; return 0; }
'''
tests = r'''
int main(void) {
    exists = 1;
    assert(overlayfs_symlink("/bin/busybox", "/bin/busybox") == -4);
    assert(created == 0 && released == 1);
    /* Existing dangling links also occupy the name (nofollow lookup). */
    assert(overlayfs_symlink("/bin/sh", "/missing") == -4);
    assert(created == 0 && released == 2);
    whiteout = 1;
    assert(overlayfs_symlink("/bin/sh", "/bin/busybox") == 0);
    assert(created == 1 && whiteout == 0);
    exists = 0;
    assert(overlayfs_symlink("/bin/new", "/bin/busybox") == 0);
    assert(created == 2);
    puts("PASS: overlay symlink collisions and whiteout replacement");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-symlink-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + function + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
