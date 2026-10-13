#!/usr/bin/env python3
"""Exercise the actual boot fallback helper without clobbering image configuration."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/entry/init.c").read_text()
start = source.index("static int boot_seed_file_if_missing(")
body = source[start:source.index("\n}\n", start) + 3]
paths = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
         "/etc/nsswitch.conf", "/etc/fstab", "/usr/share/udhcpc/default.script"]
for path in paths:
    assert f'boot_seed_file_if_missing("{path}"' in source
    assert f'fs_unlink("{path}")' not in source
    assert f'fs_create_file("{path}")' not in source

program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef long ssize_t;
typedef unsigned mode_t;
struct stat { int unused; };
struct fs_file { int unused; };
static int exists, creates, writes, frees, chmods;
static mode_t saved_mode;
static char content[1024];
static struct fs_file file;
static int vfs_lstat(const char *p, struct stat *st) { (void)p; (void)st; return exists ? 0 : -1; }
static struct fs_file *fs_create_file(const char *p) { (void)p; creates++; exists = 1; return &file; }
static ssize_t fs_write(struct fs_file *f, const void *s, size_t len, size_t off) {
    assert(f == &file && off == 0 && len < sizeof(content));
    writes++; memcpy(content, s, len); content[len] = 0; return len;
}
static void fs_file_free(struct fs_file *f) { assert(f == &file); frees++; }
static int fs_chmod(const char *p, mode_t mode) { (void)p; chmods++; saved_mode = mode; return 0; }
''' + body + r'''
int main(void) {
    const char *paths[] = {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
                          "/etc/nsswitch.conf", "/etc/fstab", "/usr/share/udhcpc/default.script"};
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        exists = 1; strcpy(content, "root:x:0:0:root:/root:/bin/sh\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\n");
        char before[1024]; strcpy(before, content);
        assert(boot_seed_file_if_missing(paths[i], "fallback", 8, 0644) == 0);
        assert(!creates && !writes && !frees && !chmods && strcmp(content, before) == 0);
        /* lstat also preserves an empty file or a dangling symlink inode. */
        content[0] = 0;
        assert(boot_seed_file_if_missing(paths[i], "fallback", 8, 0644) == 0);
        assert(!writes && !content[0]);
    }
    exists = 0;
    assert(boot_seed_file_if_missing("/etc/shadow", "root:!\n", 7, 0600) == 0);
    assert(creates == 1 && writes == 1 && frees == 1 && chmods == 1);
    assert(strcmp(content, "root:!\n") == 0 && saved_mode == 0600);
    puts("PASS: boot preserves packaged accounts/passwords/NSS/fstab/DHCP hook; seeds only absent files");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-boot-config-") as tmp:
    c = Path(tmp) / "test.c"; binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
