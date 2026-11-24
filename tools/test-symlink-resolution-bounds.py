#!/usr/bin/env python3
"""Path resolution must never silently discard target bytes or components."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/fs.c").read_text()
start = source.index("static int fs_readlink_no_resolve(")
end = source.index("\n/* Resolve symlinks anywhere", start)
program = r'''
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
struct fs_file { size_t size; };
static struct fs_file link_file = {3};
static int reads, short_read;
static void *kmalloc(size_t n) { return malloc(n); }
static struct fs_file *fs_open_nofollow(const char *p) { (void)p; return &link_file; }
static int vfs_fstat(struct fs_file *f, struct stat *st) {
    (void)f; memset(st, 0, sizeof *st); st->st_mode = S_IFLNK; return 0;
}
static void fs_file_free(struct fs_file *f) { (void)f; }
static ssize_t fs_read(struct fs_file *f, void *buf, size_t n, size_t off) {
    (void)f; (void)off; reads++; if (short_read) n--;
    memcpy(buf, "abc", n); return (ssize_t)n;
}
''' + source[start:end] + r'''
int main(void) {
    char out[8]; size_t len = 0;
    assert(fs_readlink_no_resolve("/link", out, 4, &len) == 0);
    assert(len == 3 && !strcmp(out, "abc"));
    assert(fs_readlink_no_resolve("/link", out, 3, &len) != 0 && reads == 1);
    short_read = 1;
    assert(fs_readlink_no_resolve("/link", out, sizeof out, &len) != 0);
    char path[300]; size_t n = 0;
    for (int i = 0; i < 96; i++) { path[n++] = '/'; path[n++] = 'a'; }
    path[n] = 0;
    char *result = fs_normalize_abs_path(path);
    assert(result && !strcmp(result, path)); free(result);
    path[n++] = '/'; path[n++] = 'b'; path[n] = 0;
    assert(!fs_normalize_abs_path(path));
    puts("PASS: link resolution rejects truncated targets and excessive components");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-link-bounds-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
