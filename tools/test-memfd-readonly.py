#!/usr/bin/env python3
"""An anonymous memfd is not affected by the root mount's read-only flag."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/fs.c").read_text()
start = source.index("ssize_t fs_write(")
end = source.index("\nuint64_t fs_current_generation(", start)
assert 'if (!file->is_memfd && file->path && fs_mount_is_readonly(file->path))' in source
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
struct fs_file { const char *path; int is_memfd; };
struct fs_driver_ops { ssize_t (*write)(struct fs_file *, const void *, size_t, size_t); };
struct fs_driver { struct fs_driver_ops *ops; };
static int fs_mount_is_readonly(const char *p) { (void)p; return 1; }
static int fs_file_matches_driver(struct fs_driver *d, struct fs_file *f) { (void)d; (void)f; return 1; }
static ssize_t write_impl(struct fs_file *f, const void *b, size_t n, size_t o) {
    (void)f; (void)b; (void)o; return n;
}
static struct fs_driver_ops ops = {write_impl};
static struct fs_driver driver = {&ops}, *g_drivers[] = {&driver};
static int g_drivers_count = 1;
''' + source[start:end] + r'''
int main(void) {
    struct fs_file file = {"/memfd:test (deleted)", 0};
    assert(fs_write(&file,"x",1,0)==-30);
    file.is_memfd=1;
    assert(fs_write(&file,"x",1,0)==1);
    puts("PASS: memfd bypasses unrelated read-only root mount");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-memfd-ro-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
