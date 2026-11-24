#!/usr/bin/env python3
"""mkdir must resolve the parent of a trailing-slash target correctly."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/fs.c").read_text()
start = source.index("int fs_mkdir(const char *path)")
body = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct fs_driver_ops { int (*mkdir)(const char *); };
struct fs_driver { struct fs_driver_ops *ops; };
static char seen[512];
static int create(const char *p) { strcpy(seen, p); return 0; }
static struct fs_driver_ops ops = {create};
static struct fs_driver driver = {&ops};
static struct fs_driver *g_drivers[] = {&driver};
static int g_drivers_count = 1;
static int fs_private_source_denied(const char *p) { (void)p; return 0; }
static int fs_resolve_parent_path(const char *p, char *out, size_t n) {
    assert(p[strlen(p)-1] != '/' || !strcmp(p, "/"));
    if (strlen(p) >= n) return -1;
    strcpy(out, p); return 0;
}
static int fs_mount_is_readonly(const char *p) { (void)p; return 0; }
static int fs_translate_mount_path(const char *p, char *out, size_t n) {
    if (strlen(p) >= n) return -1;
    strcpy(out, p); return 0;
}
static struct fs_driver *fs_match_mount(const char *p) { (void)p; return &driver; }
static struct fs_driver *fs_get_mount_driver_exact(const char *p) {
    return !strcmp(p, "/mnt/existing") ? &driver : NULL;
}
static void inotify_notify_entry(const char *p, uint32_t mask, int cookie) {
    (void)p; (void)mask; (void)cookie;
}
''' + body + r'''
int main(void) {
    assert(fs_mkdir("/mnt/lfs/") == 0 && !strcmp(seen, "/mnt/lfs"));
    assert(fs_mkdir("/mnt/lfs///") == 0 && !strcmp(seen, "/mnt/lfs"));
    assert(fs_mkdir("/mnt/existing/") == -4);
    assert(fs_mkdir("/") == 0 && !strcmp(seen, "/"));
    assert(fs_mkdir("") == -1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mkdir-slash-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: mkdir resolves trailing-slash destination as a leaf")
