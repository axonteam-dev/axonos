#!/usr/bin/env python3
"""Exercise the actual regular read syscall tail and ramfs reader through EOF."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
ramfs = (root / "fs/virt/ramfs.c").read_text()
syscalls = (root / "syscall/dispatch/syscall_dispatch.c").read_text()


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


node_start = ramfs.index("struct ramfs_node {")
node = ramfs[node_start:ramfs.index("\n};", node_start) + 3]
ram_read = function(ramfs, "static ssize_t ramfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {")
start = syscalls.index("            off_t read_pos = f->pos;", syscalls.index("        case SYS_read: {"))
end = syscalls.index("            return (rr >= 0) ? (uint64_t)rr : ret_read_err(rr);", start)
tail = syscalls[start:end + len("            return (rr >= 0) ? (uint64_t)rr : ret_read_err(rr);")]
program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef struct { int held; } spinlock_t;
typedef struct { uint64_t tid; } thread_t;
struct fs_file { const char *path; void *driver_private; size_t size; off_t pos; };
struct ramfs_xattr;
''' + node + r'''
struct ramfs_file_handle { struct ramfs_node *node; };
struct ext2_dir_entry { uint32_t inode; uint16_t rec_len; uint8_t name_len, file_type; };
#define EXT2_FT_DIR 2
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_SYMLINK 7
#define S_IFLNK 0120000
static void acquire_irqsave(spinlock_t *l, unsigned long *f) {
    assert(!l->held); l->held = 1; *f = 0;
}
static void release_irqrestore(spinlock_t *l, unsigned long f) {
    (void)f; assert(l->held); l->held = 0;
}
static struct ramfs_node *ramfs_resolve_link(struct ramfs_node *n) { return n; }
static struct ramfs_node *ramfs_find_child(struct ramfs_node *n, const char *name) {
    (void)n; (void)name; return NULL;
}
static int fs_get_mount_children(const char *p, char names[][64], int max) {
    (void)p; (void)names; (void)max; return 0;
}
''' + ram_read + r'''
#define kmalloc malloc
#define kfree free
#define devel_printf printf
#define kprintf printf
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static uint64_t ret_read_err(ssize_t e) { return (uint64_t)e; }
static int copy_to_user_safe(void *to, const void *from, size_t n) {
    memcpy(to, from, n); return 0;
}
static int pid1_dl_trace_thread(thread_t *t) { (void)t; return 0; }
static int pid1_dl_trace_fd(thread_t *t, int fd) { (void)t; (void)fd; return 0; }
static const char *thread_fd_path(thread_t *t, int fd) { (void)t; (void)fd; return "test"; }
static void init_trace_read(thread_t *t, struct fs_file *f, int fd,
                            off_t pos, ssize_t n, size_t count) {
    (void)t; (void)f; (void)fd; (void)pos; (void)n; (void)count;
}
static void openrc_trace_deptree_read(thread_t *t, struct fs_file *f, int fd,
                                    off_t pos, ssize_t n, const void *data, const void *user) {
    (void)t; (void)f; (void)fd; (void)pos; (void)n; (void)data; (void)user;
}
static ssize_t fs_read(struct fs_file *f, void *buf, size_t len, size_t off) {
    return ramfs_read(f, buf, len, off);
}
static uint64_t read_regular(thread_t *cur, struct fs_file *f, void *bufp, size_t cnt) {
    int fd = 3;
    size_t to_read = cnt < 65536 ? cnt : 65536;
    void *tmp = malloc(to_read); assert(tmp);
''' + tail + r'''
}
int main(void) {
    char data[20000], out[1024]; size_t size = 0;
    for (int i = 0; i < 300; i++)
        size += snprintf(data + size, sizeof(data) - size,
                         "depinfo_%d_service='service_%d'\n", i, i);
    struct ramfs_node node = {.data = data, .size = size, .capacity = sizeof(data)};
    struct ramfs_file_handle handle = {&node};
    struct fs_file file = {.path = "/run/openrc/deptree", .driver_private = &handle, .size = size};
    thread_t task = {.tid = 4};
    size_t off = 0;
    while (off < size) {
        uint64_t n = read_regular(&task, &file, out, sizeof(out));
        size_t want = size - off < sizeof(out) ? size - off : sizeof(out);
        assert(n == want && file.pos == (off_t)(off + want));
        assert(memcmp(out, data + off, want) == 0); off += want;
    }
    assert(read_regular(&task, &file, out, sizeof(out)) == 0);
    assert(read_regular(&task, &file, out, sizeof(out)) == 0);
    struct fs_file independent = file; independent.pos = 0;
    assert(read_regular(&task, &independent, out, sizeof(out)) == sizeof(out));
    assert(memcmp(out, data, sizeof(out)) == 0 && file.pos == (off_t)size);
    /* Sparse inode bytes after the allocated payload must be zeros, then EOF. */
    node.capacity = 100; node.size = 2048; independent.pos = 1024;
    assert(read_regular(&task, &independent, out, sizeof(out)) == sizeof(out));
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0);
    assert(read_regular(&task, &independent, out, sizeof(out)) == 0);
    puts("PASS: actual read + ramfs advances offsets, preserves lines, returns short read and EOF");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-read-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-but-set-variable", "-fsanitize=undefined",
                    "-Wno-sign-compare",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
