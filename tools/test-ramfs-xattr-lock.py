#!/usr/bin/env python3
"""Exercise ramfs xattr lookup while the namespace lock is already held."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/ramfs.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


lookup = function("static struct ramfs_node *ramfs_lookup_nofollow_impl(")
listing = function("ssize_t ramfs_listxattr(")
fixture = r'''
#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#define XATTR_LIST_MAX 65536
struct ramfs_xattr { char *name; struct ramfs_xattr *next; };
struct ramfs_node {
    char *name, *data;
    int is_dir;
    mode_t mode;
    struct ramfs_node *parent, *children, *next;
    struct ramfs_xattr *xattrs;
};
static struct ramfs_node *ramfs_root;
static int locked;
static void ramfs_tree_lock_acquire(unsigned long *flags) {
    assert(!locked); *flags = 0; locked = 1;
}
static void ramfs_tree_lock_release(unsigned long flags) {
    (void)flags; assert(locked); locked = 0;
}
static struct ramfs_node *ramfs_find_child(struct ramfs_node *parent, const char *name) {
    for (struct ramfs_node *n = parent->children; n; n = n->next)
        if (strcmp(n->name, name) == 0) return n;
    return NULL;
}
static struct ramfs_node *ramfs_find_child_sync(struct ramfs_node *parent, const char *name) {
    unsigned long flags;
    ramfs_tree_lock_acquire(&flags);
    struct ramfs_node *n = ramfs_find_child(parent, name);
    ramfs_tree_lock_release(flags);
    return n;
}
static int ramfs_next_component(const char **path, char *out, size_t cap) {
    while (**path == '/') ++*path;
    if (!**path) return 0;
    size_t n = 0;
    while ((*path)[n] && (*path)[n] != '/') n++;
    if (n >= cap) return 0;
    memcpy(out, *path, n);
    out[n] = 0;
    *path += n;
    return 1;
}
static int ramfs_build_path(struct ramfs_node *n, char *out, size_t cap) {
    (void)n; (void)out; (void)cap; return -1;
}
static struct ramfs_node *ramfs_resolve_link(struct ramfs_node *n) { return n; }
#define kmalloc malloc
#define kfree free
''' + lookup + listing + r'''
int main(void) {
    struct ramfs_node root = {.name="/", .is_dir=1, .mode=S_IFDIR},
                      etc = {.name="etc", .is_dir=1, .mode=S_IFDIR},
                      release = {.name="os-release", .mode=S_IFREG};
    root.children = &etc;
    etc.parent = &root;
    etc.children = &release;
    release.parent = &etc;
    ramfs_root = &root;

    assert(ramfs_lookup_nofollow_impl("/etc/os-release", 0) == &release);
    assert(ramfs_listxattr("/etc/os-release", NULL, 0) == 0);
    struct ramfs_xattr x = {.name="user.example"};
    release.xattrs = &x;
    size_t need = strlen(x.name) + 1;
    assert(ramfs_listxattr("/etc/os-release", NULL, 0) == (ssize_t)need);
    char buf[32] = {0};
    assert(ramfs_listxattr("/etc/os-release", buf, need - 1) == -ERANGE);
    assert(ramfs_listxattr("/etc/os-release", buf, sizeof(buf)) == (ssize_t)need);
    assert(strcmp(buf, x.name) == 0 && !locked);
    puts("PASS: ramfs xattr lookup does not reacquire namespace lock");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-xattr-lock-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
