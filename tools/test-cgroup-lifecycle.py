#!/usr/bin/env python3
"""Exercise real cgroupfs mkdir/rmdir rules and delayed inode freeing."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/cgroupfs.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


pieces = [function(name) for name in (
    "static int cg_name_ok(", "static struct cgroup *cg_find_child(",
    "static struct cgroup *cg_walk(", "static const char *cg_rel(",
    "static int cg_split(", "int cgroupfs_rmdir(",
    "static void cg_put_open(",
)]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CGROUP_NAME_MAX 64
struct cgroup {
    char name[CGROUP_NAME_MAX];
    struct cgroup *parent, *child, *sibling;
    uint32_t nprocs, open_count;
    int removed;
};
typedef struct { int locked; } spinlock_t;
static struct cgroup g_cgroup_root;
static char g_cg_mount[64] = "/sys/fs/cgroup";
static spinlock_t g_cg_lock;
static int freed;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(!lock->locked); lock->locked = 1; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags; assert(lock->locked); lock->locked = 0;
}
static void kfree(void *p) { freed++; free(p); }
''' + "\n".join(pieces) + r'''
int main(void) {
    assert(cgroupfs_rmdir("/sys/fs/cgroup/") == -16); /* mount root is busy */
    assert(cgroupfs_rmdir("/sys/fs/cgroup/missing") == -2);
    struct cgroup *unit = calloc(1, sizeof(*unit));
    assert(unit);
    strcpy(unit->name, "axon-getty.service");
    unit->parent = &g_cgroup_root;
    g_cgroup_root.child = unit;
    unit->nprocs = 1;
    assert(cgroupfs_rmdir("/sys/fs/cgroup/axon-getty.service") == -39);
    unit->nprocs = 0;
    struct cgroup nested = {0};
    unit->child = &nested;
    assert(cgroupfs_rmdir("/sys/fs/cgroup/axon-getty.service") == -39);
    unit->child = NULL;
    unit->open_count = 1; /* cgroup.events is still open */
    assert(cgroupfs_rmdir("/sys/fs/cgroup/axon-getty.service") == 0);
    assert(g_cgroup_root.child == NULL && unit->removed && freed == 0);
    cg_put_open(unit);
    assert(freed == 1);
    puts("PASS: cgroupfs root, busy groups, and open-handle lifetime");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-cgroup-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
