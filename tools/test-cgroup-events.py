#!/usr/bin/env python3
"""Exercise actual cgroup event snapshots, priority notifications and rewind."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/cgroupfs.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


def declaration(signature):
    start = source.index(signature)
    return source[start:source.index("\n};", start) + 3]


read_source = function("static ssize_t cgroupfs_read(")
begin = read_source.index("\tif (h->file_id) {")
opening = read_source.index("{", begin)
end, depth = opening + 1, 1
while depth:
    depth += (read_source[end] == "{") - (read_source[end] == "}")
    end += 1
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define CGROUP_NAME_MAX 64
#define CGROUP_PROCS_MAX 256
#define CGROUP_UNLIMITED (~0ULL)
#define kmalloc malloc
''' + declaration("struct cgroup {") + declaration("struct cgroupfs_handle {") + declaration("enum {") + r'''
typedef struct { uint64_t pid; struct cgroup *cgroup; } process_t;
typedef struct { int held; } spinlock_t;
struct fs_file { void *driver_private, *fs_private; size_t size; };
struct fs_driver { int unused; };
static struct cgroup g_cgroup_root;
static struct fs_driver cgroup_driver;
static spinlock_t g_cg_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) {
    assert(!l->held); l->held = 1; *f = 0;
}
static void release_irqrestore(spinlock_t *l, unsigned long f) {
    (void)f; assert(l->held); l->held = 0;
}
''' + function("static int cg_populated(") + function("static ssize_t cg_show(") + function("void cgroup_task_enter(") + function("void cgroup_task_leave(") + function("static int cg_refresh_cache(") + function("int cgroupfs_poll(") + r'''
static ssize_t read_file(struct fs_file *file, void *buf, size_t size, size_t offset) {
    struct cgroupfs_handle *h = file->driver_private;
''' + read_source[begin:end] + r'''
    return -1;
}
int main(void) {
    struct cgroup service = {.parent = &g_cgroup_root};
    struct cgroupfs_handle h = {.cg = &service, .file_id = CG_FILE_EVENTS};
    struct fs_file file = {.driver_private = &h, .fs_private = &cgroup_driver};
    char buf[128] = {0}; short ready = -1;
    assert(cg_refresh_cache(&h, &file) == 0);
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == 0); /* PRI quiet */
    assert(cgroupfs_poll(&file, 1, &ready) == 1 && ready == 1); /* IN even EOF */
    process_t p = {.pid = 118}; cgroup_task_enter(&p, &service);
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == (2 | 8));
    ssize_t n = read_file(&file, buf, sizeof(buf), 0);
    assert(n > 0 && strstr(buf, "populated 1\n"));
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == 0); /* read acknowledges */
    assert(read_file(&file, buf, sizeof(buf), n) == 0); /* EOF */
    cgroup_task_leave(&p);
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == (2 | 8));
    memset(buf, 0, sizeof(buf));
    assert(read_file(&file, buf, 0, 0) == 0); /* zero count must not acknowledge */
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == (2 | 8));
    n = read_file(&file, buf, sizeof(buf), 0);
    assert(n > 0 && strstr(buf, "populated 0\n")); /* rewind is fresh, not open snapshot */
    assert(cgroupfs_poll(&file, 2, &ready) == 1 && ready == 0);
    service.removed = 1;
    assert(cgroupfs_poll(&file, 0, &ready) == 1 && ready == 8);
    file.fs_private = NULL;
    assert(cgroupfs_poll(&file, 2, &ready) == 0); /* don't cast other driver data */
    free(h.cache);
    puts("PASS: cgroup.events fresh rewind, EOF readiness, populated PRI/ERR and acknowledgement");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-cgroup-events-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
