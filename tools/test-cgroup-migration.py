#!/usr/bin/env python3
"""Exercise cgroup.procs PID-zero semantics and atomic membership migration."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/cgroupfs.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


# Compile the actual PID parser without unrelated controller store branches.
store = source.index("\tif (fid == CG_FILE_PROCS || fid == CG_FILE_THREADS) {")
end = source.index("\n\tif (fid == CG_FILE_PIDS_MAX)", store)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define CGROUP_PROCS_MAX 4
enum { CG_FILE_PROCS, CG_FILE_THREADS };
typedef long ssize_t;
struct cgroup {
    struct cgroup *parent;
    uint32_t nprocs, pids_current;
    uint64_t event_seq;
    uint64_t procs[CGROUP_PROCS_MAX];
    int removed;
};
typedef struct { uint64_t pid; struct cgroup *cgroup; } process_t;
typedef struct { process_t *process; } thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t g_cg_lock;
static process_t process;
static thread_t current = {&process};
static thread_t *thread_current(void) { return &current; }
static process_t *process_find(uint64_t pid) { return pid == process.pid ? &process : NULL; }
static void acquire_irqsave(spinlock_t *l, unsigned long *f) {
    assert(!l->held); l->held = 1; *f = 0;
}
static void release_irqrestore(spinlock_t *l, unsigned long f) {
    (void)f; assert(l->held);
    if (process.cgroup) {
        int found = 0;
        for (uint32_t i = 0; i < process.cgroup->nprocs; i++)
            found |= process.cgroup->procs[i] == process.pid;
        assert(found); /* no unlocked membership gap */
    }
    l->held = 0;
}
''' + function("static int cg_is_ancestor(") + function("static int cg_move_pid(") + r'''
static ssize_t store(struct cgroup *cg, int fid, const char *buf, size_t size) {
''' + source[store:end] + r'''
    return -1;
}
int main(void) {
    struct cgroup root = {.nprocs = 1, .pids_current = 1, .procs = {118}};
    struct cgroup service = {.parent = &root};
    process.pid = 118; process.cgroup = &root;
    assert(store(&service, CG_FILE_PROCS, "0\n", 2) == 2);
    assert(process.cgroup == &service && service.nprocs == 1);
    assert(root.nprocs == 0 && root.pids_current == 1 && service.pids_current == 1);
    assert(root.event_seq == 0 && service.event_seq == 1);
    assert(store(&service, CG_FILE_PROCS, "0", 1) == 1); /* idempotent */
    assert(service.nprocs == 1 && service.pids_current == 1);
    assert(store(&root, CG_FILE_PROCS, "118", 3) == 3);
    assert(service.nprocs == 0 && service.pids_current == 0 && root.pids_current == 1);
    assert(root.event_seq == 0 && service.event_seq == 2);
    const char *bad[] = {"", "garbage", "-118", "118x", "0 118", "18446744073709551616"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        size_t len = 0; while (bad[i][len]) len++;
        assert(store(&service, CG_FILE_PROCS, bad[i], len) == -1);
        assert(process.cgroup == &root);
    }
    assert(store(&service, CG_FILE_PROCS, "999", 3) == -1);
    service.removed = 1;
    assert(store(&service, CG_FILE_PROCS, "0", 1) == -1);
    service.removed = 0; service.nprocs = CGROUP_PROCS_MAX;
    assert(store(&service, CG_FILE_PROCS, "0", 1) == -1);
    assert(process.cgroup == &root && root.nprocs == 1);
    puts("PASS: cgroup.procs PID 0, atomic migration, counters, malformed/full/removed rejection");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-cgroup-move-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
