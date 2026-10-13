#!/usr/bin/env python3
"""Exercise wait4's block/recheck ordering with deterministic exit interleavings."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void wait4_block_recheck(")
body = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
enum { THREAD_READY, THREAD_BLOCKED };
typedef struct process process_t;
typedef struct { uint64_t tid; int state; process_t *process; } thread_t;
struct process { int pgid; thread_t *leader; };
static thread_t parent = {.tid=6, .state=THREAD_READY}, child;
static process_t owner = {.pgid=1}, dead;
static int process_dead, no_children;
static int zombie, exit_during_scan, wanted;
static void thread_block(int tid) {
    assert(tid == 6); parent.state = THREAD_BLOCKED;
}
static void thread_unblock(int tid) {
    assert(tid == 6); parent.state = THREAD_READY;
}
static thread_t *wait4_find_thread_zombie(thread_t *t, int pid) {
    assert(t == &parent && t->state == THREAD_BLOCKED && pid == wanted);
    if (exit_during_scan) { zombie = 1; thread_unblock(6); }
    return zombie ? &child : 0;
}
enum { THREAD_TERMINATED = 3 };
static process_t *process_find_child(process_t *p, int pid, int pgid, int zombies, int *has) {
    assert(p == &owner && pid == wanted && pgid == 1 && zombies);
    *has = !no_children; return process_dead ? &dead : NULL;
}
''' + body + r'''
int main(void) {
    int pids[] = {141, -1, 0, -20};
    for (unsigned i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
        wanted = pids[i];
        /* Exit and wake occur before parent publishes its blocking state. */
        zombie = 1; exit_during_scan = 0; thread_unblock(6);
        wait4_block_recheck(&parent, wanted);
        assert(parent.state == THREAD_READY);
        /* No exit yet: remain blocked, then a normal exit wakes the parent. */
        zombie = 0; wait4_block_recheck(&parent, wanted);
        assert(parent.state == THREAD_BLOCKED);
        zombie = 1; thread_unblock(6); assert(parent.state == THREAD_READY);
        /* Exit during the condition recheck also cannot lose its wakeup. */
        zombie = 0; exit_during_scan = 1;
        wait4_block_recheck(&parent, wanted);
        assert(parent.state == THREAD_READY);
    }
    parent.process = &owner; wanted = -1; zombie = 0; exit_during_scan = 0;
    process_dead = 1; dead.leader = NULL; /* waitid can observe process-only zombies */
    wait4_block_recheck(&parent, wanted); assert(parent.state == THREAD_READY);
    process_dead = 0; no_children = 1;
    wait4_block_recheck(&parent, wanted); assert(parent.state == THREAD_READY); /* retry returns ECHILD */
    puts("PASS: wait4 block/recheck cannot lose child-exit wakeup");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-wait4-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
