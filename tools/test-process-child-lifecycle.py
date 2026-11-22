#!/usr/bin/env python3
"""Recycled thread slots must not corrupt the process child lists."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "core/process.c").read_text()
start = source.index("static int process_wait_spec_match(")
end = source.index("\nvoid process_mark_zombie(", start)
reparent = source.index("void process_reparent_children(")
reparent_end = source.index("\nint process_reap(", reparent)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define PROCESS_TABLE_MAX 16
enum { PROCESS_ALIVE, PROCESS_ZOMBIE };
typedef struct process process_t;
typedef struct thread {
    int parent_tid, linux_ppid;
    uint64_t tid;
    process_t *process;
} thread_t;
struct process {
    uint64_t pid;
    int pgid, state;
    process_t *parent, *first_child, *next_sibling;
    thread_t *leader;
};
static process_t *process_table[PROCESS_TABLE_MAX];
static thread_t *threads[32];
static int process_lock;
static void acquire_irqsave(int *lock, unsigned long *flags) { (void)lock; *flags = 0; }
static void release_irqrestore(int *lock, unsigned long flags) { (void)lock; (void)flags; }
static thread_t *thread_get(int tid) { return tid >= 0 && tid < 32 ? threads[tid] : NULL; }
''' + source[start:end] + source[reparent:reparent_end] + r'''
int main(void) {
    int has;
    process_t init = {.pid=1}, old = {.pid=2}, other = {.pid=3}, child = {.pid=4};
    thread_t init_t = {.tid=1, .process=&init};
    thread_t other_t = {.tid=17, .process=&other};
    thread_t child_t = {.tid=18, .parent_tid=17, .linux_ppid=2, .process=&child};
    init.leader = &init_t; other.leader = &other_t; child.leader = &child_t;
    threads[17] = &other_t;
    process_table[0]=&init; process_table[1]=&old;
    process_table[2]=&other; process_table[3]=&child;
    old.parent=&init; other.parent=&init;
    init.first_child=&old; old.next_sibling=&other;
    old.first_child=&child; child.parent=&old;

    process_reparent_children(&old, &init);
    assert(child.parent == &init && child_t.linux_ppid == 1);
    /* The old slot can already have been recycled by another process. */
    child_t.parent_tid = 17;
    assert(!process_find_child(&other, 4, 0, 0, &has) && !has);
    assert(child.parent == &init);
    assert(process_find_child(&init, 4, 0, 0, &has) == &child && has);
    process_reparent_children(&other, &init);
    assert(init.first_child == &child && child.next_sibling != &child);

    /* A pre-existing cycle must be repaired, not spin with interrupts off. */
    child.next_sibling = &child;
    assert(!process_find_child(&init, -1, 0, 1, &has) && has);
    assert(init.first_child != NULL);
    int seen = 0;
    for (process_t *p = init.first_child; p; p = p->next_sibling)
        assert(++seen <= PROCESS_TABLE_MAX && p->parent == &init);
    assert(seen == 3);

    /* Repair a genuinely parentless record when its stable PPID agrees. */
    process_t orphan = {.pid=5};
    thread_t orphan_t = {.tid=19, .parent_tid=17, .linux_ppid=3, .process=&orphan};
    orphan.leader=&orphan_t; process_table[4]=&orphan;
    assert(process_find_child(&other, 5, 0, 0, &has) == &orphan && has);
    assert(orphan.parent == &other);
    puts("PASS: recycled thread ids cannot steal children or hang wait");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-process-child-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=5)
