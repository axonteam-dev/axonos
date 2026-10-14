#!/usr/bin/env python3
"""Exercise actual block/sleep accounting when deadlines expire before dispatch."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()


def function(signature):
    start = source.index(signature)
    while source.index(";", start) < source.index("{", start):
        start = source.index(signature, start + len(signature))
    return source[start:source.index("\n}\n", start) + 3]


program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
enum { THREAD_READY, THREAD_RUNNING, THREAD_BLOCKED, THREAD_TERMINATED, THREAD_SLEEPING };
typedef struct {
    uint64_t tid, sched_vruntime;
    uint32_t sleep_until, sched_fifo_seq;
    int state, nice, vfork_waiting, idle;
} thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t sched_lock;
static thread_t sleeper = {.tid = 1, .state = THREAD_RUNNING};
static thread_t child = {.tid = 2, .state = THREAD_READY, .sched_vruntime = 100};
static thread_t *threads[] = {&sleeper, &child}, *current = &sleeper;
static int thread_count = 2, child_selected;
static uint32_t sched_fifo_counter;
static thread_t *thread_current(void) { return current; }
static thread_t *thread_get(int tid) {
    for (int i = 0; i < thread_count; i++) if (threads[i]->tid == (uint64_t)tid) return threads[i];
    return NULL;
}
static int thread_is_any_idle(const thread_t *t) { return t->idle; }
static uint32_t thread_deadline_ms(uint32_t delay) { return 100 + delay; }
static void acquire_irqsave(spinlock_t *l, unsigned long *f) {
    assert(!l->held); l->held = 1; *f = 0;
}
static void release(spinlock_t *l) { assert(l->held); l->held = 0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; release(l); }
#define klogprintf(...) ((void)0)
static void thread_yield(void);
''' + function("static uint64_t thread_vruntime_delta(") + function("static void thread_account_block_nolock(") + function("static void thread_note_ready_nolock(") + function("void thread_schedule_prev_saved(") + function("void thread_block(") + function("int thread_block_current_atomic(") + function("void thread_block_with_timeout(") + function("void thread_sleep(") + r'''
static void thread_yield(void) {
    unsigned long f; acquire_irqsave(&sched_lock, &f);
    thread_t *prev = current;
    /* Model the real inline timeout scan: a tiny sleep expired before pick. */
    prev->sleep_until = 0;
    thread_note_ready_nolock(prev);
    if (child.state == THREAD_READY && child.sched_vruntime < prev->sched_vruntime) {
        child_selected++;
        current = &child; child.state = THREAD_RUNNING;
        thread_schedule_prev_saved(prev); /* READY outgoing task: no double charge */
    } else {
        prev->state = THREAD_RUNNING; release_irqrestore(&sched_lock, f);
    }
}
int main(void) {
    int rounds;
    for (rounds = 0; rounds < 20 && !child_selected; rounds++) thread_sleep(1);
    assert(child_selected && rounds == 5); /* old path kept sleeper at vruntime 0 forever */
    assert(sleeper.sched_vruntime == 105);
    current = &sleeper; sleeper.state = THREAD_RUNNING;
    uint64_t before = sleeper.sched_vruntime;
    thread_block(1);
    assert(sleeper.sched_vruntime == before + 21 && sleeper.state == THREAD_BLOCKED);
    thread_block(1); assert(sleeper.sched_vruntime == before + 21);
    assert(!thread_block_current_atomic());
    sleeper.state = THREAD_RUNNING;
    assert(thread_block_current_atomic());
    assert(sleeper.sched_vruntime == before + 42);
    child.state = THREAD_READY; uint64_t child_before = child.sched_vruntime;
    thread_block(2); assert(child.sched_vruntime == child_before); /* another task does not accrue CPU */
    sleeper.state = THREAD_RUNNING;
    thread_block_with_timeout(1, 10);
    assert(sleeper.sched_vruntime == before + 63 && sleeper.sleep_until == 110);
    unsigned long f; acquire_irqsave(&sched_lock, &f);
    thread_schedule_prev_saved(&sleeper);
    assert(sleeper.sched_vruntime == before + 63); /* BLOCKED outgoing: exactly once */
    child.state = THREAD_TERMINATED;
    thread_block_with_timeout(2, 10); assert(child.state == THREAD_TERMINATED);
    sleeper.idle = 1; sleeper.state = THREAD_RUNNING; before = sleeper.sched_vruntime;
    thread_sleep(1); assert(sleeper.sched_vruntime == before);
    puts("PASS: short-sleep workers cannot retain zero-runtime credit and starve READY fork children");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sched-block-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-sign-compare", "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
