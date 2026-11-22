#!/usr/bin/env python3
"""Host regression/turn-count benchmark for the actual scheduler wake helper."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()
start = source.index("static void thread_note_ready_nolock(thread_t *t) {")
end = source.index("\n/* Called from context_switch_with_prev", start)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef enum { THREAD_READY, THREAD_RUNNING, THREAD_BLOCKED,
               THREAD_TERMINATED, THREAD_SLEEPING } thread_state_t;
typedef struct thread {
    thread_state_t state;
    int vfork_waiting, idle;
    uint64_t sched_vruntime;
    uint32_t sched_fifo_seq;
} thread_t;
static thread_t *threads[8];
static int thread_count;
static uint32_t sched_fifo_counter;
static int thread_is_any_idle(const thread_t *t) { return t->idle; }
''' + source[start:end] + r'''
int main(void) {
    thread_t active = { .state = THREAD_RUNNING, .sched_vruntime = 21000000 };
    thread_t sleeper = { .state = THREAD_SLEEPING };
    thread_t idle = { .state = THREAD_RUNNING, .idle = 1 };
    threads[0] = &active; threads[1] = &sleeper; threads[2] = &idle;
    thread_count = 3;
    thread_note_ready_nolock(&sleeper);
    assert(sleeper.state == THREAD_READY);
    assert(sleeper.sched_vruntime == active.sched_vruntime);
    /* At 21 units per turn, the old wake policy gave the sleeper one million
       consecutive selections before the active task could compete. */
    uint64_t old_turns = active.sched_vruntime / 21;
    uint64_t new_turns = (active.sched_vruntime - sleeper.sched_vruntime) / 21;
    assert(old_turns == 1000000 && new_turns == 0);
    sleeper.state = THREAD_BLOCKED; sleeper.sched_vruntime = 22000000;
    thread_note_ready_nolock(&sleeper);
    assert(sleeper.sched_vruntime == 22000000); /* no unearned credit */
    sleeper.state = THREAD_BLOCKED; sleeper.vfork_waiting = 1;
    thread_note_ready_nolock(&sleeper);
    assert(sleeper.state == THREAD_BLOCKED);
    sleeper.vfork_waiting = 0; active.state = THREAD_BLOCKED;
    sleeper.sched_vruntime = 7;
    thread_note_ready_nolock(&sleeper);
    assert(sleeper.sched_vruntime == 7); /* no non-idle runnable floor */
    puts("PASS: wakeup catch-up turns: 1000000 -> 0; state guards preserved");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sched-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
