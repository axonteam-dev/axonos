#!/usr/bin/env python3
"""Exercise the real thread publication helper with concurrent creators."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()
start = source.index("static int thread_publish_new(")
end = source.index("\nstatic thread_t* thread_create_with_state(", start)
create_end = source.index("\nthread_t* thread_create(", end)
create = source[end:create_end]
assert "if (thread_publish_new(t) != 0)" in create
assert "thread_free_resources(t);" in create[create.index("if (thread_publish_new(t) != 0)"):]

program = r'''
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_THREADS 33
#define CREATORS 64
#define THREAD_READY 0
#define THREAD_BLOCKED 2
typedef struct { int state; uint64_t tid; uint32_t sched_fifo_seq; } thread_t;
typedef pthread_mutex_t spinlock_t;
static thread_t *threads[MAX_THREADS];
static int thread_count = 1;
static uint32_t sched_fifo_counter;
static spinlock_t sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static thread_t tasks[CREATORS];
static int results[CREATORS];
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    *flags = 0;
    assert(pthread_mutex_lock(lock) == 0);
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags;
    assert(pthread_mutex_unlock(lock) == 0);
}
''' + source[start:end] + r'''
static void *create(void *arg) {
    intptr_t id = (intptr_t)arg;
    tasks[id].state = id % 2 ? THREAD_READY : THREAD_BLOCKED;
    /* All creators reach publication together, like creators which observed
     * the same free slot before allocating their stacks. */
    int rc = pthread_barrier_wait(&barrier);
    assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    results[id] = thread_publish_new(&tasks[id]);
    return NULL;
}
int main(void) {
    pthread_t workers[CREATORS];
    assert(pthread_barrier_init(&barrier, NULL, CREATORS) == 0);
    for (intptr_t i = 0; i < CREATORS; i++)
        assert(pthread_create(&workers[i], NULL, create, (void *)i) == 0);
    for (int i = 0; i < CREATORS; i++)
        assert(pthread_join(workers[i], NULL) == 0);
    int successes = 0, ready = 0;
    for (int i = 0; i < CREATORS; i++) {
        if (results[i] == 0) {
            successes++;
            assert(tasks[i].tid > 0 && tasks[i].tid < MAX_THREADS);
            assert(threads[tasks[i].tid] == &tasks[i]);
            if (tasks[i].state == THREAD_READY) {
                assert(tasks[i].sched_fifo_seq != 0);
                ready++;
            } else {
                assert(tasks[i].sched_fifo_seq == 0);
            }
        } else {
            assert(results[i] == -1);
        }
    }
    assert(successes == MAX_THREADS - 1);
    assert(thread_count == MAX_THREADS);
    assert(sched_fifo_counter == (uint32_t)ready);
    assert(pthread_barrier_destroy(&barrier) == 0);
    puts("PASS: concurrent thread publication preserves every allocated slot");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-thread-publish-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
