#!/usr/bin/env python3
"""Check tgkill resolves Linux task IDs rather than kernel scheduler slots."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
syscalls = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
process_source = (root / "core/process.c").read_text()


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


linux_task_tid = function(syscalls, "static uint64_t linux_task_tid(const thread_t *task) {")
find_target = function(syscalls, "static thread_t *syscall_find_tgkill_target(int tgid, int tid) {")
set_pending = function(syscalls, "static void thread_set_pending_signal(thread_t *t, int signum) {")
process_pid = function(process_source, "uint64_t process_pid(const thread_t *thread) {")
tgkill_case = syscalls[syscalls.index("case SYS_tgkill:"):]
tgkill_case = tgkill_case[:tgkill_case.index("case SYS_sched_yield:")]
assert "syscall_find_tgkill_target(tgid, tid)" in tgkill_case
assert "thread_get(tid)" not in tgkill_case

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#define THREAD_TERMINATED 3
#define THREAD_BLOCKED 2
#define THREAD_SLEEPING 4
typedef struct thread thread_t;
typedef struct process {
    uint64_t pid;
    thread_t *leader;
} process_t;
struct thread {
    uint64_t tid, pending_signals;
    int state, ring;
    process_t *process;
};
static thread_t *threads[8];
static int thread_count;
static int unblocked_tid;
static int thread_get_count(void) { return thread_count; }
static thread_t *thread_get_by_index(int i) {
    return i >= 0 && i < thread_count ? threads[i] : NULL;
}
static void thread_unblock(int tid) { unblocked_tid = tid; }
''' + process_pid + linux_task_tid + find_target + set_pending + r'''
int main(void) {
    process_t init = {.pid = 1};
    process_t daemon = {.pid = 33};
    thread_t idle = {.tid = 1, .state = 1, .ring = 0};
    thread_t init_leader = {.tid = 7, .state = 1, .ring = 3, .process = &init};
    thread_t init_worker = {.tid = 8, .state = 1, .ring = 3, .process = &init};
    thread_t daemon_leader = {.tid = 9, .state = 1, .ring = 3, .process = &daemon};
    thread_t dead = {.tid = 10, .state = THREAD_TERMINATED, .ring = 3, .process = &init};
    init.leader = &init_leader;
    daemon.leader = &daemon_leader;
    threads[0] = &idle;
    threads[1] = &init_leader;
    threads[2] = &init_worker;
    threads[3] = &daemon_leader;
    threads[4] = &dead;
    thread_count = 5;

    assert(linux_task_tid(&init_leader) == 1); /* differs from scheduler TID 7 */
    assert(syscall_find_tgkill_target(1, 1) == &init_leader);
    assert(syscall_find_tgkill_target(1, 8) == &init_worker);
    assert(syscall_find_tgkill_target(33, 33) == &daemon_leader);
    assert(syscall_find_tgkill_target(33, 1) == NULL);
    assert(syscall_find_tgkill_target(1, 10) == NULL);

    thread_set_pending_signal(&init_leader, 6); /* SIGABRT from glibc abort() */
    assert(init_leader.pending_signals == (1ULL << 5));
    puts("PASS: tgkill maps Linux leader IDs to live user tasks and queues SIGABRT");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-tgkill-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
