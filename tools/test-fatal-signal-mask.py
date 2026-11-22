#!/usr/bin/env python3
"""Host regression for default-fatal process signals blocked by all threads."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "core/process.c").read_text()
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("int process_signal_has_unblocked_thread(")
end = source.index("\nint process_signal_targets(", start)
helper = source[start:end]
assert "process_signal_dfl(p, sig) &&\n                        process_signal_has_unblocked_thread(p, sig)" in dispatch

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define THREAD_TERMINATED 3
typedef struct process { int unused; } process_t;
typedef struct thread {
    process_t *process;
    int state;
    uint64_t saved_sig_mask;
} thread_t;
static thread_t *threads[4];
static int thread_get_count(void) { return 4; }
static thread_t *thread_get_by_index(int i) { return threads[i]; }
''' + helper + r'''
int main(void) {
    process_t victim = {0}, other = {0};
    uint64_t term = 1ULL << (15 - 1);
    thread_t leader = {&victim, 1, term};
    thread_t worker = {&victim, 1, term};
    thread_t unrelated = {&other, 1, 0};
    threads[0] = &leader; threads[1] = &worker; threads[2] = &unrelated;
    assert(!process_signal_has_unblocked_thread(&victim, 15));
    worker.saved_sig_mask = 0;
    assert(process_signal_has_unblocked_thread(&victim, 15));
    worker.state = THREAD_TERMINATED;
    assert(!process_signal_has_unblocked_thread(&victim, 15));
    leader.saved_sig_mask = 0;
    assert(process_signal_has_unblocked_thread(&victim, 15));
    assert(!process_signal_has_unblocked_thread(&victim, 0));
    puts("PASS: default-fatal signal respects masks of live target threads");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-fatal-mask-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
