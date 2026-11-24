#!/usr/bin/env python3
"""Check that already-running and pinned tasks do not trigger needless preemption."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()
start = source.index("static int thread_ready_on_cpu_nolock(")
end = source.index("\n}\n", start) + 3
reap_start = source.index("static int thread_on_any_cpu_nolock(")
reap_end = source.index("\n}\n", reap_start) + 3
explicit_reap = source[source.index("int thread_reap(int pid) {"):
                       source.index("/* NULL out ->process")]
auto_reap = source[source.index("static int thread_zombie_autoreap_ok("):
                   source.index("/* Reparent living children")]
assert "thread_on_any_cpu_nolock(t)" in explicit_reap
assert "thread_on_any_cpu_nolock(t)" in auto_reap
program = r'''
#include <assert.h>
#define AXON_EXPERIMENTAL_SMP 1
#define SMP_MAX_CPUS 4
enum { THREAD_READY, THREAD_RUNNING, THREAD_BLOCKED };
typedef struct { int state, vfork_waiting, idle, bound_cpu, ring; } thread_t;
static thread_t *current_cpu[SMP_MAX_CPUS];
static int thread_is_any_idle(const thread_t *t) { return t->idle; }
''' + source[start:end] + source[reap_start:reap_end] + r'''
int main(void) {
    thread_t t = {.state = THREAD_RUNNING, .bound_cpu = -1, .ring = 3};
    assert(!thread_ready_on_cpu_nolock(&t, 1));
    t.state = THREAD_READY;
    assert(thread_ready_on_cpu_nolock(&t, 1));
    current_cpu[0] = &t;
    assert(thread_on_any_cpu_nolock(&t));
    assert(!thread_ready_on_cpu_nolock(&t, 1));
    assert(thread_ready_on_cpu_nolock(&t, 0));
    current_cpu[0] = 0;
    assert(!thread_on_any_cpu_nolock(&t));
    t.bound_cpu = 0;
    assert(!thread_ready_on_cpu_nolock(&t, 1));
    assert(thread_ready_on_cpu_nolock(&t, 0));
    t.vfork_waiting = 1;
    assert(!thread_ready_on_cpu_nolock(&t, 0));
    t.vfork_waiting = 0;
    t.idle = 1;
    assert(!thread_ready_on_cpu_nolock(&t, 0));
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-smp-ready-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: ready-task selection respects CPU eligibility")
