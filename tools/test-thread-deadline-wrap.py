#!/usr/bin/env python3
"""Exercise the scheduler's actual deadline helper at 32-bit wraparound."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()
start = source.index("static inline int thread_time_after_eq32(")
end = source.index("\nvoid thread_wake_expired_timeouts(", start)
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
static uint64_t now_ms;
static uint64_t pit_get_time_ms(void) { return now_ms; }
''' + source[start:end] + r'''
int main(void) {
    now_ms = UINT32_MAX - 1u;
    uint32_t deadline = thread_deadline_ms(2);
    assert(deadline != 0); /* zero is the no-timeout sentinel */
    assert(!thread_time_after_eq32((uint32_t)now_ms, deadline));
    assert(thread_time_after_eq32(1, deadline));
    now_ms = 100;
    assert(thread_deadline_ms(2) == 102);
    assert(thread_deadline_ms(0) == 101);
    puts("PASS: wrapped scheduler deadline remains wakeable");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-deadline-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
