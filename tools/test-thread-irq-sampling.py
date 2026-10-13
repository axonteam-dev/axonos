#!/usr/bin/env python3
"""Check timer instruction samples don't overwrite syscall-return state."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "cpu/thread/thread.c").read_text()
start = source.index("void thread_sample_irq_rip(")
body = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef struct {
    int ring;
    uint64_t saved_user_rip, last_irq_user_rip, last_irq_kernel_rip;
} thread_t;
static thread_t *current;
static thread_t *thread_current(void) { return current; }
''' + body + r'''
int main(void) {
    thread_sample_irq_rip(0x1234, 1); /* no current task */
    thread_t user = {.ring = 3, .saved_user_rip = 0x4db378};
    current = &user;
    thread_sample_irq_rip(0x401234, 1);
    thread_sample_irq_rip(0x120034, 0);
    assert(user.last_irq_user_rip == 0x401234);
    assert(user.last_irq_kernel_rip == 0x120034);
    assert(user.saved_user_rip == 0x4db378);
    thread_t kernel = {.ring = 0}; current = &kernel;
    thread_sample_irq_rip(0x110000, 0);
    assert(!kernel.last_irq_kernel_rip && !kernel.last_irq_user_rip);
    puts("PASS: timer RIP samples distinguish user/kernel execution without changing return RIP");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-irq-sample-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
