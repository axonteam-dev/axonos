#!/usr/bin/env python3
"""Exercise the real tty write batching boundary with simulated IRQ flags."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/devfs.c").read_text()
start = source.index('static ssize_t devfs_tty_write_stream(struct devfs_tty *t, const char *s,\n')
body = source[start:source.index('/* Also append written chars', start)]
boundary = body[body.index('        if (i && (i % 64u) == 0) {'):body.index('        /* IRQs stay masked', body.index('        if (i && (i % 64u) == 0) {'))]
program = r'''
#include <assert.h>
#include <stddef.h>
struct tty { int out_lock, cursor_x, cursor_y; } tty, *t = &tty;
static int irq, restores, batches, devfs_active, graphics, idx;
static void acquire_irqsave(int *lock, unsigned long *flags) { *flags = irq; irq = 0; assert(!*lock); *lock = 1; }
static void release_irqrestore(int *lock, unsigned long flags) { assert(*lock && !irq); *lock = 0; irq = flags; restores++; if (restores == 1) devfs_active = 1; }
static int video_kd_graphics(void) { return graphics; }
static void console_begin_tty_batch(void) { batches++; }
static void console_end_tty_batch(void) { batches--; }
static void console_set_cursor(int x, int y) { (void)x; (void)y; }
int main(void) {
    int tty_on_vga_batch = 1;
    unsigned long out_flags;
    irq = 1; acquire_irqsave(&t->out_lock, &out_flags); console_begin_tty_batch();
    for (size_t i = 0; i < 130; ++i) {
''' + boundary + r'''
        assert(!irq && t->out_lock);
        if (i == 64) { assert(restores == 1); assert(!tty_on_vga_batch && !batches); }
    }
    assert(restores == 2 && !batches);
    release_irqrestore(&t->out_lock, out_flags);
    assert(irq && restores == 3);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="tty-irq-batch-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: tty writes restore interrupts between bounded batches")
