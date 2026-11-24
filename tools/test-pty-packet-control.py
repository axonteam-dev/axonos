#!/usr/bin/env python3
"""Exercise the PTY packet-mode control state and wakeups."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/virt/pty.c").read_text()
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()

def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]

assert "pty_set_packet_mode(f, enabled)" in dispatch
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef int spinlock_t;
#define PTY_NCCS 19
#define TCS_IXON 0x400u
#define PKT_FLUSHREAD 0x01u
#define PKT_FLUSHWRITE 0x02u
#define PKT_NOSTOP 0x10u
#define PKT_DOSTOP 0x20u
struct pty_ring { size_t head, tail, count; spinlock_t lock; int waiters[8], waiters_count; };
struct pty_pair { struct pty_ring m2s, s2m; int packet_mode; uint8_t packet_status;
    uint32_t term_iflag, term_oflag, term_cflag, term_lflag; uint8_t term_cc[PTY_NCCS]; };
struct pty_handle { struct pty_pair *pair; int is_master; };
struct fs_file { struct pty_handle *handle; };
static int wakes;
static struct pty_handle *pty_handle_of(struct fs_file *f) { return f ? f->handle : 0; }
static void acquire_irqsave(spinlock_t *l, unsigned long *flags) { assert(!*l); *l=1; *flags=0; }
static void release_irqrestore(spinlock_t *l, unsigned long flags) { (void)flags; assert(*l); *l=0; }
static void thread_unblock(int tid) { assert(tid == 7); wakes++; }
''' + "".join(function(sig) for sig in (
    "static void pty_ring_wake(", "static void pty_packet_signal(",
    "static void pty_ring_flush(", "int pty_set_packet_mode(",
    "int pty_get_packet_mode(", "void pty_set_termios(", "void pty_flush_input(")) + r'''
int main(void) {
    struct pty_pair p = {0};
    struct pty_handle mh = {&p, 1}, sh = {&p, 0};
    struct fs_file master = {&mh}, slave = {&sh};
    assert(pty_set_packet_mode(&slave, 1) == -1);
    assert(pty_set_packet_mode(&master, 1) == 0 && pty_get_packet_mode(&master) == 1);
    p.term_cc[8] = 021; p.term_cc[9] = 023;
    p.s2m.waiters[0] = 7; p.s2m.waiters_count = 1;
    pty_set_termios(&slave, TCS_IXON, 0, 0, 0, NULL, 0);
    assert(p.packet_status == PKT_DOSTOP && wakes == 1);
    p.packet_status = 0;
    pty_set_termios(&slave, 0, 0, 0, 0, NULL, 0);
    assert(p.packet_status == PKT_NOSTOP);
    p.packet_status = 0; p.m2s.count = 4;
    pty_flush_input(&slave);
    assert(p.m2s.count == 0 && p.packet_status == PKT_FLUSHREAD);
    assert(pty_set_packet_mode(&master, 0) == 0 && pty_get_packet_mode(&master) == 0);
    pty_flush_input(&slave);
    assert(p.packet_status == 0);
    assert(pty_get_packet_mode(&slave) == -1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-pty-packet-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: PTY packet mode emits control notifications and wakes readers")
