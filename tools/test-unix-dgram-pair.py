#!/usr/bin/env python3
"""Exercise AF_UNIX datagram-pair message boundaries and credentials."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
types = source[source.index("typedef struct unix_dgram_msg {"):
               source.index("} unix_dgram_pair_t;") + len("} unix_dgram_pair_t;")]
helpers = source[source.index("static ssize_t unix_dgram_send("):
                 source.index("static size_t unix_stream_avail_to_read(")]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef struct { int lock; } spinlock_t;
typedef struct { uint64_t pid; } process_t;
typedef struct { process_t *process; uint64_t tid; uint32_t euid, egid; } thread_t;
''' + types + r'''
typedef struct {
    unix_dgram_pair_t *unix_dgram;
    int unix_end, nonblock;
} ksock_net_t;
#define kmalloc malloc
#define kfree free
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(!lock->lock); lock->lock = 1; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags; assert(lock->lock); lock->lock = 0;
}
static int user_range_ok(const void *ptr, size_t len) { return ptr != NULL || len == 0; }
static int copy_from_user_raw(void *out, const void *in, size_t len) {
    memcpy(out, in, len); return 0;
}
static int copy_to_user_safe(void *out, const void *in, size_t len) {
    memcpy(out, in, len); return 0;
}
static int thread_has_interrupt_signal(thread_t *t) { (void)t; return 0; }
static void thread_sleep(int ms) { (void)ms; assert(0 && "unexpected blocking wait"); }
''' + helpers + r'''
int main(void) {
    unix_dgram_pair_t pair = {.refs = 2};
    ksock_net_t sender = {.unix_dgram = &pair, .unix_end = 0, .nonblock = 1};
    ksock_net_t receiver = {.unix_dgram = &pair, .unix_end = 1, .nonblock = 1};
    process_t proc = {.pid = 17};
    thread_t thread = {.process = &proc, .euid = 100, .egid = 200};
    assert(unix_dgram_send(&sender, "abc", 3, 1, &thread, 1) == 3);
    assert(unix_dgram_send(&sender, "12345", 5, 0, &thread, 1) == 5);
    char buf[8] = {0};
    size_t copied = 0, full = 0;
    uint32_t creds[3] = {0};
    assert(unix_dgram_recv_kernel(&receiver, buf, 2, 0, &copied, &full, creds) == 0);
    assert(copied == 2 && full == 3 && memcmp(buf, "ab", 2) == 0);
    assert(creds[0] == 17 && creds[1] == 100 && creds[2] == 200);
    assert(unix_dgram_read_to_user(&receiver, buf, 5, 0) == 5);
    assert(memcmp(buf, "12345", 5) == 0);
    assert(unix_dgram_send(&sender, "XYZ", 3, 0, &thread, 1) == 3);
    assert(unix_dgram_recv_kernel(&receiver, buf, sizeof(buf), 0x2, &copied, &full, creds) == 0);
    assert(copied == 3 && pair.queued_messages[0] == 1);
    assert(unix_dgram_read_to_user(&receiver, buf, sizeof(buf), 0) == 3);
    assert(memcmp(buf, "XYZ", 3) == 0 && pair.queued_messages[0] == 0);
    assert(unix_dgram_read_to_user(&receiver, buf, sizeof(buf), 0) == -EAGAIN);
    pair.closed[1] = 1;
    assert(unix_dgram_send(&sender, "x", 1, 0, &thread, 1) == -EPIPE);
    puts("PASS: AF_UNIX datagram boundaries, peek, credentials, and close");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-unix-dgram-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
