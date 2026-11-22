#!/usr/bin/env python3
"""Netlink sockets remain open and block (or return EAGAIN) after a dump."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int netlink_wait_readable(")
body = source[start:source.index("\n}\n", start) + 3]
start = source.index("if ((events & POLLIN_K) && s->sock_domain == AF_NETLINK_LOCAL)")
poll = source[start:source.index("} else if (s->unix_domain_stub)", start)]
assert "POLLHUP_K" not in poll
assert "EOF after dump" not in source
assert source.count("netlink_wait_readable(") >= 4

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
typedef struct { int interrupted; } thread_t;
typedef struct { int nonblock, route_count; size_t nl_rx_off, nl_rx_len; } ksock_net_t;
static ksock_net_t *asleep;
static int sleeps;
static int netlink_route_event_peek(ksock_net_t *s, void *event, int consume) {
    (void)event; (void)consume; return s->route_count > 0;
}
static int thread_has_interrupt_signal(thread_t *t) { return t && t->interrupted; }
static void thread_sleep(int n) { assert(n == 1); sleeps++; asleep->route_count = 1; }
''' + body + r'''
int main(void) {
    thread_t t = {0};
    ksock_net_t s = {.nl_rx_off = 64, .nl_rx_len = 64};
    asleep = &s;
    assert(netlink_wait_readable(&t, &s, 0x40) == -EAGAIN);
    s.nonblock = 1;
    assert(netlink_wait_readable(&t, &s, 0) == -EAGAIN);
    s.nonblock = 0;
    t.interrupted = 1;
    assert(netlink_wait_readable(&t, &s, 0) == -EINTR);
    t.interrupted = 0;
    assert(netlink_wait_readable(&t, &s, 0) == 0 && sleeps == 1);
    s.route_count = 0; s.nl_rx_off = 0;
    assert(netlink_wait_readable(&t, &s, 0x40) == 0);
    puts("PASS: drained netlink stays open; readiness, EAGAIN and blocking semantics");
}
'''

with tempfile.TemporaryDirectory(prefix="axonos-netlink-ready-", dir="/tmp/opencode") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(path / "test.c"), "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
