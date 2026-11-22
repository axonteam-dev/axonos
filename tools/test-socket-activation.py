#!/usr/bin/env python3
"""Compile the actual getsockopt dispatcher used by sd_is_socket activation."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
recvmsg = source[source.index("case 47: { /* recvmsg"):
                 source.index("case 299: { /* recvmmsg", source.index("case 47: { /* recvmsg"))]
assert "m.msg_controllen = 0;" in recvmsg
assert "Got unexpected auxiliary data" not in source
handler = source[source.index("        case 55: { /* getsockopt */"):
                 source.index("        case 44: { /* sendto */")]
fixture = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
typedef struct { uint64_t tid; } thread_t;
typedef struct {
    int type_base, sock_domain, protocol, dns_tcp_udp_bridge;
    int unix_listening, tcp_listening, ipv6_only;
    uint32_t peer_cred_pid, peer_cred_uid, peer_cred_gid;
    int peer_cred_valid;
    struct { int connect_pending, connect_timed_out, connect_refused, peer_rst; } tcp;
} ksock_net_t;
#define SOCK_STREAM_LOCAL SOCK_STREAM
#define AF_UNIX_LOCAL AF_UNIX
#define IPPROTO_TCP_LOCAL 6
static thread_t current = {.tid = 7};
static ksock_net_t socket_state;
static thread_t *thread_get_current_user(void) { return &current; }
static thread_t *thread_current(void) { return &current; }
static int socket_file_get(thread_t *t, int fd, ksock_net_t **out) {
    (void)t;
    if (fd != 4) return 0;
    *out = &socket_state;
    return 1;
}
static int user_range_ok(const void *p, size_t n) { return p || !n; }
static int copy_from_user_raw(void *dst, const void *src, size_t n) {
    if (!src) return -1;
    memcpy(dst, src, n); return 0;
}
static int copy_to_user_safe(void *dst, const void *src, size_t n) {
    if (!dst) return -1;
    memcpy(dst, src, n); return 0;
}
static uint64_t ret_err(int n) { return (uint64_t)-(int64_t)n; }
static uint64_t get_option(uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5) {
    switch (55) {
''' + handler + r'''
    }
    return ret_err(ENOSYS);
}
static int option(int name) {
    int value = -1;
    uint32_t len = sizeof(value);
    assert(get_option(4, SOL_SOCKET, name, (uintptr_t)&value, (uintptr_t)&len) == 0);
    assert(len == sizeof(value));
    return value;
}
int main(void) {
    socket_state.sock_domain = AF_UNIX;
    socket_state.type_base = SOCK_STREAM;
    socket_state.unix_listening = 1;
    assert(option(SO_TYPE) == SOCK_STREAM);
    assert(option(SO_DOMAIN) == AF_UNIX);
    assert(option(SO_PROTOCOL) == 0);
    assert(option(SO_ACCEPTCONN) == 1); /* journald stdout activation fd */
    socket_state.peer_cred_valid = 1;
    socket_state.peer_cred_pid = 27;
    socket_state.peer_cred_uid = 1001;
    socket_state.peer_cred_gid = 1002;
    uint32_t peer[3] = {0};
    uint32_t peer_len = sizeof(peer);
    assert(get_option(4, SOL_SOCKET, SO_PEERCRED, (uintptr_t)peer,
                      (uintptr_t)&peer_len) == 0);
    assert(peer_len == sizeof(peer) && peer[0] == 27 &&
           peer[1] == 1001 && peer[2] == 1002);
    socket_state.unix_listening = 0;
    assert(option(SO_ACCEPTCONN) == 0);
    socket_state.type_base = SOCK_DGRAM;
    assert(option(SO_TYPE) == SOCK_DGRAM);
    assert(option(SO_ACCEPTCONN) == 0); /* journal and notify datagrams */
    socket_state.sock_domain = AF_INET;
    socket_state.type_base = SOCK_STREAM;
    socket_state.protocol = IPPROTO_TCP_LOCAL;
    socket_state.tcp_listening = 1;
    assert(option(SO_ACCEPTCONN) == 1);
    assert(option(SO_PROTOCOL) == IPPROTO_TCP_LOCAL);
    assert((int64_t)get_option(99, SOL_SOCKET, SO_TYPE, 0, 0) == -EBADF);
    puts("PASS: socket activation reports listening state, type, domain and protocol");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-socket-activation-",
                                 dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
