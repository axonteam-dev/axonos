#!/usr/bin/env python3
"""Exercise AF_UNIX datagram and seqpacket queues, including udev control."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
types = source[source.index("typedef struct unix_dgram_msg {"):
               source.index("} unix_dgram_pair_t;") + len("} unix_dgram_pair_t;")]
addresses = source[source.index("static int unix_sockaddr_path_from_user("):
                   source.index("static void unix_ensure_parent_dirs(")]
helpers = source[source.index("static void unix_dgram_pair_put("):
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
    int unix_dgram_named, connected, unix_peer_path_len, unix_peer_abstract;
    char unix_peer_path[108];
    int unix_domain_stub, unix_bound, type_base, unix_abstract, unix_path_len;
    int unix_passcred;
    char unix_path[108];
} ksock_net_t;
#define KSOCK_REGISTRY_MAX 8
#define SOCK_DGRAM_LOCAL 2
#define SOCK_SEQPACKET_LOCAL 5
#define AF_UNIX_LOCAL 1
static ksock_net_t *g_ksock_registry[KSOCK_REGISTRY_MAX];
static spinlock_t g_ksock_registry_lock;
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
''' + addresses + helpers + r'''
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

    /* Bind uses sizeof(sockaddr_un); sd_notify uses only the path length.
     * Both must resolve to the same endpoint, independent of trailing bytes. */
    struct { uint16_t family; char path[108]; } addr = {.family = AF_UNIX_LOCAL};
    strcpy(addr.path, "/run/systemd/notify");
    unix_dgram_pair_t *inbox = calloc(1, sizeof(*inbox));
    assert(inbox);
    inbox->refs = 1;
    ksock_net_t notify = {.unix_dgram = inbox, .unix_dgram_named = 1,
        .unix_domain_stub = 1, .unix_bound = 1, .type_base = SOCK_DGRAM_LOCAL,
        .nonblock = 1};
    assert(unix_sockaddr_path_from_user(&addr, sizeof(addr), notify.unix_path,
        sizeof(notify.unix_path), &notify.unix_path_len, &notify.unix_abstract) == 0);
    assert(notify.unix_path_len == (int)strlen(addr.path) + 1);
    g_ksock_registry[0] = &notify;
    unix_dgram_pair_t outbox = {.refs = 1};
    ksock_net_t client = {.unix_dgram = &outbox, .unix_dgram_named = 1, .nonblock = 1};
    assert(!client.connected);
    assert(unix_dgram_send(&client, "x", 1, 0, &thread, 1) == -ENOTCONN);
    assert(unix_dgram_send_address(&client, "READY=1", 7, 0, &thread, 1,
        &addr, 2 + strlen(addr.path)) == 7);
    assert(inbox->refs == 1 && inbox->queued_messages[1] == 1);
    assert(unix_dgram_recv_kernel(&notify, buf, sizeof(buf), 0,
        &copied, &full, creds) == 0);
    assert(copied == 7 && memcmp(buf, "READY=1", 7) == 0);
    assert(creds[0] == 17 && creds[1] == 100 && creds[2] == 200);
    assert(!client.connected); /* sendto must not change connect state */
    assert(unix_dgram_read_to_user(&notify, buf, sizeof(buf), 0) == -EAGAIN);

    /* Connected datagrams use a peer name separate from their local name. */
    client.connected = 1;
    memcpy(client.unix_peer_path, notify.unix_path, sizeof(client.unix_peer_path));
    client.unix_peer_path_len = notify.unix_path_len;
    assert(unix_dgram_send(&client, "WATCHDOG", 8, 0, &thread, 1) == 8);
    assert(outbox.queued_messages[0] == 0 && outbox.queued_messages[1] == 0);
    assert(unix_dgram_read_to_user(&notify, buf, sizeof(buf), 0) == 8);
    assert(memcmp(buf, "WATCHDOG", 8) == 0);
    assert(unix_dgram_send_address(&client, "x", 65537, 0, &thread, 1,
        &addr, sizeof(addr)) == -EMSGSIZE);
    for (int i = 0; i < 64; i++)
        assert(unix_dgram_send_address(&client, "x", 1, 0, &thread, 1,
            &addr, sizeof(addr)) == 1);
    assert(unix_dgram_send_address(&client, "x", 1, 0, &thread, 1,
        &addr, sizeof(addr)) == -EAGAIN);

    /* A sender's pin survives endpoint close until it releases the queue. */
    int receiver_end = -1;
    unix_dgram_pair_t *pinned = unix_dgram_lookup(notify.unix_path,
        notify.unix_path_len, 0, &receiver_end);
    assert(pinned == inbox && receiver_end == 0 && inbox->refs == 2);
    g_ksock_registry[0] = NULL;
    inbox->closed[0] = 1;
    unix_dgram_pair_put(inbox);
    assert(unix_dgram_queue_send(pinned, 1, "x", 1, 0, &thread, 1) == -EPIPE);
    unix_dgram_pair_put(pinned); /* frees pending messages as well */
    assert(unix_dgram_send_address(&client, "x", 1, 0, &thread, 1,
        &addr, sizeof(addr)) == -ECONNREFUSED);

    /* udev control uses connected SOCK_SEQPACKET and requires per-message creds. */
    unix_dgram_pair_t seqpacket_pair = {.refs = 2};
    ksock_net_t udev_client = {.unix_dgram = &seqpacket_pair, .unix_end = 0,
        .type_base = SOCK_SEQPACKET_LOCAL, .connected = 1};
    ksock_net_t udev_server = {.unix_dgram = &seqpacket_pair, .unix_end = 1,
        .type_base = SOCK_SEQPACKET_LOCAL, .connected = 1, .unix_passcred = 1};
    struct udev_ctrl_wire {
        char version[16];
        uint32_t magic;
        uint32_t type;
        char value[256];
    } ctrl_wire = {.version = "udev-257", .magic = 0xdead1dea, .type = 7};
    assert(sizeof(ctrl_wire) == 280); /* systemd UDEV_CTRL_PING wire size */
    assert(unix_dgram_send(&udev_client, &ctrl_wire, sizeof(ctrl_wire),
                           0, &thread, 1) == (ssize_t)sizeof(ctrl_wire));
    char ctrl_buf[sizeof(ctrl_wire)] = {0};
    assert(unix_dgram_recv_kernel(&udev_server, ctrl_buf, sizeof(ctrl_buf), 0,
                                  &copied, &full, creds) == 0);
    assert(copied == sizeof(ctrl_wire) && full == sizeof(ctrl_wire));
    assert(memcmp(ctrl_buf, &ctrl_wire, sizeof(ctrl_wire)) == 0);
    assert(creds[0] == 17 && creds[1] == 100 && creds[2] == 200);
    assert(seqpacket_pair.queued_messages[0] == 0);

    /* Abstract names preserve embedded NULs and their exact lengths. */
    char name[108];
    int plen, abstract;
    memset(addr.path, 0, sizeof(addr.path));
    memcpy(addr.path + 1, "a\0b", 3);
    assert(unix_sockaddr_path_from_user(&addr, 6, name, sizeof(name),
        &plen, &abstract) == 0);
    assert(abstract && plen == 4 && memcmp(name, "\0a\0b", 4) == 0);
    puts("PASS: AF_UNIX datagram/seqpacket queues, credentials, boundaries, peek, backpressure, close");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-unix-dgram-", dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Keep the syscall paths wired to the message queue and preserve the listener's
# socket type on accepted SOCK_SEQPACKET connections.
connect_start = source.index("case 42: { /* connect */")
connect = source[connect_start:source.index("case 51: { /* getsockname */", connect_start)]
assert "s->type_base != listener->type_base" in connect
assert "srv->type_base = listener->type_base;" in connect
assert "srv->unix_dgram = pair;" in connect
assert "s->unix_dgram = pair;" in connect

socketpair = source[source.index("case 53: { /* socketpair"):source.index("case SYS_pipe:")]
assert "type_base != SOCK_SEQPACKET_LOCAL" in socketpair
assert "type_base == SOCK_SEQPACKET_LOCAL" in socketpair

sendto = source[source.index("case 44: { /* sendto */"):source.index("case 45: { /* recvfrom */")]
sendmsg = source[source.index("case 46: { /* sendmsg -> map to sendto for first iov */"):source.index("case 307: { /* sendmmsg")]
recvmsg_start = source.index("case 47: { /* recvmsg */")
recvmsg = source[recvmsg_start:source.index("case 299: { /* recvmmsg", recvmsg_start)]
assert "if (s->unix_dgram)" in sendto and "unix_dgram_send_address" in sendto
assert "if (s->unix_dgram)" in sendmsg and "unix_dgram_send_address" in sendmsg
assert "if (s->unix_dgram)" in recvmsg and "s->unix_passcred" in recvmsg

accept_start = source.index("case 43:  /* accept */")
accept = source[accept_start:source.index("case 42: { /* connect */", accept_start)]
assert "(int)a4" in accept and "SOCK_CLOEXEC_LINUX" in accept
assert "accept_flags & O_NONBLOCK_LINUX" in accept
assert "accepted->nonblock = 1;" in accept
assert "af->flags |= O_NONBLOCK_LINUX;" in accept
assert "fd_cloexec[nfd] = 1;" in accept

socket_start = source.index("case SYS_socket: { /* socket(domain, type, protocol) */")
socket = source[socket_start:source.index("case SYS_bind:", socket_start)]
assert "(type & SOCK_CLOEXEC_LINUX)" in socket
