#!/usr/bin/env python3
"""Check AF_PACKET FIONREAD sizing used by systemd-networkd's DHCP client."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void packet_sock_enqueue(")
end = source.index("\nstatic int net_l2_payload(", start)
implementation = source[start:end]

# Verify the ioctl dispatch reaches the queue helper, rather than UDP handling.
ioctl_end = source.index("/* Network interface ioctls")
ioctl_start = source.rindex("if (req == FIONREAD)", 0, ioctl_end)
ioctl = source[ioctl_start:ioctl_end]
assert "s->sock_domain == AF_PACKET_LOCAL" in ioctl
assert "packet_sock_next_len(s)" in ioctl

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PACKET_RXQ_DEPTH 4
#define PACKET_RXQ_FRAME 2048
typedef struct {
    uint8_t *packet_rxq;
    size_t *packet_rxq_len;
    int packet_rxq_r, packet_rxq_w, packet_rxq_n, rx_has_pending;
} ksock_net_t;
typedef int spinlock_t;
static spinlock_t g_packet_socks_lock;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    (void)lock; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)lock; (void)flags;
}
''' + implementation + r'''
int main(void) {
    uint8_t storage[PACKET_RXQ_DEPTH * PACKET_RXQ_FRAME] = {0};
    size_t lengths[PACKET_RXQ_DEPTH] = {0};
    uint8_t offer[576] = {0x45}, ack[312] = {0x45}, readback[576];
    ksock_net_t s = {.packet_rxq = storage, .packet_rxq_len = lengths};

    assert(packet_sock_next_len(NULL) == 0);
    assert(packet_sock_next_len(&s) == 0);
    assert(!packet_sock_has_data(&s));
    packet_sock_enqueue(&s, offer, sizeof(offer));
    packet_sock_enqueue(&s, ack, sizeof(ack));
    assert(packet_sock_has_data(&s));
    assert(packet_sock_next_len(&s) == sizeof(offer)); /* not 888 total */
    assert(packet_sock_dequeue(&s, readback, sizeof(readback), 1) == sizeof(offer));
    assert(packet_sock_next_len(&s) == sizeof(offer)); /* MSG_PEEK */
    assert(packet_sock_dequeue(&s, readback, sizeof(readback), 0) == sizeof(offer));
    assert(packet_sock_next_len(&s) == sizeof(ack));
    assert(packet_sock_dequeue(&s, readback, 8, 0) == 8); /* truncation consumes packet */
    assert(packet_sock_next_len(&s) == 0);
    assert(!packet_sock_has_data(&s));
    puts("PASS: AF_PACKET FIONREAD reports the next queued datagram length");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-packet-fionread-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
