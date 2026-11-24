#!/usr/bin/env python3
"""Exercise TCP receive and cumulative ACKs across the 32-bit wrap."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "net/tcp.c").read_text()

def extract(signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef struct {
    uint32_t snd_una, snd_nxt, rcv_nxt;
    uint8_t *rx_buf;
    size_t rx_cap, rx_len;
} net_tcp_conn_t;
static size_t net_tcp_rx_room(const net_tcp_conn_t *c) {
    return c->rx_cap - c->rx_len;
}
''' + "\n".join(extract(s) for s in (
    "static int tcp_seq_after(",
    "static void tcp_apply_ack(",
    "static size_t tcp_accept_inorder(",
)) + r'''
int main(void) {
    uint8_t buf[32] = {0};
    net_tcp_conn_t c = {.snd_una = 0xfffffffeu, .snd_nxt = 2,
                        .rcv_nxt = 1, .rx_buf = buf, .rx_cap = sizeof(buf)};
    tcp_apply_ack(&c, 0);
    assert(c.snd_una == 0);
    tcp_apply_ack(&c, 3); /* beyond snd_nxt */
    assert(c.snd_una == 0);
    tcp_apply_ack(&c, 2);
    assert(c.snd_una == 2);
    /* Two retransmitted bytes precede the wrap; only "BC" is new. */
    assert(tcp_accept_inorder(&c, 0xffffffffu, (const uint8_t *)"xyBC", 4) == 2);
    assert(c.rcv_nxt == 3 && c.rx_len == 2 && memcmp(buf, "BC", 2) == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-tcp-wrap-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: TCP sequence wrap preserves ACK and overlapping received data")
