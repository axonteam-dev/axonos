#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int (*net_tcp_send_l4_fn)(void *context, uint32_t dst_ip_be, uint8_t proto,
                                  const void *l4, size_t l4_len);
typedef int (*net_tcp_recv_frame_fn)(void *context, void *buf, size_t cap);
typedef uint64_t (*net_tcp_time_ms_fn)(void);
typedef void (*net_tcp_yield_fn)(void *context);
/* Shared RX queue: put back a frame that does not belong to this TCP connection (Linux: other sockets still see it). */
typedef void (*net_tcp_return_frame_fn)(const void *frame, size_t n);

typedef struct {
    void *context;
    uint32_t local_ip_be;
    net_tcp_send_l4_fn send_l4;
    net_tcp_recv_frame_fn recv_frame;
    net_tcp_time_ms_fn time_ms;
    net_tcp_yield_fn yield;
    net_tcp_return_frame_fn return_frame;
} net_tcp_ops_t;

typedef struct {
    int used;
    int established;
    int connect_pending; /* nonblocking connect: SYN sent, awaiting SYN-ACK */
    int connect_peer_pkts; /* RX TCP segments from peer during connect (debug) */
    int connect_refused; /* valid RST while connecting: SO_ERROR/errno = ECONNREFUSED */
    uint64_t connect_syn_ms; /* last SYN (re)transmit time for nonblocking poll */
    int peer_fin;
    int peer_fin_pending; /* FIN seen but rcv_nxt has not reached fin seq yet */
    uint32_t peer_fin_seq; /* seq of FIN (after any payload on that segment) */
    int peer_rst;
    uint32_t dst_ip_be;
    uint16_t dst_port;
    uint16_t src_port;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t syn_isn;    /* initial seq for outbound SYN (connect handshake) */
    uint32_t rcv_nxt;
    /* Bigger receive window for HTTP downloads; 8 KiB caused frequent sender stalls. */
    uint8_t rx_buf[65536];
    size_t rx_len;
    /*
     * Bounded selective reassembly queue. A single saved segment cannot
     * represent normal VMware/NAT reordering and used to silently lose tails
     * when an in-order retransmit overlapped the saved segment.
     */
#define NET_TCP_OOO_SLOTS 16
#define NET_TCP_OOO_BYTES 1600
    uint8_t ooo_buf[NET_TCP_OOO_SLOTS][NET_TCP_OOO_BYTES];
    size_t ooo_len[NET_TCP_OOO_SLOTS];
    uint32_t ooo_seq[NET_TCP_OOO_SLOTS];
    uint8_t ooo_slot_valid[NET_TCP_OOO_SLOTS];
    int ooo_valid; /* number of occupied slots */
    /* Server path: L2 address learned from the client's SYN (avoid ARP before SYN-ACK). */
    uint8_t peer_mac[6];
    int peer_mac_valid;
} net_tcp_conn_t;

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms);
/* Inbound SYN (server): reply SYN+ACK and seed connection state. Returns 0 on success. */
int net_tcp_server_reply_syn(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t client_seq);
/* Inbound ACK completing server handshake. Returns 0 when established. */
int net_tcp_server_complete_ack(net_tcp_conn_t *c, uint32_t ack);
/* Resend SYN+ACK for a half-open server connection (SYN retransmit from client). */
int net_tcp_server_resend_synack(net_tcp_conn_t *c, const net_tcp_ops_t *ops);
/* Finish connect_pending (0=established, -1=still pending, -2=failed/timeout). */
int net_tcp_connect_poll(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms);
int net_tcp_send(net_tcp_conn_t *c, const net_tcp_ops_t *ops, const uint8_t *data, size_t len, uint32_t timeout_ms);
/* Wait until all sent bytes are ACKed (needed before TLS read after Client Finished). */
int net_tcp_flush_tx(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms);
int net_tcp_recv(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t *out, size_t cap, uint32_t timeout_ms);
int net_tcp_close(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms);
int net_tcp_service(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int budget);
/* Tell peer receive window opened after application read() drains rx_buf. */
int net_tcp_window_update(net_tcp_conn_t *c, const net_tcp_ops_t *ops);
