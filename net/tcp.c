#include <net_tcp.h>
#include <heap.h>
#include <string.h>
#include <klog.h>

extern void klogprintf(const char *fmt, ...);

/* Hot-path RX/TX must not paint the VGA console — that alone made SSH and
 * interactive tools feel multi-second laggy on VMware. Opt in with -DNET_TCP_TRACE=1. */
#ifndef NET_TCP_TRACE
#define NET_TCP_TRACE 0
#endif
#if NET_TCP_TRACE
#define tcp_trace(...) klogprintf(__VA_ARGS__)
#else
#define tcp_trace(...) ((void)0)
#endif

#define ETH_TYPE_IPV4 0x0800
#define IPPROTO_TCP_LOCAL 6

typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t doff_res;
    uint8_t flags;
    uint16_t wnd;
    uint16_t csum;
    uint16_t urg;
} tcp_hdr_t;

static inline uint16_t be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t be32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

static int tcp_seq_after(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

static int tcp_seq_in_window(uint32_t seq, uint32_t rcv_nxt, uint32_t wnd) {
    if (wnd == 0)
        return seq == rcv_nxt;
    uint32_t last = rcv_nxt + wnd - 1u;
    return !tcp_seq_after(rcv_nxt, seq) && !tcp_seq_after(seq, last);
}

static void tcp_apply_ack(net_tcp_conn_t *c, uint32_t ack) {
    if (ack == 0)
        return;
    /* RFC 793: an ACK beyond SND.NXT is unacceptable and must never advance
     * SND.UNA. Accept only cumulative ACKs in (SND.UNA, SND.NXT]. */
    if (tcp_seq_after(ack, c->snd_una) && !tcp_seq_after(ack, c->snd_nxt))
        c->snd_una = ack;
}

static uint16_t csum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_ip_be, uint32_t dst_ip_be, const uint8_t *seg, size_t seg_len) {
    uint8_t pseudo[12];
    pseudo[0] = (uint8_t)(src_ip_be >> 24);
    pseudo[1] = (uint8_t)(src_ip_be >> 16);
    pseudo[2] = (uint8_t)(src_ip_be >> 8);
    pseudo[3] = (uint8_t)(src_ip_be);
    pseudo[4] = (uint8_t)(dst_ip_be >> 24);
    pseudo[5] = (uint8_t)(dst_ip_be >> 16);
    pseudo[6] = (uint8_t)(dst_ip_be >> 8);
    pseudo[7] = (uint8_t)(dst_ip_be);
    pseudo[8] = 0;
    pseudo[9] = (uint8_t)IPPROTO_TCP_LOCAL;
    pseudo[10] = (uint8_t)(seg_len >> 8);
    pseudo[11] = (uint8_t)(seg_len);
    uint32_t sum = 0;
    const uint8_t *p = pseudo;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    p = seg;
    size_t len = seg_len;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    uint16_t c = (uint16_t)(~sum);
    return (c == 0) ? 0xFFFFu : c;
}

/* Linux net/ipv4/tcp.c tcp_select_window_scaling(). */
static uint8_t tcp_select_window_scaling(size_t space)
{
    uint8_t w = 0;

    while (w < 14 && (space >> w) > 65535u)
        w++;
    return w;
}

int net_tcp_rx_ensure(net_tcp_conn_t *c)
{
    static const size_t tries[] = {
        256u * 1024u, 128u * 1024u, 64u * 1024u
    };
    unsigned i;

    if (!c)
        return -1;
    if (c->rx_buf && c->rx_cap)
        return 0;
    for (i = 0; i < 3; i++) {
        c->rx_buf = (uint8_t *)kmalloc(tries[i]);
        if (c->rx_buf) {
            c->rx_cap = tries[i];
            c->rx_len = 0;
            c->rcv_wscale = tcp_select_window_scaling(c->rx_cap);
            return 0;
        }
    }
    c->rx_cap = 0;
    c->rcv_wscale = 0;
    return -1;
}

void net_tcp_rx_release(net_tcp_conn_t *c)
{
    if (!c)
        return;
    if (c->rx_buf)
        kfree(c->rx_buf);
    c->rx_buf = NULL;
    c->rx_cap = 0;
    c->rx_len = 0;
}

void net_tcp_rx_orphan(net_tcp_conn_t *c)
{
    if (!c)
        return;
    c->rx_buf = NULL;
    c->rx_cap = 0;
    c->rx_len = 0;
}

void net_tcp_conn_clear(net_tcp_conn_t *c)
{
    if (!c)
        return;
    net_tcp_rx_release(c);
    memset(c, 0, sizeof(*c));
}

/* RFC 7323: MSS + NOP + Window Scale (Linux tcp_syn_options). */
static size_t tcp_syn_options(const net_tcp_conn_t *c, uint8_t *opts, size_t cap)
{
    if (!opts || cap < 8)
        return 0;
    opts[0] = 0x02;
    opts[1] = 0x04;
    opts[2] = 0x05;
    opts[3] = 0xB4; /* MSS 1460 */
    opts[4] = 0x01; /* NOP */
    opts[5] = 0x03; /* TCPOPT_WINDOW */
    opts[6] = 0x03;
    opts[7] = c ? (uint8_t)(c->rcv_wscale & 14) : 0;
    return 8;
}

/* Linux tcp_parse_options(): only WINDOW from SYN/SYN-ACK. */
static void tcp_parse_options(net_tcp_conn_t *c, const uint8_t *opt, size_t opt_len)
{
    size_t i = 0;

    if (!c || !opt)
        return;
    while (i < opt_len) {
        uint8_t kind = opt[i];
        uint8_t len;

        if (kind == 0)
            break;
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1 >= opt_len)
            break;
        len = opt[i + 1];
        if (len < 2 || i + len > opt_len)
            break;
        if (kind == 3 && len == 3)
            c->snd_wscale = (uint8_t)(opt[i + 2] & 14);
        i += len;
    }
}

static int tcp_send_seg_len(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t flags,
    const uint8_t *payload, size_t payload_len, const uint8_t *opts, size_t opt_len) {
    if (!c || !ops || !ops->send_l4) return -1;
    size_t hdr_len = sizeof(tcp_hdr_t) + opt_len;
    size_t seg_len = hdr_len + payload_len;
    if (seg_len > 1500 || (hdr_len % 4u) != 0) return -1;
    uint8_t seg[1600];
    memset(seg, 0, seg_len);
    tcp_hdr_t *th = (tcp_hdr_t *)seg;
    th->src_port = be16(c->src_port);
    th->dst_port = be16(c->dst_port);
    th->seq = be32(c->snd_nxt);
    th->ack = be32(c->rcv_nxt);
    th->doff_res = (uint8_t)((hdr_len / 4u) << 4);
    th->flags = flags;
    {
        /* RFC 7323: header window is sk_rcvbuf remainder >> rcv_wscale. */
        size_t free_rx = net_tcp_rx_room(c);
        if (c->rcv_wscale)
            free_rx >>= c->rcv_wscale;
        uint16_t wnd = (free_rx > 65535u) ? 65535u : (uint16_t)free_rx;
        th->wnd = be16(wnd);
    }
    th->csum = 0;
    th->urg = 0;
    if (opt_len > 0 && opts)
        memcpy(seg + sizeof(tcp_hdr_t), opts, opt_len);
    if (payload_len > 0) memcpy(seg + hdr_len, payload, payload_len);
    {
        uint16_t tc = tcp_checksum(ops->local_ip_be, c->dst_ip_be, seg, seg_len);
        th->csum = be16(tc);
    }
    if (ops->send_l4(ops->context, c->dst_ip_be, IPPROTO_TCP_LOCAL, seg, seg_len) != 0) return -1;
    return 0;
}

static int tcp_send_seg(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t flags, const uint8_t *payload, size_t payload_len) {
    return tcp_send_seg_len(c, ops, flags, payload, payload_len, NULL, 0);
}

static int tcp_send_syn(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    uint8_t opts[8];
    size_t n = tcp_syn_options(c, opts, sizeof(opts));
    return tcp_send_seg_len(c, ops, 0x02u, NULL, 0, opts, n);
}

#define TCP_FRAME_BUF 2048

static void tcp_return_frame(const net_tcp_ops_t *ops, const uint8_t *frame, size_t n) {
    if (ops && ops->return_frame && frame && n > 0)
        (void)ops->return_frame(frame, n);
}

static void tcp_try_merge_ooo(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    for (;;) {
        int best = -1;
        uint32_t best_seq = 0;
        for (int i = 0; i < NET_TCP_OOO_SLOTS; ++i) {
            if (!c->ooo_slot_valid[i] || c->ooo_len[i] == 0)
                continue;
            uint32_t end = c->ooo_seq[i] + (uint32_t)c->ooo_len[i];
            if (!tcp_seq_after(end, c->rcv_nxt)) {
                c->ooo_slot_valid[i] = 0;
                c->ooo_len[i] = 0;
                if (c->ooo_valid > 0) c->ooo_valid--;
                continue;
            }
            if (tcp_seq_after(c->ooo_seq[i], c->rcv_nxt))
                continue;
            if (best < 0 || tcp_seq_after(best_seq, c->ooo_seq[i])) {
                best = i;
                best_seq = c->ooo_seq[i];
            }
        }
        if (best < 0)
            break;
        size_t skip = (size_t)(c->rcv_nxt - c->ooo_seq[best]);
        size_t available = c->ooo_len[best] - skip;
        size_t room = net_tcp_rx_room(c);
        size_t cp = available > room ? room : available;
        if (cp == 0)
            break;
        memcpy(c->rx_buf + c->rx_len, c->ooo_buf[best] + skip, cp);
        c->rx_len += cp;
        c->rcv_nxt += (uint32_t)cp;
        if (cp == available) {
            c->ooo_slot_valid[best] = 0;
            c->ooo_len[best] = 0;
            if (c->ooo_valid > 0) c->ooo_valid--;
        } else {
            size_t consumed = skip + cp;
            memmove(c->ooo_buf[best],
                    c->ooo_buf[best] + consumed,
                    c->ooo_len[best] - consumed);
            c->ooo_len[best] -= consumed;
            c->ooo_seq[best] = c->rcv_nxt;
            break;
        }
    }
    (void)ops;
}

static size_t tcp_accept_inorder(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    size_t accepted = 0;
    if (!c->rx_buf || c->rx_cap == 0)
        return 0;
    if (seq == c->rcv_nxt) {
        size_t room = net_tcp_rx_room(c);
        size_t cp = (payload_len > room) ? room : payload_len;
        if (cp > 0) {
            memcpy(c->rx_buf + c->rx_len, payload, cp);
            c->rx_len += cp;
            accepted = cp;
        }
        /* Advance only over bytes we accepted (never ACK-skipped data). */
        if (payload_len > 0)
            c->rcv_nxt += (uint32_t)cp;
        return accepted;
    } else if (seq < c->rcv_nxt) {
        uint32_t skip_u32 = c->rcv_nxt - seq;
        size_t skip = (size_t)skip_u32;
        if (skip < payload_len) {
            size_t room = net_tcp_rx_room(c);
            size_t tail = payload_len - skip;
            size_t cp = (tail > room) ? room : tail;
            if (cp > 0) {
                memcpy(c->rx_buf + c->rx_len, payload + skip, cp);
                c->rx_len += cp;
                accepted = cp;
            }
        }
        c->rcv_nxt += (uint32_t)accepted;
        return accepted;
    }
    return accepted;
}

static void tcp_try_complete_fin(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !c->peer_fin_pending || c->peer_fin)
        return;
    if (c->rcv_nxt != c->peer_fin_seq)
        return;
    c->peer_fin = 1;
    c->peer_fin_pending = 0;
    c->rcv_nxt++;
    c->established = 0;
    if (ops)
        (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
    tcp_trace("tcp: complete pending fin rcv_nxt=%u\n", (unsigned)c->rcv_nxt);
}

static void tcp_store_ooo(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    if (!c || !payload || payload_len == 0)
        return;
    /* Never truncate: a partial OOO slot would ACK a hole and corrupt streams. */
    if (payload_len > NET_TCP_OOO_BYTES)
        return;
    int slot = -1;
    int farthest = -1;
    for (int i = 0; i < NET_TCP_OOO_SLOTS; ++i) {
        if (!c->ooo_slot_valid[i]) {
            if (slot < 0) slot = i;
            continue;
        }
        if (c->ooo_seq[i] == seq) {
            if (c->ooo_len[i] >= payload_len)
                return;
            slot = i;
            break;
        }
        if (farthest < 0 ||
            tcp_seq_after(c->ooo_seq[i], c->ooo_seq[farthest]))
            farthest = i;
    }
    if (slot < 0 && farthest >= 0 &&
        tcp_seq_after(c->ooo_seq[farthest], seq))
        slot = farthest;
    if (slot >= 0) {
        if (!c->ooo_slot_valid[slot])
            c->ooo_valid++;
        memcpy(c->ooo_buf[slot], payload, payload_len);
        c->ooo_len[slot] = payload_len;
        c->ooo_seq[slot] = seq;
        c->ooo_slot_valid[slot] = 1;
    }
}

int net_tcp_service(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int budget) {
    if (!c || !ops || !ops->recv_frame) return -1;
    uint8_t frame[TCP_FRAME_BUF];
    int got = 0;
    for (int i = 0; i < budget; i++) {
        int n = ops->recv_frame(ops->context, frame, sizeof(frame));
        if (n <= 0) continue;
        if ((size_t)n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const eth_hdr_t *eth = (const eth_hdr_t *)frame;
        if (be16(eth->ethertype) != ETH_TYPE_IPV4) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
        size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
        if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((be16(ip->frag_off) & 0x1FFFu) != 0) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        uint32_t src_ip_be = be32(ip->src);
        uint32_t dst_ip_be = be32(ip->dst);
        if (dst_ip_be != ops->local_ip_be || src_ip_be != c->dst_ip_be) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
        uint16_t sport = be16(th->src_port), dport = be16(th->dst_port);
        if (sport != c->dst_port || dport != c->src_port) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if (c->connect_pending && !c->established)
            c->connect_peer_pkts++;
        uint32_t seq = be32(th->seq);
        uint32_t ack = be32(th->ack);
        size_t doff = (size_t)((th->doff_res >> 4) * 4u);
        if (doff < sizeof(tcp_hdr_t) || doff > 60) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + doff) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        size_t ip_tot = (size_t)be16(ip->total_len);
        if (ip_tot < ihl + doff) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((th->flags & 0x02u) && doff > sizeof(tcp_hdr_t))
            tcp_parse_options(c, (const uint8_t *)th + sizeof(tcp_hdr_t),
                              doff - sizeof(tcp_hdr_t));
        size_t payload_len = ip_tot - ihl - doff;
        size_t frame_pay = (size_t)n - (sizeof(eth_hdr_t) + ihl + doff);
        if (payload_len > frame_pay)
            payload_len = frame_pay;
        const uint8_t *payload = frame + sizeof(eth_hdr_t) + ihl + doff;
        /* Never ACK corrupted bytes into the stream. The sender will
         * retransmit when rcv_nxt does not advance. */
        size_t tcp_len = ip_tot - ihl;
        if (tcp_len > (size_t)n - sizeof(eth_hdr_t) - ihl ||
            tcp_checksum(src_ip_be, dst_ip_be,
                         (const uint8_t *)th, tcp_len) != 0xFFFFu) {
            got = 1;
            continue;
        }

        if (th->flags & 0x04u) {
            int rst_ok = 0;
            if (c->connect_pending && !c->established) {
                if ((th->flags & 0x10u) && ack == c->syn_isn + 1u) {
                    rst_ok = 1;
                    c->connect_refused = 1;
                }
            } else if (c->established) {
                uint32_t wnd = (uint32_t)net_tcp_rx_room(c);
                if (seq == c->rcv_nxt) {
                    rst_ok = 1;
                } else if (tcp_seq_in_window(seq, c->rcv_nxt, wnd)) {
                    /* Linux/RFC5961-style: in-window but non-exact RST gets a challenge ACK. */
                    (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
                    got = 1;
                    continue;
                }
            }
            if (!rst_ok) {
                got = 1;
                continue;
            }
            tcp_trace("tcp: peer rst sport=%u dport=%u\n", (unsigned)sport, (unsigned)dport);
            c->established = 0;
            c->connect_pending = 0;
            c->peer_rst = 1;
            got = 1;
            continue;
        }

        /* Handshake before tcp_apply_ack — stray large ack must not move snd_una early. */
        if ((th->flags & 0x02u) && (th->flags & 0x10u) && !c->established) {
            if (!c->connect_pending || ack != c->syn_isn + 1u) {
                tcp_trace("tcp: ignored syn-ack seq=%u ack=%u syn=%u\n",
                    (unsigned)seq, (unsigned)ack, (unsigned)c->syn_isn);
                got = 1;
                continue;
            }
            tcp_trace("tcp: syn-ack seq=%u ack=%u sport=%u dport=%u\n",
                (unsigned)seq, (unsigned)ack, (unsigned)sport, (unsigned)dport);
            c->rcv_nxt = seq + 1;
            c->snd_una = ack;
            c->snd_nxt = ack;
            c->established = 1;
            c->connect_pending = 0;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
            continue;
        }

        tcp_apply_ack(c, ack);

        /* Pure ACK (no data): cumulative ack for our sends — must not be ignored. */
        if (payload_len == 0 && (th->flags & 0x10u) && !(th->flags & 0x02u) && !(th->flags & 0x01u)) {
            got = 1;
            continue;
        }

        if (payload_len > 0) {
            if (net_tcp_rx_ensure(c) != 0) {
                (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
                got = 1;
                continue;
            }
            size_t before = c->rx_len;
            if (seq == c->rcv_nxt || !tcp_seq_after(seq, c->rcv_nxt)) {
                uint32_t rcv_before = c->rcv_nxt;
                size_t acc = tcp_accept_inorder(c, seq, payload, payload_len);
                /* Frame is already off the NIC — park any unaccepted bytes in
                 * OOO so a full rx_buf cannot permanently lose the tail. */
                if (acc < payload_len && !tcp_seq_after(seq, rcv_before)) {
                    size_t off = (seq == rcv_before)
                        ? acc
                        : (size_t)(rcv_before - seq) + acc;
                    if (off < payload_len)
                        tcp_store_ooo(c, c->rcv_nxt, payload + off, payload_len - off);
                }
                tcp_try_merge_ooo(c, ops);
            } else {
                tcp_store_ooo(c, seq, payload, payload_len);
            }
            if (c->rx_len > before && c->rx_len - before >= 512)
                tcp_trace("tcp: rx +%u total=%u seq=%u\n",
                    (unsigned)(c->rx_len - before), (unsigned)c->rx_len, (unsigned)seq);
            tcp_try_complete_fin(c, ops);
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
        }

        if (th->flags & 0x01u) {
            /* Allow FIN while established OR while draining after prior data. */
            if (!c->established && !c->peer_fin_pending && !c->peer_fin) {
                got = 1;
                continue;
            }
            uint32_t fin_seq = seq + (uint32_t)payload_len;
            tcp_trace("tcp: peer fin seq=%u rcv_nxt=%u\n", (unsigned)fin_seq, (unsigned)c->rcv_nxt);
            if (fin_seq == c->rcv_nxt) {
                c->peer_fin = 1;
                c->peer_fin_pending = 0;
                c->rcv_nxt++;
                c->established = 0;
                (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            } else if (!tcp_seq_after(fin_seq, c->rcv_nxt)) {
                /* Retransmitted FIN already covered by rcv_nxt. ACK only;
                 * do not newly mark a live session as closed. */
                if (c->peer_fin || c->peer_fin_pending)
                    (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            } else {
                /* FIN ahead of a gap / unread payload — remember it. */
                c->peer_fin_pending = 1;
                c->peer_fin_seq = fin_seq;
                (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
                tcp_try_complete_fin(c, ops);
            }
            got = 1;
        }
    }
    return got;
}

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (ops->recv_frame) {
        uint8_t drain[TCP_FRAME_BUF];
        for (int d = 0; d < 64; d++) {
            int dn = ops->recv_frame(ops->context, drain, sizeof(drain));
            if (dn <= 0) break;
            if (ops->return_frame)
                ops->return_frame(drain, (size_t)dn);
        }
    }
    /* Preserve L2 next-hop and sk_rcvbuf; memset used to wipe both. */
    uint8_t saved_mac[6];
    int saved_mac_valid = c->peer_mac_valid;
    uint8_t *saved_rx = c->rx_buf;
    size_t saved_cap = c->rx_cap;
    uint8_t saved_ws = c->rcv_wscale;
    if (saved_mac_valid)
        memcpy(saved_mac, c->peer_mac, 6);
    memset(c, 0, sizeof(*c));
    if (saved_mac_valid) {
        memcpy(c->peer_mac, saved_mac, 6);
        c->peer_mac_valid = 1;
    }
    c->rx_buf = saved_rx;
    c->rx_cap = saved_cap;
    c->rcv_wscale = saved_ws;
    c->rx_len = 0;
    if (net_tcp_rx_ensure(c) != 0)
        return -1;
    c->used = 1;
    c->dst_ip_be = dst_ip_be;
    c->dst_port = dst_port;
    c->src_port = src_port;
    uint32_t isn = (uint32_t)(ops->time_ms() ^ 0x71A9C33Du);
    c->syn_isn = isn;
    c->snd_una = isn;
    c->snd_nxt = isn;
    c->rcv_nxt = 0;
    c->connect_pending = 1; /* before SYN: post_tx_drain must see handshake state */
    if (tcp_send_syn(c, ops) != 0) {
        c->used = 0;
        c->connect_pending = 0;
        return -1;
    }
    c->snd_nxt = isn + 1;
    c->connect_syn_ms = ops->time_ms();
    c->connect_born_ms = c->connect_syn_ms;
    c->connect_timed_out = 0;
    tcp_trace("tcp: syn sent isn=%u sport=%u dport=%u\n",
        (unsigned)isn, (unsigned)c->src_port, (unsigned)c->dst_port);
    if (timeout_ms == 0) {
        (void)net_tcp_service(c, ops, 8);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        if (c->connect_refused && !c->established) {
            c->connect_pending = 0;
            return -3;
        }
        c->connect_pending = 1;
        return 0; /* caller maps to EINPROGRESS */
    }
    for (int y = 0; y < 8; y++) {
        (void)net_tcp_service(c, ops, 16);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        if (c->connect_refused && !c->established) {
            c->connect_pending = 0;
            return -3;
        }
        ops->yield(ops->context);
    }
    return net_tcp_connect_poll(c, ops, timeout_ms);
}

/* Reset control fields and drop sk_rcvbuf (Linux tcp_close / tcp_done). */
void net_tcp_reset(net_tcp_conn_t *c) {
    uint8_t mac[6];
    int mac_ok;
    if (!c)
        return;
    mac_ok = c->peer_mac_valid;
    if (mac_ok)
        memcpy(mac, c->peer_mac, 6);
    net_tcp_rx_release(c);
    c->used = 0;
    c->established = 0;
    c->connect_pending = 0;
    c->connect_peer_pkts = 0;
    c->connect_refused = 0;
    c->connect_timed_out = 0;
    c->connect_syn_ms = 0;
    c->connect_born_ms = 0;
    c->peer_fin = 0;
    c->peer_fin_pending = 0;
    c->peer_fin_seq = 0;
    c->peer_rst = 0;
    c->dst_ip_be = 0;
    c->dst_port = 0;
    c->src_port = 0;
    c->snd_una = 0;
    c->snd_nxt = 0;
    c->syn_isn = 0;
    c->rcv_nxt = 0;
    c->rx_len = 0;
    c->ooo_valid = 0;
    memset(c->ooo_slot_valid, 0, sizeof(c->ooo_slot_valid));
    memset(c->ooo_len, 0, sizeof(c->ooo_len));
    if (mac_ok) {
        memcpy(c->peer_mac, mac, 6);
        c->peer_mac_valid = 1;
    } else {
        memset(c->peer_mac, 0, sizeof(c->peer_mac));
        c->peer_mac_valid = 0;
    }
}

int net_tcp_server_reply_syn(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t client_seq) {
    if (!c || !ops || !ops->time_ms) return -1;
    uint32_t isn = (uint32_t)(ops->time_ms() ^ 0x81A5D77Du);
    uint32_t dst_ip = c->dst_ip_be;
    uint16_t dst_port = c->dst_port;
    uint16_t src_port = c->src_port;
    net_tcp_reset(c);
    c->dst_ip_be = dst_ip;
    c->dst_port = dst_port;
    c->src_port = src_port;
    c->used = 1;
    if (net_tcp_rx_ensure(c) != 0)
        return -1;
    c->syn_isn = isn;
    c->snd_una = isn;
    /* SYN-ACK must carry SEQ=ISN; snd_nxt advances to ISN+1 only after the segment is sent. */
    c->snd_nxt = isn;
    c->rcv_nxt = client_seq + 1u;
    {
        uint8_t opts[8];
        size_t n = tcp_syn_options(c, opts, sizeof(opts));
        if (tcp_send_seg_len(c, ops, 0x12u, NULL, 0, opts, n) != 0)
            return -1;
    }
    c->snd_nxt = isn + 1u;
    return 0;
}

int net_tcp_server_complete_ack(net_tcp_conn_t *c, uint32_t ack) {
    if (!c || !c->used || c->established) return -1;
    /* SYN consumes exactly one sequence number. No TCP option or Ethernet
     * padding contributes to sequence space. */
    if (ack != c->syn_isn + 1u || ack != c->snd_nxt) return -1;
    c->snd_una = ack;
    c->established = 1;
    c->connect_pending = 0;
    return 0;
}

int net_tcp_send_ack(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !ops || !c->used) return -1;
    return tcp_send_seg(c, ops, 0x10u, NULL, 0);
}

int net_tcp_reject_ack(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t ack) {
    if (!c || !ops) return -1;
    /* RFC 793 SYN-RECEIVED: unacceptable ACK is answered with
     * <SEQ=SEG.ACK><CTL=RST>. Do not mutate the half-open state. */
    uint32_t saved = c->snd_nxt;
    c->snd_nxt = ack;
    int rc = tcp_send_seg(c, ops, 0x04u, NULL, 0);
    c->snd_nxt = saved;
    return rc;
}

int net_tcp_server_resend_synack(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !c->used || !ops) return -1;
    uint32_t save_snd = c->snd_nxt;
    c->snd_nxt = c->syn_isn;
    {
        uint8_t opts[8];
        size_t n = tcp_syn_options(c, opts, sizeof(opts));
        int r = tcp_send_seg_len(c, ops, 0x12u, NULL, 0, opts, n);
        if (save_snd > c->syn_isn)
            c->snd_nxt = save_snd;
        return r;
    }
}

static void tcp_rexmit_syn_if_due(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !ops || !ops->time_ms || !c->connect_pending || c->established)
        return;
    uint64_t now = ops->time_ms();
    uint64_t last = c->connect_syn_ms ? c->connect_syn_ms : now;
    if (now - last < 1000)
        return;
    uint32_t save = c->snd_nxt;
    c->snd_nxt = save - 1;
    {
        uint8_t opts[8];
        size_t n = tcp_syn_options(c, opts, sizeof(opts));
        (void)tcp_send_seg_len(c, ops, 0x02u, NULL, 0, opts, n);
    }
    c->snd_nxt = save;
    c->connect_syn_ms = now;
    tcp_trace("tcp: syn rexmit sport=%u\n", (unsigned)c->src_port);
}

int net_tcp_connect_poll(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (c->established) {
        c->connect_pending = 0;
        return 0;
    }
    if (c->connect_refused && !c->established) {
        c->connect_pending = 0;
        return -3;
    }
    if (c->connect_timed_out && !c->established) {
        c->connect_pending = 0;
        return -2;
    }
    if (!c->connect_pending && !c->used) return -1;
    uint64_t start = ops->time_ms();
    if (timeout_ms == 0) {
        /* Nonblocking / select progress: one shot. Never clear connect_pending
         * on "still waiting" — a short wait inside poll/select used to call
         * this with 200ms and then abort the handshake after the first tick.
         * Do abort if the handshake itself has been pending too long: apt's
         * http method uses poll(-1) and otherwise sits at "0% [Working]". */
        enum { NET_TCP_NB_CONNECT_MS = 15000u };
        (void)net_tcp_service(c, ops, 8);
        tcp_rexmit_syn_if_due(c, ops);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        if (c->connect_refused && !c->established) {
            c->connect_pending = 0;
            return -3;
        }
        {
            uint64_t born = c->connect_born_ms ? c->connect_born_ms : start;
            if (start - born >= (uint64_t)NET_TCP_NB_CONNECT_MS) {
                c->connect_pending = 0;
                c->connect_timed_out = 1;
                tcp_trace("tcp: connect poll timeout peer_pkts=%d syn=%u\n",
                    c->connect_peer_pkts, (unsigned)c->syn_isn);
                return -2;
            }
        }
        return -1;
    }
    while ((ops->time_ms() - start) < timeout_ms) {
        ops->yield(ops->context);
        for (int burst = 0; burst < 2; burst++) {
            (void)net_tcp_service(c, ops, 16);
            if (c->established) {
                c->connect_pending = 0;
                return 0;
            }
            if (c->connect_refused && !c->established) {
                c->connect_pending = 0;
                return -3;
            }
        }
        tcp_rexmit_syn_if_due(c, ops);
        for (int r = 0; r < 4; r++)
            (void)net_tcp_service(c, ops, 16);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        if (c->connect_refused && !c->established) {
            c->connect_pending = 0;
            return -3;
        }
    }
    c->connect_pending = 0;
    tcp_trace("tcp: connect give up peer_pkts=%d syn=%u\n",
        c->connect_peer_pkts, (unsigned)c->syn_isn);
    return -2;
}

int net_tcp_send(net_tcp_conn_t *c, const net_tcp_ops_t *ops, const uint8_t *data, size_t len, uint32_t timeout_ms) {
    if (!c || !ops || !data) return -1;
    if (!c->established) return -1;
    (void)timeout_ms;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        /* Ethernet/IPv4/TCP MSS: 1500 - 20 - 20 = 1460. */
        if (chunk > 1460) chunk = 1460;
        uint32_t seq0 = c->snd_nxt;
        if (tcp_send_seg(c, ops, 0x18u, data + off, chunk) != 0) return (off > 0) ? (int)off : -1;
        c->snd_nxt += (uint32_t)chunk;
        /* Do not block until peer ACK here: HTTP servers may reply+close before send() returns. */
        for (int poll = 0; poll < 32; poll++) {
            (void)net_tcp_service(c, ops, 8);
            if (c->snd_una >= seq0 + (uint32_t)chunk)
                break;
            if ((poll & 3) == 3)
                ops->yield(ops->context);
        }
        off += chunk;
    }
    return (int)len;
}

int net_tcp_flush_tx(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (!c->established || c->snd_una >= c->snd_nxt) return 0;
    uint64_t start = ops->time_ms();
    while ((ops->time_ms() - start) < timeout_ms) {
        (void)net_tcp_service(c, ops, 16);
        if (c->snd_una >= c->snd_nxt)
            return 0;
        ops->yield(ops->context);
    }
    return (c->snd_una >= c->snd_nxt) ? 0 : -2;
}

int net_tcp_window_update(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !ops) return -1;
    /* Still advertise window after peer FIN while draining, and while a
     * pending FIN waits on a gap that OOO merge may close. */
    if (!c->established && !c->peer_fin_pending && c->rx_len == 0 && !c->ooo_valid)
        return -1;
    tcp_try_merge_ooo(c, ops);
    tcp_try_complete_fin(c, ops);
    return tcp_send_seg(c, ops, 0x10u, NULL, 0);
}

static void net_tcp_drain_rx(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int max_rounds) {
    for (int r = 0; r < max_rounds; r++) {
        (void)net_tcp_service(c, ops, 16);
        if (c->rx_len > 0)
            break;
    }
}

int net_tcp_recv(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t *out, size_t cap, uint32_t timeout_ms) {
    if (!c || !ops || !out || cap == 0) return -1;
    /* Pull any OOO bytes that fit now that the app may have drained rx_buf. */
    tcp_try_merge_ooo(c, ops);
    tcp_try_complete_fin(c, ops);
    if (c->rx_len > 0) {
        size_t n = (c->rx_len > cap) ? cap : c->rx_len;
        memcpy(out, c->rx_buf, n);
        if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
        c->rx_len -= n;
        tcp_try_merge_ooo(c, ops);
        tcp_try_complete_fin(c, ops);
        (void)net_tcp_window_update(c, ops);
        return (int)n;
    }
    uint64_t start = ops->time_ms();
    uint64_t last_win = start;
    do {
        /* A blocking socket must relinquish the CPU between bounded checks.
         * Thousands of empty recv_frame calls here starved every other BSP
         * userspace task when browsers opened idle speculative connections. */
        net_tcp_drain_rx(c, ops, 1);
        if (c->rx_len > 0) {
            size_t n = (c->rx_len > cap) ? cap : c->rx_len;
            memcpy(out, c->rx_buf, n);
            if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
            c->rx_len -= n;
            (void)net_tcp_window_update(c, ops);
            return (int)n;
        }
        if (c->peer_rst) return -4;
        if (c->peer_fin) return 0;
        uint64_t now = ops->time_ms();
        if (now - last_win >= 50) {
            (void)net_tcp_window_update(c, ops);
            last_win = now;
        }
        if (timeout_ms != 0)
            ops->yield(ops->context);
    } while ((ops->time_ms() - start) < timeout_ms);
    return -2;
}

int net_tcp_close(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!c) return -1;
    if (!c->used) return 0;
    /* Fire-and-forget FIN. Waiting here (and memset of ~170KiB) froze the
     * guest on the first SSH child's exit, so the second client hung in KEX. */
    if (c->established && ops && ops->send_l4)
        (void)tcp_send_seg(c, ops, 0x11u, NULL, 0);
    net_tcp_reset(c);
    return 0;
}
