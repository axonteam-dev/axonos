#include "syscall_internal.h"


typedef struct {
    int active;
    ksock_net_t *listener;
    uint32_t peer_ip_be;
    uint16_t peer_port;
    uint8_t peer_mac[6];
    uint32_t last_synack_tick;
    net_tcp_conn_t tcp;
} tcp_syn_wait_t;

#define TCP_SYN_WAIT_SLOTS 16
static tcp_syn_wait_t g_tcp_syn_wait[TCP_SYN_WAIT_SLOTS];
static spinlock_t g_tcp_syn_wait_lock = { 0 };

static int net_tcp_dispatch_incoming(const uint8_t *frame, size_t n);
ksock_net_t *net_tcp_find_listener(uint16_t port);

/* Parse sockaddr_un from user memory into a kernel path buffer.
   Returns 0 on success, or Linux errno value on failure. */
int unix_sockaddr_path_from_user(const void *addr_u, size_t addrlen, char *out, size_t out_cap, int *is_abstract) {
    if (!out || out_cap == 0) return EFAULT;
    out[0] = '\0';
    if (is_abstract) *is_abstract = 0;
    if (!addr_u || addrlen < 3) return EINVAL; /* family + at least one path byte */
    if (!user_range_ok(addr_u, addrlen)) return EFAULT;
    uint16_t fam = 0;
    if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return EFAULT;
    if (fam != 1u) return EAFNOSUPPORT; /* AF_UNIX */

    size_t path_len = addrlen - sizeof(uint16_t);
    if (path_len >= out_cap) path_len = out_cap - 1;
    if (path_len == 0) return EINVAL;
    if (copy_from_user_raw(out, (const uint8_t *)addr_u + sizeof(uint16_t), path_len) != 0) return EFAULT;
    out[path_len] = '\0';

    if (out[0] == '\0') {
        if (is_abstract) *is_abstract = 1; /* Linux abstract AF_UNIX */
        return 0;
    }
    /* Linux accepts addrlen without trailing NUL in sun_path.
       We already terminate in-kernel buffer above, so treat it as valid. */
    return 0;
}

int unix_acceptq_push(ksock_net_t *listener, struct fs_file *pending_f) {
    if (!listener || !pending_f) return -1;
    unsigned long fl = 0;
    acquire_irqsave(&listener->unix_accept_lock, &fl);
    if (listener->unix_accept_count >= (int)(sizeof(listener->unix_accept_q) / sizeof(listener->unix_accept_q[0]))) {
        release_irqrestore(&listener->unix_accept_lock, fl);
        return -1;
    }
    listener->unix_accept_q[listener->unix_accept_tail] = pending_f;
    listener->unix_accept_tail = (listener->unix_accept_tail + 1) % (int)(sizeof(listener->unix_accept_q) / sizeof(listener->unix_accept_q[0]));
    listener->unix_accept_count++;
    release_irqrestore(&listener->unix_accept_lock, fl);
    return 0;
}

struct fs_file *unix_acceptq_pop(ksock_net_t *listener) {
    if (!listener) return NULL;
    struct fs_file *out = NULL;
    unsigned long fl = 0;
    acquire_irqsave(&listener->unix_accept_lock, &fl);
    if (listener->unix_accept_count > 0) {
        out = listener->unix_accept_q[listener->unix_accept_head];
        listener->unix_accept_q[listener->unix_accept_head] = NULL;
        listener->unix_accept_head = (listener->unix_accept_head + 1) % (int)(sizeof(listener->unix_accept_q) / sizeof(listener->unix_accept_q[0]));
        listener->unix_accept_count--;
    }
    release_irqrestore(&listener->unix_accept_lock, fl);
    return out;
}

ksock_net_t *unix_find_listener_by_path(const char *path) {
    if (!path || !path[0]) return NULL;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *th = thread_get_by_index(ti);
        if (!th) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = th->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (!s->unix_domain_stub || !s->unix_listening || !s->unix_bound) continue;
            if (strncmp(s->unix_path, path, sizeof(s->unix_path)) == 0) return s;
        }
    }
    return NULL;
}

size_t unix_stream_avail_to_read(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 0;
    const unix_stream_conn_t *c = s->unix_conn;
    return (s->unix_end == 0) ? c->q10_count : c->q01_count;
}

size_t unix_stream_avail_to_write(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 0;
    const unix_stream_conn_t *c = s->unix_conn;
    size_t cap = (s->unix_end == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t used = (s->unix_end == 0) ? c->q01_count : c->q10_count;
    if (used >= cap) return 0;
    return cap - used;
}

int unix_stream_peer_closed(const ksock_net_t *s) {
    if (!s || !s->unix_conn) return 1;
    const unix_stream_conn_t *c = s->unix_conn;
    int peer = (s->unix_end == 0) ? 1 : 0;
    return c->closed[peer] ? 1 : 0;
}

ssize_t unix_stream_write_from_user(ksock_net_t *s, const void *buf_u, size_t len) {
    if (!s || !s->unix_conn) return -ENOTCONN;
    if (len == 0) return 0;
    if (!buf_u) return -EINVAL;
    if (!user_range_ok(buf_u, len)) return -EFAULT;
    unix_stream_conn_t *c = s->unix_conn;
    int from = s->unix_end;
    int to = (from == 0) ? 1 : 0;
    uint8_t *q = (from == 0) ? c->q01 : c->q10;
    size_t cap = (from == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t *head = (from == 0) ? &c->q01_head : &c->q10_head;
    size_t *tail = (from == 0) ? &c->q01_tail : &c->q10_tail;
    size_t *count = (from == 0) ? &c->q01_count : &c->q10_count;
    size_t written = 0;
    while (written < len) {
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        if (c->closed[to]) {
            release_irqrestore(&c->lock, fl);
            return written > 0 ? (ssize_t)written : -EPIPE;
        }
        size_t free = cap - *count;
        if (free == 0) {
            release_irqrestore(&c->lock, fl);
            if (s->nonblock) return written > 0 ? (ssize_t)written : -EAGAIN;
            thread_sleep(1);
            continue;
        }
        size_t n = len - written;
        if (n > free) n = free;
        size_t h = *head;
        size_t first = (h + n <= cap) ? n : (cap - h);
        uint8_t tmp[256];
        size_t off = 0;
        while (off < n) {
            size_t ch = n - off;
            if (ch > sizeof(tmp)) ch = sizeof(tmp);
            if (copy_from_user_raw(tmp, (const uint8_t *)buf_u + written + off, ch) != 0) {
                release_irqrestore(&c->lock, fl);
                return written > 0 ? (ssize_t)written : -EFAULT;
            }
            if (off < first) {
                size_t p = first - off;
                if (p > ch) p = ch;
                memcpy(q + h + off, tmp, p);
                if (p < ch) memcpy(q, tmp + p, ch - p);
            } else {
                memcpy(q + (off - first), tmp, ch);
            }
            off += ch;
        }
        *head = (h + n) % cap;
        *count += n;
        (void)tail;
        release_irqrestore(&c->lock, fl);
        written += n;
    }
    return (ssize_t)written;
}

ssize_t unix_stream_read_to_user(ksock_net_t *s, void *buf_u, size_t len, int peek) {
    if (!s || !s->unix_conn) return -ENOTCONN;
    if (len == 0) return 0;
    if (!buf_u) return -EINVAL;
    if (!user_range_ok(buf_u, len)) return -EFAULT;
    unix_stream_conn_t *c = s->unix_conn;
    int from = (s->unix_end == 0) ? 1 : 0;
    uint8_t *q = (from == 0) ? c->q01 : c->q10;
    size_t cap = (from == 0) ? sizeof(c->q01) : sizeof(c->q10);
    size_t *head = (from == 0) ? &c->q01_head : &c->q10_head;
    size_t *tail = (from == 0) ? &c->q01_tail : &c->q10_tail;
    size_t *count = (from == 0) ? &c->q01_count : &c->q10_count;
    (void)head;
    for (;;) {
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        if (*count > 0) {
            size_t n = len;
            if (n > *count) n = *count;
            size_t t = *tail;
            size_t first = (t + n <= cap) ? n : (cap - t);
            uint8_t tmp[256];
            size_t off = 0;
            while (off < n) {
                size_t ch = n - off;
                if (ch > sizeof(tmp)) ch = sizeof(tmp);
                if (off < first) {
                    size_t p = first - off;
                    if (p > ch) p = ch;
                    memcpy(tmp, q + t + off, p);
                    if (p < ch) memcpy(tmp + p, q, ch - p);
                } else {
                    memcpy(tmp, q + (off - first), ch);
                }
                if (copy_to_user_safe((uint8_t *)buf_u + off, tmp, ch) != 0) {
                    release_irqrestore(&c->lock, fl);
                    return -EFAULT;
                }
                off += ch;
            }
            if (!peek) {
                *tail = (t + n) % cap;
                *count -= n;
            }
            release_irqrestore(&c->lock, fl);
            return (ssize_t)n;
        }
        if (c->closed[from]) {
            release_irqrestore(&c->lock, fl);
            return 0;
        }
        release_irqrestore(&c->lock, fl);
        if (s->nonblock) return -EAGAIN;
        thread_sleep(1);
    }
}

static void unix_socket_cleanup(ksock_net_t *s) {
    if (!s) return;
    if (s->unix_listening) {
        struct fs_file *pf = NULL;
        while ((pf = unix_acceptq_pop(s)) != NULL) {
            if (pf->driver_private) {
                ksock_net_t *ps = (ksock_net_t *)pf->driver_private;
                if (ps->unix_conn) {
                    unix_stream_conn_t *c = ps->unix_conn;
                    unsigned long fl = 0;
                    acquire_irqsave(&c->lock, &fl);
                    c->closed[ps->unix_end] = 1;
                    c->refs--;
                    int refs = c->refs;
                    release_irqrestore(&c->lock, fl);
                    if (refs <= 0) kfree(c);
                    ps->unix_conn = NULL;
                }
                kfree(ps);
            }
            if (pf->path) kfree((void *)pf->path);
            kfree(pf);
        }
    }
    if (s->unix_conn) {
        unix_stream_conn_t *c = s->unix_conn;
        unsigned long fl = 0;
        acquire_irqsave(&c->lock, &fl);
        c->closed[s->unix_end] = 1;
        c->refs--;
        int refs = c->refs;
        release_irqrestore(&c->lock, fl);
        if (refs <= 0) kfree(c);
        s->unix_conn = NULL;
    }
}


sysv_shm_seg_t g_sysv_shm[SYSV_SHM_MAX_SEGMENTS];
sysv_shm_attach_t g_sysv_shm_attach[SYSV_SHM_MAX_ATTACH];
int g_sysv_shm_next_id = 1;
uintptr_t g_sysv_shm_next_addr = SYSV_SHM_BASE;
spinlock_t g_sysv_shm_lock = { 0 };

uint64_t sysv_shm_now_secs(void) {
    return pit_get_time_ms() / 1000ull;
}

sysv_shm_seg_t *sysv_shm_find_by_id_nolock(int shmid) {
    for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
        if (g_sysv_shm[i].used && g_sysv_shm[i].shmid == shmid) return &g_sysv_shm[i];
    }
    return NULL;
}

sysv_shm_seg_t *sysv_shm_find_by_key_nolock(int key) {
    for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
        if (g_sysv_shm[i].used && !g_sysv_shm[i].removed && g_sysv_shm[i].key == key) return &g_sysv_shm[i];
    }
    return NULL;
}

uintptr_t sysv_shm_alloc_va_nolock(size_t size) {
    uintptr_t top = (uintptr_t)USER_TLS_BASE;
    uintptr_t addr = (g_sysv_shm_next_addr + 4095u) & ~(uintptr_t)4095u;
    if (addr < SYSV_SHM_BASE) addr = SYSV_SHM_BASE;
    if (addr + size < addr) return 0;
    if (addr + size >= top) return 0;
    g_sysv_shm_next_addr = addr + size;
    return addr;
}

int sysv_shm_register_attach_nolock(int shmid, uint64_t tid, uintptr_t addr, int readonly) {
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used) {
            g_sysv_shm_attach[i].used = 1;
            g_sysv_shm_attach[i].shmid = shmid;
            g_sysv_shm_attach[i].tid = tid;
            g_sysv_shm_attach[i].addr = addr;
            g_sysv_shm_attach[i].readonly = readonly;
            return 0;
        }
    }
    return -1;
}

int sysv_shm_detach_one_by_tid_addr_nolock(uint64_t tid, uintptr_t addr, int *out_shmid) {
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used) continue;
        if (g_sysv_shm_attach[i].tid != tid) continue;
        if (g_sysv_shm_attach[i].addr != addr) continue;
        int shmid = g_sysv_shm_attach[i].shmid;
        g_sysv_shm_attach[i].used = 0;
        if (out_shmid) *out_shmid = shmid;
        return 0;
    }
    return -1;
}

void sysv_shm_cleanup_removed_nolock(sysv_shm_seg_t *seg) {
    if (!seg) return;
    if (seg->removed && seg->nattch == 0) {
        seg->used = 0;
    }
}

void sysv_shm_detach_all_for_tid(uint64_t tid) {
    unsigned long fl = 0;
    acquire_irqsave(&g_sysv_shm_lock, &fl);
    for (int i = 0; i < SYSV_SHM_MAX_ATTACH; i++) {
        if (!g_sysv_shm_attach[i].used || g_sysv_shm_attach[i].tid != tid) continue;
        int shmid = g_sysv_shm_attach[i].shmid;
        g_sysv_shm_attach[i].used = 0;
        sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
        if (seg) {
            if (seg->nattch > 0) seg->nattch--;
            seg->dtime = sysv_shm_now_secs();
            seg->lpid = (uint32_t)tid;
            sysv_shm_cleanup_removed_nolock(seg);
        }
    }
    release_irqrestore(&g_sysv_shm_lock, fl);
}

static inline size_t ksock_rx_pending_cap(void) {
    return (size_t)sizeof(((ksock_net_t *)0)->rx_pending);
}

/* Drop inconsistent pending state (e.g. off > len) before using rx_pending. */
void ksock_rx_pending_normalize(ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return;
    size_t cap = ksock_rx_pending_cap();
    if (s->rx_pending_len > cap || s->rx_pending_off > s->rx_pending_len) {
        s->rx_has_pending = 0;
        s->rx_pending_len = 0;
        s->rx_pending_off = 0;
    }
}

size_t ksock_rx_pending_avail(const ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return 0;
    if (s->rx_pending_off > s->rx_pending_len) return 0;
    return s->rx_pending_len - s->rx_pending_off;
}

void ksock_rx_pending_install(ksock_net_t *s, int rn) {
    if (!s || rn <= 0) return;
    size_t n = (size_t)rn;
    size_t cap = ksock_rx_pending_cap();
    if (n > cap) n = cap;
    s->rx_has_pending = 1;
    s->rx_pending_len = n;
    s->rx_pending_off = 0;
}

net_state_t g_net;
static net_state_t g_net_shadow;
static int g_net_shadow_valid = 0;
static volatile int g_net_redhcp_pending = 0;

/* ---------- RX pump: answer ARP/ICMP and queue everything else ---------- */
static uint16_t ip_checksum16(const void *data, size_t len);
static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]);
static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len);

#define NET_RXQ_SLOTS  128
#define NET_RXQ_BUF    2048
static uint8_t g_net_rxq[NET_RXQ_SLOTS][NET_RXQ_BUF];
static uint16_t g_net_rxq_len[NET_RXQ_SLOTS];
static uint32_t g_net_rxq_head = 0, g_net_rxq_tail = 0, g_net_rxq_count = 0;
static spinlock_t g_net_rxq_lock = { 0 };
static spinlock_t g_net_nic_lock = { 0 };
volatile int g_net_tcp_connect_active = 0;
int g_net_tcp_sniff_left = 0;
uint8_t g_tcp_xmit_mac[6];
int g_tcp_xmit_mac_valid = 0;
static int g_net_rx_thread_started = 0;

static int net_rxq_push(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return -1;
    if (n > NET_RXQ_BUF) n = NET_RXQ_BUF;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count >= NET_RXQ_SLOTS) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return -2;
    }
    memcpy(g_net_rxq[g_net_rxq_tail], frame, n);
    g_net_rxq_len[g_net_rxq_tail] = (uint16_t)n;
    g_net_rxq_tail = (g_net_rxq_tail + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count++;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return 0;
}

static int net_rxq_pop(void *out, size_t cap) {
    if (!out || cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t idx = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[idx];
    g_net_rxq_len[idx] = 0;
    g_net_rxq_head = (idx + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    size_t copy_len = (n > cap) ? cap : (size_t)n;
    memcpy(out, g_net_rxq[idx], copy_len);
    return (int)copy_len;
}

static int net_reply_arp_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return 0;
    static int arp_dbg_left = 3;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return 0;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->oper) != 1) return 0; /* request */
    if (be16(arp->htype) != 1 || be16(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4) return 0;
    uint32_t tpa = ((uint32_t)arp->tpa[0] << 24) | ((uint32_t)arp->tpa[1] << 16) | ((uint32_t)arp->tpa[2] << 8) | arp->tpa[3];
    if (tpa != g_net.ip_be) return 0;
    if (arp_dbg_left-- > 0) {
        uint32_t spa = ((uint32_t)arp->spa[0] << 24) | ((uint32_t)arp->spa[1] << 16) | ((uint32_t)arp->spa[2] << 8) | arp->spa[3];
    }

    uint8_t reply[64];
    memset(reply, 0, sizeof(reply));
    eth_hdr_t *reth = (eth_hdr_t *)reply;
    memcpy(reth->dst, eth->src, 6);
    memcpy(reth->src, g_net.mac, 6);
    reth->ethertype = be16(ETH_TYPE_ARP);
    arp_hdr_t *rarp = (arp_hdr_t *)(reply + sizeof(eth_hdr_t));
    rarp->htype = be16(1);
    rarp->ptype = be16(ETH_TYPE_IPV4);
    rarp->hlen = 6;
    rarp->plen = 4;
    rarp->oper = be16(2); /* reply */
    memcpy(rarp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, rarp->spa);
    memcpy(rarp->tha, arp->sha, 6);
    memcpy(rarp->tpa, arp->spa, 4);
    (void)e1000_send_frame(reply, sizeof(reply));
    return 1;
}

static int net_reply_icmp_echo_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8) return 0;
    static int icmp_dbg_left = 3;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint32_t dst_ip_be = be32(ip->dst);
    if (dst_ip_be != g_net.ip_be) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + (size_t)tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 8 || icmp[1] != 0) return 0; /* echo request */
    size_t icmp_len = (size_t)tot - ihl;
    if (icmp_dbg_left-- > 0) {
        uint32_t src_ip_be = be32(ip->src);
        klogprintf("net: ICMP echo request from %u.%u.%u.%u len=%u\n",
                   (unsigned)((src_ip_be >> 24) & 0xFF), (unsigned)((src_ip_be >> 16) & 0xFF),
                   (unsigned)((src_ip_be >> 8) & 0xFF), (unsigned)(src_ip_be & 0xFF),
                   (unsigned)icmp_len);
    }

    uint8_t *reply = (uint8_t *)kmalloc(icmp_len);
    if (!reply) return 1; /* consume to avoid loops; out of memory */
    memcpy(reply, icmp, icmp_len);
    reply[0] = 0; /* echo reply */
    reply[2] = 0; reply[3] = 0;
    uint16_t csum = ip_checksum16(reply, icmp_len);
    reply[2] = (uint8_t)(csum >> 8);
    reply[3] = (uint8_t)(csum);
    uint32_t src_ip_be = be32(ip->src);
    (void)net_send_eth_ipv4(eth->src, src_ip_be, IPPROTO_ICMP_LOCAL, reply, icmp_len);
    kfree(reply);
    if (icmp_dbg_left >= 0) klogprintf("net: ICMP echo reply sent\n");
    return 1;
}

static int net_process_incoming_or_queue(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return 0;
    if (net_reply_arp_if_needed(frame, n)) return 1;
    if (net_reply_icmp_echo_if_needed(frame, n)) return 1;
    if (net_tcp_dispatch_incoming(frame, n)) return 1;
    (void)net_rxq_push(frame, n);
    return 1;
}

/* Single consumer for e1000 RX ring (net_rx thread + syscalls share this lock). */
static int net_nic_pull_frame(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_nic_lock, &irqf);
    int n = e1000_recv_frame(buf, cap);
    release_irqrestore(&g_net_nic_lock, irqf);
    return n;
}

void net_nic_drain_to_rxq(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(frame, sizeof(frame));
        if (n <= 0) break;
        if (net_reply_arp_if_needed(frame, (size_t)n)) continue;
        if (net_reply_icmp_echo_if_needed(frame, (size_t)n)) continue;
        if (net_rxq_push(frame, (size_t)n) != 0) {
            uint8_t drop[NET_RXQ_BUF];
            (void)net_rxq_pop(drop, sizeof(drop));
            (void)net_rxq_push(frame, (size_t)n);
        }
    }
}

/* Pull NIC frames and run TCP listen/handshake immediately (accept must not only enqueue). */
static void net_nic_drain_process_incoming(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(frame, sizeof(frame));
        if (n <= 0) break;
        (void)net_process_incoming_or_queue(frame, (size_t)n);
    }
}

static void net_rxq_drain_process_incoming(int budget) {
    uint8_t frame[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_rxq_pop(frame, sizeof(frame));
        if (n <= 0) break;
        (void)net_process_incoming_or_queue(frame, (size_t)n);
    }
}

void net_pump_listen_handshake(void) {
    net_nic_drain_process_incoming(64);
    net_rxq_drain_process_incoming(32);
}

static void net_nic_discard_pending(int budget) {
    uint8_t junk[NET_RXQ_BUF];
    for (int i = 0; i < budget; i++) {
        int n = net_nic_pull_frame(junk, sizeof(junk));
        if (n <= 0) break;
        (void)net_reply_arp_if_needed(junk, (size_t)n);
        (void)net_reply_icmp_echo_if_needed(junk, (size_t)n);
    }
}

static int net_recv_frame_any(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    int qn = net_rxq_pop(buf, cap);
    if (qn > 0) return qn;
    net_nic_drain_to_rxq(16);
    return net_rxq_pop(buf, cap);
}

/* Drop queued RX frames (stale TCP after failed HTTPS, etc.) before a new connect. */
void net_rxq_flush(void) {
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    g_net_rxq_head = 0;
    g_net_rxq_tail = 0;
    g_net_rxq_count = 0;
    release_irqrestore(&g_net_rxq_lock, irqf);
    net_nic_discard_pending(64);
}

/* Match IPv4/TCP frame to an established connection (same filters as net/tcp.c). */
static int net_tcp_match_frame(const uint8_t *frame, size_t n, uint32_t local_ip_be,
    const net_tcp_conn_t *c) {
    if (!c || !c->used || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 20u)
        return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if ((be16(ip->frag_off) & 0x1FFFu) != 0) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) return 0;
    if (be32(ip->dst) != local_ip_be || be32(ip->src) != c->dst_ip_be) return 0;
    const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(th->src_port) != c->dst_port || be16(th->dst_port) != c->src_port) return 0;
    return 1;
}

/* Log any IPv4 RX during blocking connect (SYN-ACK, ICMP errors, etc.). */
static void net_tcp_sniff_frame(const uint8_t *frame, size_t n, const net_tcp_conn_t *c) {
    if (!g_net_tcp_connect_active || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t))
        return;
    if (g_net_tcp_sniff_left <= 0)
        g_net_tcp_sniff_left = 1; /* always log at least one RX during connect */
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return;
    uint32_t sip = be32(ip->src), dip = be32(ip->dst);
    if (ip->proto == IPPROTO_TCP_LOCAL && n >= sizeof(eth_hdr_t) + ihl + 20u && c) {
        const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
        klogprintf("tcp: sniff tcp %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u fl=0x%02x ack=%u match=%d\n",
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF), (unsigned)be16(th->src_port),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF), (unsigned)be16(th->dst_port),
            (unsigned)th->flags, (unsigned)be32(th->ack),
            net_tcp_match_frame(frame, n, g_net.ip_be, c));
    } else if (ip->proto == IPPROTO_ICMP_LOCAL) {
        klogprintf("tcp: sniff icmp %u.%u.%u.%u -> %u.%u.%u.%u type=%u\n",
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF),
            (unsigned)(frame[sizeof(eth_hdr_t) + ihl]));
    } else {
        klogprintf("tcp: sniff proto=%u %u.%u.%u.%u -> %u.%u.%u.%u\n",
            (unsigned)ip->proto,
            (unsigned)((sip >> 24) & 0xFF), (unsigned)((sip >> 16) & 0xFF),
            (unsigned)((sip >> 8) & 0xFF), (unsigned)(sip & 0xFF),
            (unsigned)((dip >> 24) & 0xFF), (unsigned)((dip >> 16) & 0xFF),
            (unsigned)((dip >> 8) & 0xFF), (unsigned)(dip & 0xFF));
    }
    g_net_tcp_sniff_left--;
}

/* Dequeue a TCP frame for this socket without head-of-line blocking (DNS-style scan). */
static int net_rxq_take_tcp_frame(const net_tcp_conn_t *c, uint32_t local_ip_be,
    void *buf, size_t cap) {
    if (!c || !buf || cap == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_tcp_match_frame(g_net_rxq[idx], fn, local_ip_be, c)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    size_t copy_len = (n > cap) ? cap : (size_t)n;
    memcpy(buf, g_net_rxq[hi2], copy_len);
    return (int)copy_len;
}

int net_stack_init(void);

static void net_rx_pump_thread(void) {
    uint8_t buf[NET_RXQ_BUF];
    static uint64_t link_down_ms = 0;
    for (;;) {
        if (e1000_link_changed()) {
            if (!e1000_link_is_up()) {
                link_down_ms = pit_get_time_ms();
            } else if (link_down_ms && pit_get_time_ms() - link_down_ms >= 2000ULL) {
                g_net_redhcp_pending = 1;
                link_down_ms = 0;
            }
        }
        if (g_net_redhcp_pending) {
            g_net_redhcp_pending = 0;
            dhcp_invalidate_cache();
            g_net_shadow_valid = 0;
            memset(&g_net_shadow, 0, sizeof(g_net_shadow));
            g_net.ready = 0;
            g_net.gw_mac_valid = 0;
            g_net.inited = 0;
            net_rxq_flush();
            (void)net_stack_init();
        }
        if (!g_net.ready) { thread_sleep(50); continue; }
        for (int i = 0; i < 32; i++) {
            int n = net_nic_pull_frame(buf, sizeof(buf));
            if (n <= 0) break;
            (void)net_process_incoming_or_queue(buf, (size_t)n);
        }
        thread_sleep(1);
    }
}

/* Linux-style demux: scan the software RX ring for a matching UDP datagram; do not drop non-matches
 * that belong to TCP or another UDP port (head-of-line blocking was losing DNS replies). */
static int net_udp_match_sock_frame(const uint8_t *frame, size_t n, ksock_net_t *s) {
    if (!s || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != s->local_port) return 0;
    uint32_t src_ip = be32(ip->src);
    uint16_t sport = be16(uh->src_port);
    if (s->connected) {
        int ok = (src_ip == s->peer_ip_be && sport == s->peer_port);
        if (!ok && s->peer_port == 53u && sport == 53u &&
            ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
             (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)))
            ok = 1;
        if (!ok) return 0;
    }
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    return 1;
}

static int net_udp_match_raw_frame(const uint8_t *frame, size_t n, uint16_t local_port,
                                   uint32_t peer_ip_be, uint16_t peer_port) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != local_port) return 0;
    uint32_t sip = be32(ip->src);
    uint16_t sp = be16(uh->src_port);
    int ok = (sip == peer_ip_be && sp == peer_port);
    if (!ok && peer_port == 53u && sp == 53u) ok = 1;
    return ok ? 1 : 0;
}

static int net_udp_copy_payload_from_frame(const uint8_t *frame, size_t n, uint8_t *out, size_t out_cap,
                                          uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!frame || !out || out_cap == 0) return 0;
    if (n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t sport = be16(uh->src_port);
    uint32_t src_ip = be32(ip->src);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    size_t copy_len = (payload_len > out_cap) ? out_cap : payload_len;
    if (copy_len > 0) memcpy(out, (const uint8_t *)uh + sizeof(udp_hdr_t), copy_len);
    if (out_src_ip_be) *out_src_ip_be = src_ip;
    if (out_src_port) *out_src_port = sport;
    return (int)copy_len;
}

/* UDP payload length in frame (for FIONREAD); 0 if not a valid IPv4 UDP datagram. */
static int net_udp_payload_len_from_frame(const uint8_t *frame, size_t n) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    if (payload_len > 0x7fffffffu) return 0;
    return (int)payload_len;
}

/* Bytes available for recv without dequeuing (head-of-line: first matching UDP in RX queue). */
int net_rxq_peek_udp_payload_for_sock(ksock_net_t *s) {
    if (!s || s->local_port == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    uint32_t head0 = g_net_rxq_head;
    int plen = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            plen = net_udp_payload_len_from_frame(g_net_rxq[idx], fn);
            break;
        }
    }
    release_irqrestore(&g_net_rxq_lock, irqf);
    return plen;
}

static int net_recv_post_arp_icmp_from_nic(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    for (int i = 0; i < 16; i++) {
        int nn = net_nic_pull_frame(buf, cap);
        if (nn <= 0) return nn;
        if (net_reply_arp_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        if (net_reply_icmp_echo_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        (void)net_rxq_push((const uint8_t *)buf, (size_t)nn);
    }
    return 0;
}

static int net_rxq_take_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap,
                                    uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, out_src_ip_be, out_src_port);
}

static int net_rxq_take_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                               uint8_t *out, size_t out_cap) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_raw_frame(g_net_rxq[idx], fn, local_port, peer_ip_be, peer_port)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, NULL, NULL);
}

static uint16_t ip_checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)((uint16_t)p[0] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]) {
    out[0] = (uint8_t)(ip_be >> 24);
    out[1] = (uint8_t)(ip_be >> 16);
    out[2] = (uint8_t)(ip_be >> 8);
    out[3] = (uint8_t)(ip_be);
}

int ip_same_subnet(uint32_t a_be, uint32_t b_be, uint32_t mask_be) {
    return ((a_be & mask_be) == (b_be & mask_be));
}

int net_stack_init(void);
static void net_ensure_resolv_conf(uint32_t dns_be);
static int ip_mask_prefix_len(uint32_t mask_be);
int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms);

static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len) {
    if (!g_net.ready || !dst_mac || !l4 || l4_len > 1500) return -1;
    size_t frame_len = sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + l4_len;
    uint8_t *frame = (uint8_t *)kmalloc(frame_len);
    if (!frame) return -1;

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_IPV4);

    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = be16((uint16_t)(sizeof(ipv4_hdr_t) + l4_len));
    ip->id = be16(++g_net.ip_id);
    ip->frag_off = be16(0x0000);
    ip->ttl = 64;
    ip->proto = proto;
    ip->src = be32(g_net.ip_be);
    ip->dst = be32(dst_ip_be);
    {
        uint16_t c = ip_checksum16(ip, sizeof(*ip));
        uint8_t *cp = (uint8_t *)&ip->csum;
        cp[0] = (uint8_t)(c >> 8);
        cp[1] = (uint8_t)(c & 0xFF);
    }

    memcpy(frame + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t), l4, l4_len);
    int r = e1000_send_frame(frame, frame_len);
    e1000_poll();
    e1000_poll();
    kfree(frame);
    return (r < 0) ? -1 : 0;
}

static int net_resolve_next_hop_mac(uint32_t dst_ip_be, uint8_t out_mac[6]) {
    if (!out_mac) return -1;
    if (net_stack_init() != 0) return -1;
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    if (nh == g_net.gw_be && g_net.gw_mac_valid) {
        memcpy(out_mac, g_net.gw_mac, 6);
        return 0;
    }
    if (net_resolve_mac(nh, out_mac, 15000) != 0) return -1;
    if (nh == g_net.gw_be) {
        memcpy(g_net.gw_mac, out_mac, 6);
        g_net.gw_mac_valid = 1;
    }
    return 0;
}

int net_send_udp_datagram(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len > 1472) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t dst_mac[6];
    if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) return -1;
    size_t l4_len = sizeof(udp_hdr_t) + payload_len;
    uint8_t *pkt = (uint8_t *)kmalloc(l4_len);
    if (!pkt) return -1;
    udp_hdr_t *uh = (udp_hdr_t *)pkt;
    uh->src_port = be16(src_port);
    uh->dst_port = be16(dst_port);
    uh->len = be16((uint16_t)l4_len);
    uh->csum = 0; /* checksum optional for IPv4 */
    if (payload_len > 0) memcpy(pkt + sizeof(udp_hdr_t), payload, payload_len);
    int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_UDP_LOCAL, pkt, l4_len);
    kfree(pkt);
    return r;
}

static uint32_t g_net_ephemeral_port_seq;

/* Linux-style dynamic ports (32768–65535). Per-tid reuse broke resolver: parallel A/AAAA
 * UDP sockets on one thread shared the same local port and stole each other's replies. */
uint16_t net_alloc_ephemeral_port(void) {
    uint32_t n = __atomic_add_fetch(&g_net_ephemeral_port_seq, 1u, __ATOMIC_RELAXED);
    return (uint16_t)(32768u + (n % 32768u));
}

int net_recv_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0 || s->local_port == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    /* timeout_ms==0: single attempt (poll / non-blocking). Old code used while(elapsed<0) and ran zero times. */
    do {
        int q = net_rxq_take_udp_datagram(s, out, out_cap, out_src_ip_be, out_src_port);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_sock_frame((const uint8_t *)frame, (size_t)n, s)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, out_src_ip_be, out_src_port);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

/* One-off UDP recv for DNS: filter by local_port and peer (peer_ip_be, peer_port). Returns bytes, 0=timeout, <0=error. */
static int net_recv_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                            uint8_t *out, size_t out_cap, uint32_t timeout_ms) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    do {
        int q = net_rxq_take_udp_raw(local_port, peer_ip_be, peer_port, out, out_cap);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_raw_frame((const uint8_t *)frame, (size_t)n, local_port, peer_ip_be, peer_port)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, NULL, NULL);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

#define NET_UDP_BLOCK_MAX_MS 120000u

/* One blocking recv: keep waiting (slice by slice) instead of returning EAGAIN after ~3s like a non-blocking socket. */
int net_udp_recv_into_pending(ksock_net_t *s) {
    if (!s || s->rx_has_pending) return 1;
    if (s->local_port == 0) return -1;
    if (s->nonblock) {
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0u,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        return (rn < 0) ? -1 : 0;
    }
    uint64_t deadline = pit_get_time_ms() + (uint64_t)NET_UDP_BLOCK_MAX_MS;
    for (;;) {
        uint32_t slice = 10000u;
        uint64_t now = pit_get_time_ms();
        if (now >= deadline) return 0;
        if (now + slice > deadline) slice = (uint32_t)(deadline - now);
        if (slice < 1u) slice = 1u;
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), slice,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        if (rn < 0) return -1;
    }
}

static const net_tcp_conn_t *s_tcp_rx_match;
static uint8_t s_net_pull_buf[NET_RXQ_BUF];

static int net_send_l4_ipv4_cb(uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len);
static void net_tcp_post_tx_drain(void);

static int net_recv_frame_cb(void *buf, size_t cap) {
    if (s_tcp_rx_match && g_net.ready) {
        for (int pass = 0; pass < 16; pass++) {
            int n = net_rxq_take_tcp_frame(s_tcp_rx_match, g_net.ip_be, buf, cap);
            if (n > 0) return n;
            if (g_net_tcp_connect_active)
                net_nic_drain_to_rxq(64);
            else
                net_nic_drain_to_rxq(32);
        }
        for (int nic = 0; nic < 32; nic++) {
            int r = net_nic_pull_frame(s_net_pull_buf, sizeof(s_net_pull_buf));
            if (r <= 0)
                return 0;
            if (g_net_tcp_connect_active)
                net_tcp_sniff_frame(s_net_pull_buf, (size_t)r, s_tcp_rx_match);
            if (net_tcp_match_frame(s_net_pull_buf, (size_t)r, g_net.ip_be, s_tcp_rx_match)) {
                if ((size_t)r > cap)
                    return -1;
                memcpy(buf, s_net_pull_buf, (size_t)r);
                return r;
            }
            (void)net_process_incoming_or_queue(s_net_pull_buf, (size_t)r);
        }
        return 0;
    }
    return net_recv_frame_any(buf, cap);
}

static uint64_t net_time_ms_cb(void) {
    return pit_get_time_ms();
}

static void net_yield_connect_cb(void) {
    net_nic_drain_to_rxq(128);
    for (int i = 0; i < 8; i++)
        thread_yield();
    thread_sleep(1);
}

static unsigned g_net_yield_spins;

static void net_yield_cb(void) {
    if (g_net_tcp_connect_active) {
        net_yield_connect_cb();
        return;
    }
    net_nic_drain_process_incoming(32);
    net_rxq_drain_process_incoming(16);
    g_net_yield_spins++;
    if ((g_net_yield_spins & 63u) == 0u)
        thread_sleep(1);
    else
        thread_yield();
}

static void net_tcp_return_frame_cb(const void *frame, size_t n) {
    if (!frame || n == 0) return;
    if (net_rxq_push((const uint8_t *)frame, n) != 0) {
        uint8_t drop[NET_RXQ_BUF];
        (void)net_rxq_pop(drop, sizeof(drop));
        (void)net_rxq_push((const uint8_t *)frame, n);
    }
}

void net_make_tcp_ops(net_tcp_ops_t *ops, net_tcp_conn_t *match) {
    if (!ops) return;
    memset(ops, 0, sizeof(*ops));
    s_tcp_rx_match = match;
    ops->local_ip_be = g_net.ip_be;
    ops->send_l4 = net_send_l4_ipv4_cb;
    ops->recv_frame = net_recv_frame_cb;
    ops->time_ms = net_time_ms_cb;
    ops->yield = net_yield_cb;
    ops->return_frame = net_tcp_return_frame_cb;
}

static void ksock_hold(ksock_net_t *s) {
    if (s) s->kref++;
}

static void ksock_drop(ksock_net_t *s) {
    if (!s) return;
    if (s->kref > 1) {
        s->kref--;
        return;
    }
    if (s->unix_domain_stub)
        unix_socket_cleanup(s);
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
        if (s->tcp.used) {
            net_tcp_ops_t ops;
            net_make_tcp_ops(&ops, &s->tcp);
            (void)net_tcp_close(&s->tcp, &ops, 1000);
        }
        net_rxq_flush();
    }
    kfree(s);
}

static int fork_socket_is_connected_client(const ksock_net_t *s) {
    if (!s) return 0;
    if (s->unix_domain_stub)
        return s->connected && !s->unix_listening;
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge)
        return s->tcp.used && s->connected && !s->tcp_listening;
    return 0;
}

/* Child gets its own fs_file; both parent and child share one ksock (RX after fork). */
static struct fs_file *fork_child_socket_file(struct fs_file *pf) {
    if (!pf || pf->type != SYSCALL_FTYPE_SOCKET || !pf->driver_private) return NULL;
    ksock_net_t *s = (ksock_net_t *)pf->driver_private;
    struct fs_file *cf = (struct fs_file *)kmalloc(sizeof(*cf));
    char *cp = (char *)kmalloc(24);
    if (!cf || !cp) {
        if (cf) kfree(cf);
        if (cp) kfree(cp);
        return NULL;
    }
    memset(cf, 0, sizeof(*cf));
    if (s->unix_domain_stub)
        snprintf(cp, 24, "socket:[unix]");
    else
        snprintf(cp, 24, "socket:[tcp]");
    cf->path = cp;
    cf->type = pf->type;
    cf->fs_private = pf->fs_private;
    cf->driver_private = s;
    cf->refcount = 1;
    ksock_hold(s);
    return cf;
}

void fork_inherit_fd_table(thread_t *child, thread_t *parent) {
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        struct fs_file *pf = parent->fds[i];
        child->fds[i] = NULL;
        if (!pf) continue;
        if (pf->type == SYSCALL_FTYPE_SOCKET && fork_socket_is_connected_client((ksock_net_t *)pf->driver_private)) {
            struct fs_file *cf = fork_child_socket_file(pf);
            if (cf) {
                child->fds[i] = cf;
                continue;
            }
        }
        child->fds[i] = pf;
        if (pf->refcount <= 0) pf->refcount = 1;
        else pf->refcount++;
    }
}

/* Final unref: close TCP/unix and free driver_private (also used from SYS_exit via fs_file_free). */
void net_fs_file_destroy(struct fs_file *f) {
    if (!f) return;
    if (f->type != SYSCALL_FTYPE_SOCKET) return;
    ksock_net_t *s = (ksock_net_t *)f->driver_private;
    f->driver_private = NULL;
    ksock_drop(s);
    if (f->path) {
        kfree((void *)f->path);
        f->path = NULL;
    }
    kfree(f);
}

ksock_net_t *net_tcp_find_listener(uint16_t port) {
    if (port == 0) return NULL;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *th = thread_get_by_index(ti);
        if (!th) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = th->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->unix_domain_stub) continue;
            if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) continue;
            if (!s->tcp_listening || s->local_port != port) continue;
            return s;
        }
    }
    return NULL;
}

static ksock_net_t *net_tcp_match_established_sock(uint16_t lport, uint32_t rip, uint16_t rport, ksock_net_t *s) {
    if (!s || s->unix_domain_stub || s->dns_tcp_udp_bridge) return NULL;
    if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) return NULL;
    if (!s->tcp.used || !s->tcp.established) return NULL;
    if (s->tcp.peer_fin || s->tcp.peer_rst) return NULL;
    if (s->local_port != lport || s->peer_ip_be != rip || s->peer_port != rport) return NULL;
    return s;
}

static ksock_net_t *net_tcp_find_established(uint16_t lport, uint32_t rip, uint16_t rport) {
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *th = thread_get_by_index(ti);
        if (!th || th->state == THREAD_TERMINATED) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = th->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            ksock_net_t *m = net_tcp_match_established_sock(lport, rip, rport, s);
            if (m) return m;
            if (!s->tcp_listening) continue;
            unsigned long fl = 0;
            acquire_irqsave(&s->unix_accept_lock, &fl);
            int qcnt = s->unix_accept_count;
            int qidx = s->unix_accept_head;
            for (int qi = 0; qi < qcnt; qi++) {
                struct fs_file *af = s->unix_accept_q[qidx];
                if (af && af->driver_private) {
                    ksock_net_t *as = (ksock_net_t *)af->driver_private;
                    ksock_net_t *am = net_tcp_match_established_sock(lport, rip, rport, as);
                    if (am) {
                        release_irqrestore(&s->unix_accept_lock, fl);
                        return am;
                    }
                }
                qidx = (qidx + 1) % (int)(sizeof(s->unix_accept_q) / sizeof(s->unix_accept_q[0]));
            }
            release_irqrestore(&s->unix_accept_lock, fl);
        }
    }
    return NULL;
}

static void net_tcp_frame_payload(const uint8_t *frame, size_t n, size_t ihl,
    const tcp_hdr_t *th, const uint8_t **payload_out, size_t *payload_len_out) {
    if (payload_out) *payload_out = NULL;
    if (payload_len_out) *payload_len_out = 0;
    if (!frame || !th || !payload_out || !payload_len_out) return;
    size_t doff = (size_t)((th->doff_res >> 4) * 4u);
    if (doff < sizeof(tcp_hdr_t) || (size_t)n < sizeof(eth_hdr_t) + ihl + doff) return;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ip_tot = (size_t)be16(ip->total_len);
    if (ip_tot < ihl + doff) return;
    size_t plen = ip_tot - ihl - doff;
    size_t frame_pay = (size_t)n - (sizeof(eth_hdr_t) + ihl + doff);
    if (plen > frame_pay) plen = frame_pay;
    *payload_out = frame + sizeof(eth_hdr_t) + ihl + doff;
    *payload_len_out = plen;
}

static void net_tcp_stage_peer_mac(net_tcp_conn_t *c, const uint8_t mac[6]) {
    if (!c || !mac) return;
    memcpy(c->peer_mac, mac, 6);
    c->peer_mac_valid = 1;
}

static void net_tcp_push_payload(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    if (!c || !payload || payload_len == 0) return;
    if (seq != c->rcv_nxt) return;
    size_t room = sizeof(c->rx_buf) - c->rx_len;
    size_t cp = payload_len > room ? room : payload_len;
    if (cp == 0) return;
    memcpy(c->rx_buf + c->rx_len, payload, cp);
    c->rx_len += cp;
    c->rcv_nxt += (uint32_t)cp;
}

static struct fs_file *net_tcp_make_accepted_file(ksock_net_t *listener, const net_tcp_conn_t *tcp,
                                                  uint32_t peer_ip_be, uint16_t peer_port,
                                                  const uint8_t peer_mac[6]) {
    ksock_net_t *srv = (ksock_net_t *)kmalloc(sizeof(*srv));
    struct fs_file *srv_f = (struct fs_file *)kmalloc(sizeof(*srv_f));
    char *srv_p = (char *)kmalloc(24);
    if (!srv || !srv_f || !srv_p) {
        if (srv) kfree(srv);
        if (srv_f) kfree(srv_f);
        if (srv_p) kfree(srv_p);
        return NULL;
    }
    memset(srv, 0, sizeof(*srv));
    memset(srv_f, 0, sizeof(*srv_f));
    snprintf(srv_p, 24, "socket:[tcp]");
    srv->sock_domain = AF_INET_LOCAL;
    srv->type_base = SOCK_STREAM_LOCAL;
    srv->protocol = IPPROTO_TCP_LOCAL;
    srv->connected = 1;
    srv->local_port = listener->local_port;
    srv->peer_ip_be = peer_ip_be;
    srv->peer_port = peer_port;
    srv->nonblock = listener->nonblock;
    memcpy(&srv->tcp, tcp, sizeof(*tcp));
    if (peer_mac)
        net_tcp_stage_peer_mac(&srv->tcp, peer_mac);
    srv->kref = 1;
    srv_f->path = srv_p;
    srv_f->type = SYSCALL_FTYPE_SOCKET;
    srv_f->driver_private = srv;
    srv_f->refcount = 1;
    return srv_f;
}

static int net_tcp_syn_wait_take_slot(tcp_syn_wait_t **out) {
    unsigned long fl = 0;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    for (int i = 0; i < TCP_SYN_WAIT_SLOTS; i++) {
        if (!g_tcp_syn_wait[i].active) {
            memset(&g_tcp_syn_wait[i], 0, sizeof(g_tcp_syn_wait[i]));
            g_tcp_syn_wait[i].active = 1;
            *out = &g_tcp_syn_wait[i];
            release_irqrestore(&g_tcp_syn_wait_lock, fl);
            return 0;
        }
    }
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
    return -1;
}

static tcp_syn_wait_t *net_tcp_syn_wait_find(uint16_t lport, uint32_t rip, uint16_t rport) {
    unsigned long fl = 0;
    tcp_syn_wait_t *found = NULL;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    for (int i = 0; i < TCP_SYN_WAIT_SLOTS; i++) {
        tcp_syn_wait_t *w = &g_tcp_syn_wait[i];
        if (!w->active || !w->listener) continue;
        if (w->listener->local_port == lport && w->peer_ip_be == rip && w->peer_port == rport) {
            found = w;
            break;
        }
    }
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
    return found;
}

static void net_tcp_syn_wait_release(tcp_syn_wait_t *w) {
    if (!w) return;
    unsigned long fl = 0;
    acquire_irqsave(&g_tcp_syn_wait_lock, &fl);
    memset(w, 0, sizeof(*w));
    release_irqrestore(&g_tcp_syn_wait_lock, fl);
}

static int net_tcp_dispatch_incoming(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 20u)
        return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (be32(ip->dst) != g_net.ip_be) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) return 0;
    const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t sport = be16(th->src_port);
    uint16_t dport = be16(th->dst_port);
    uint32_t seq = be32(th->seq);
    uint32_t ack = be32(th->ack);
    uint8_t flags = th->flags;
    uint32_t rip = be32(ip->src);
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    net_tcp_frame_payload(frame, n, ihl, th, &payload, &payload_len);

    if ((flags & 0x02u) && !(flags & 0x10u)) {
        if (heap_free_bytes() < (2u << 20))
            (void)thread_reap_unwaited_zombies();
        ksock_net_t *listener = net_tcp_find_listener(dport);
        if (!listener) return 0;
        tcp_syn_wait_t *wait = net_tcp_syn_wait_find(dport, rip, sport);
        net_tcp_conn_t *tc = wait ? &wait->tcp : NULL;
        if (!wait) {
            if (net_tcp_syn_wait_take_slot(&wait) != 0) return 0;
            wait->listener = listener;
            wait->peer_ip_be = rip;
            wait->peer_port = sport;
            memcpy(wait->peer_mac, eth->src, 6);
            tc = &wait->tcp;
            tc->dst_ip_be = rip;
            tc->dst_port = sport;
            tc->src_port = dport;
            net_tcp_stage_peer_mac(tc, eth->src);
        }
        g_tcp_xmit_mac_valid = 1;
        memcpy(g_tcp_xmit_mac, eth->src, 6);
        {
            extern volatile uint64_t timer_ticks;
            uint32_t now = (uint32_t)timer_ticks;
            if (wait && tc->used && wait->last_synack_tick != 0 &&
                (uint32_t)(now - wait->last_synack_tick) < 8u) {
                return 1;
            }
            if (wait)
                wait->last_synack_tick = now;
        }
        int first_syn = !tc->used;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, tc);
        if (tc->used)
            (void)net_tcp_server_resend_synack(tc, &ops);
        else
            (void)net_tcp_server_reply_syn(tc, &ops, seq);
        if (first_syn) {
            klogprintf("tcp: server syn-ack port=%u from %u.%u.%u.%u:%u\n",
                (unsigned)dport,
                (unsigned)((rip >> 24) & 0xFF), (unsigned)((rip >> 16) & 0xFF),
                (unsigned)((rip >> 8) & 0xFF), (unsigned)(rip & 0xFF), (unsigned)sport);
        }
        g_tcp_xmit_mac_valid = 0;
        {
            uint8_t drain[NET_RXQ_BUF];
            for (int di = 0; di < 4; di++) {
                int dn = net_nic_pull_frame(drain, sizeof(drain));
                if (dn <= 0) break;
                (void)net_process_incoming_or_queue(drain, (size_t)dn);
            }
        }
        return 1;
    }

    if ((flags & 0x10u) && !(flags & 0x02u)) {
        tcp_syn_wait_t *wait = net_tcp_syn_wait_find(dport, rip, sport);
        if (wait && wait->listener) {
            if (net_tcp_server_complete_ack(&wait->tcp, ack) == 0) {
                if (payload_len > 0)
                    net_tcp_push_payload(&wait->tcp, seq, payload, payload_len);
                struct fs_file *af = net_tcp_make_accepted_file(wait->listener, &wait->tcp, rip, sport, wait->peer_mac);
                if (!af) {
                    net_tcp_syn_wait_release(wait);
                    return 1;
                }
                if (unix_acceptq_push(wait->listener, af) != 0) {
                    net_fs_file_destroy(af);
                } else {
                    klogprintf("tcp: server accept port=%u from %u.%u.%u.%u:%u\n",
                        (unsigned)dport,
                        (unsigned)((rip >> 24) & 0xFF), (unsigned)((rip >> 16) & 0xFF),
                        (unsigned)((rip >> 8) & 0xFF), (unsigned)(rip & 0xFF), (unsigned)sport);
                }
                net_tcp_syn_wait_release(wait);
                return 1;
            }
            klogprintf("tcp: server ack mismatch port=%u ack=%u want=%u\n",
                (unsigned)dport, (unsigned)ack, (unsigned)(wait->tcp.syn_isn + 1u));
            return 1;
        }
    }

    ksock_net_t *est = net_tcp_find_established(dport, rip, sport);
    if (est) {
        if (net_rxq_push(frame, n) != 0) {
            uint8_t drop[NET_RXQ_BUF];
            (void)net_rxq_pop(drop, sizeof(drop));
            (void)net_rxq_push(frame, n);
        }
        if (est->tcp.peer_mac_valid) {
            g_tcp_xmit_mac_valid = 1;
            memcpy(g_tcp_xmit_mac, est->tcp.peer_mac, 6);
        }
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, &est->tcp);
        (void)net_tcp_service(&est->tcp, &ops, 64);
        g_tcp_xmit_mac_valid = 0;
        return 1;
    }
    return 0;
}

/* Pull NIC immediately after TCP TX during connect (SYN-ACK often lands before next poll). */
static void net_tcp_post_tx_drain(void) {
    if (!g_net_tcp_connect_active || !s_tcp_rx_match || !g_net.ready)
        return;
    net_tcp_conn_t *c = (net_tcp_conn_t *)s_tcp_rx_match;
    net_tcp_ops_t ops;
    net_make_tcp_ops(&ops, c);
    for (int i = 0; i < 64; i++) {
        int r = net_nic_pull_frame(s_net_pull_buf, sizeof(s_net_pull_buf));
        if (r <= 0)
            break;
        net_tcp_sniff_frame(s_net_pull_buf, (size_t)r, c);
        if (net_tcp_match_frame(s_net_pull_buf, (size_t)r, g_net.ip_be, c)) {
            if (net_rxq_push(s_net_pull_buf, (size_t)r) != 0) {
                uint8_t drop[NET_RXQ_BUF];
                (void)net_rxq_pop(drop, sizeof(drop));
                (void)net_rxq_push(s_net_pull_buf, (size_t)r);
            }
            (void)net_tcp_service(c, &ops, 64);
            if (c->established)
                return;
        } else {
            (void)net_process_incoming_or_queue(s_net_pull_buf, (size_t)r);
        }
    }
}

static int net_send_l4_ipv4_cb(uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len) {
    uint8_t dst_mac[6];
    if (g_tcp_xmit_mac_valid) {
        memcpy(dst_mac, g_tcp_xmit_mac, 6);
    } else if (s_tcp_rx_match && s_tcp_rx_match->peer_mac_valid) {
        memcpy(dst_mac, s_tcp_rx_match->peer_mac, 6);
    } else if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) {
        return -1;
    }
    return net_send_eth_ipv4(dst_mac, dst_ip_be, proto, l4, l4_len);
}

void net_pump_tcp_sock(ksock_net_t *s, int rounds) {
    if (!s || !g_net.ready || !s->tcp.used) return;
    net_tcp_ops_t ops;
    net_make_tcp_ops(&ops, &s->tcp);
    for (int i = 0; i < rounds; i++)
        (void)net_tcp_service(&s->tcp, &ops, 64);
}

void net_pump_all_tcp(thread_t *cur) {
    (void)cur;
    if (!g_net.ready) return;
    net_nic_drain_to_rxq(48);
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *th = thread_get_by_index(ti);
        if (!th) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = th->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *sk = (ksock_net_t *)f->driver_private;
            if (sk->type_base != SOCK_STREAM_LOCAL || sk->protocol != IPPROTO_TCP_LOCAL || sk->dns_tcp_udp_bridge)
                continue;
            net_pump_tcp_sock(sk, 12);
        }
    }
}

static int net_send_arp_request(uint32_t target_ip_be) {
    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_ARP);

    arp_hdr_t *arp = (arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    arp->htype = be16(1);
    arp->ptype = be16(ETH_TYPE_IPV4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = be16(1);
    memcpy(arp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, arp->spa);
    memset(arp->tha, 0, 6);
    ip_be_to_bytes(target_ip_be, arp->tpa);

    return (e1000_send_frame(frame, sizeof(frame)) < 0) ? -1 : 0;
}

static int net_try_parse_arp_reply_for_ip(const uint8_t *frame, size_t n, uint32_t ip_be, uint8_t out_mac[6]) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return 0;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->oper) != 2) return 0;
    uint32_t spa = ((uint32_t)arp->spa[0] << 24) | ((uint32_t)arp->spa[1] << 16) | ((uint32_t)arp->spa[2] << 8) | arp->spa[3];
    if (spa != ip_be) return 0;
    memcpy(out_mac, arp->sha, 6);
    return 1;
}

int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms) {
    if (!out_mac) return -1;
    if (net_send_arp_request(ip_be) != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = -1;
    while ((pit_get_time_ms() - start) < timeout_ms) {
        int n = net_nic_pull_frame(frame, NET_FRAME_BUF);
        if (n > 0) {
            if (net_try_parse_arp_reply_for_ip(frame, (size_t)n, ip_be, out_mac)) {
                ret = 0;
                break;
            }
            if (net_reply_arp_if_needed(frame, (size_t)n)) continue;
            if (net_reply_icmp_echo_if_needed(frame, (size_t)n)) continue;
            if (net_rxq_push(frame, (size_t)n) != 0) {
                uint8_t drop[NET_RXQ_BUF];
                (void)net_rxq_pop(drop, sizeof(drop));
                (void)net_rxq_push(frame, (size_t)n);
            }
        } else {
            thread_sleep(1);
        }
    }
    kfree(frame);
    return ret;
}


int net_stack_init(void) {
    static uint32_t net_announced_ip;
    if (g_net.inited) return g_net.ready ? 0 : -1;
    if (g_net_shadow_valid && g_net_shadow.ready) {
        g_net = g_net_shadow;
        g_net.inited = 1;
        /* L2 next-hop is not part of DHCP; stale gw_mac caused TCP timeout while ICMP worked. */
        g_net.gw_mac_valid = 0;
        return 0;
    }
    memset(&g_net, 0, sizeof(g_net));
    g_net.inited = 1;
    g_net.ip_id = 1;
    if (e1000_get_mac(g_net.mac) != 0) return -1;

    dhcp_lease_t lease;
    int dhcp_ok = 0;
    for (int dhcp_round = 0; dhcp_round < 2 && !dhcp_ok; dhcp_round++) {
        if (dhcp_round > 0) {
            e1000_flush_rx();
            pit_sleep_ms(3000);
        }
        if (dhcp_acquire(g_net.mac, &lease) != 0)
            continue;
        g_net.ip_be = lease.ip_be;
        g_net.mask_be = lease.mask_be;
        g_net.gw_be = lease.gw_be;
        g_net.dns_be = lease.dns_be ? lease.dns_be : lease.gw_be;
        dhcp_ok = 1;
    }
    if (!dhcp_ok) {
        /* QEMU user-NAT fallback only — never reuse across bridged WiFi changes. */
        g_net.ip_be = 0x0A00020Fu;   /* 10.0.2.15 */
        g_net.mask_be = 0xFFFFFF00u; /* /24 */
        g_net.gw_be = 0x0A000202u;   /* 10.0.2.2 */
        g_net.dns_be = 0x0A000203u;   /* 10.0.2.3 */
        klogprintf("net: DHCP failed, fallback ip=10.0.2.15 gw=10.0.2.2\n");
    }
    g_net.ready = 1;
    if (dhcp_ok) {
        g_net_shadow = g_net;
        g_net_shadow_valid = 1;
    }
    if (g_net.ip_be != net_announced_ip) {
        net_announced_ip = g_net.ip_be;
        klogprintf("net: ready ip=%u.%u.%u.%u gw=%u.%u.%u.%u%s\n",
                   (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                   (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                   (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                   (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF),
                   dhcp_ok ? "" : " (dhcp fallback)");
    }

    /* Start background RX pump once: reply to ARP/ICMP even when userland is idle. */
    if (!g_net_rx_thread_started) {
        thread_t *t = thread_create(net_rx_pump_thread, "net_rx");
        if (t) {
            t->nice = 5;
            g_net_rx_thread_started = 1;
        }
    }
    return 0;
}

int syscall_net_preinit(void) {
    return net_stack_init();
}

void syscall_net_ensure_resolv(void) {
    /* Without /etc/resolv.conf, glibc/musl/wget try stub paths (e.g. 127.0.0.1) and
       report "bad address". Mirror the same DNS choice as SYS_resolve. */
    (void)net_stack_init();
    uint32_t dns_be = 0;
    if (g_net.ready)
        dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
    if (!dns_be && g_net.gw_be)
        dns_be = g_net.gw_be;
    /* Last resort for QEMU usernet; bridged setups should have gw/dns above. */
    if (!dns_be)
        dns_be = 0x0A000202u;

    char line[96];
    unsigned a = (unsigned)((dns_be >> 24) & 0xFFu);
    unsigned b = (unsigned)((dns_be >> 16) & 0xFFu);
    unsigned c = (unsigned)((dns_be >> 8) & 0xFFu);
    unsigned d = (unsigned)(dns_be & 0xFFu);
    int n = snprintf(line, sizeof(line), "nameserver %u.%u.%u.%u\n", a, b, c, d);
    if (n <= 0 || (size_t)n >= sizeof(line))
        return;

    (void)fs_unlink("/etc/resolv.conf");
    struct fs_file *f = fs_create_file("/etc/resolv.conf");
    if (!f)
        f = fs_open("/etc/resolv.conf");
    if (f) {
        fs_write(f, line, (size_t)n, 0);
        fs_file_free(f);
    }
}

/* DNS resolver callbacks (ctx unused) */
static int dns_send_udp_cb(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port,
                           const void *data, size_t len, void *ctx) {
    (void)ctx;
    return net_send_udp_datagram(dst_ip_be, src_port, dst_port, (const uint8_t *)data, len) == 0 ? 0 : -1;
}
static int dns_recv_udp_cb(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                           void *out, size_t cap, uint32_t timeout_ms, void *ctx) {
    (void)ctx;
    return net_recv_udp_raw(local_port, peer_ip_be, peer_port, (uint8_t *)out, cap, timeout_ms);
}

uint16_t axonos_dns_alloc_src_port(void) {
    return net_alloc_ephemeral_port();
}

uint64_t axonos_dns_time_ms(void) {
    return pit_get_time_ms();
}

static int kernel_dns_resolve(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!g_net.ready || !dns_ip_be) return -1;
    return net_dns_resolve(hostname, dns_ip_be, dns_send_udp_cb, dns_recv_udp_cb, NULL, out_ip_be);
}

/* Parse "a.b.c.d" to IPv4 network byte order. Returns 0 on success, -1 on invalid. */
static int parse_ipv4_dotted(const char *s, uint32_t *out_ip_be) {
    if (!s || !out_ip_be) return -1;
    uint32_t a = 0, b = 0, c = 0, d = 0;
    int na = 0, nb = 0, nc = 0, nd = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (uint32_t)(*p - '0'); na++; p++; }
    if (na == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { b = b * 10 + (uint32_t)(*p - '0'); nb++; p++; }
    if (nb == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { c = c * 10 + (uint32_t)(*p - '0'); nc++; p++; }
    if (nc == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { d = d * 10 + (uint32_t)(*p - '0'); nd++; p++; }
    if (nd == 0 || *p != '\0') return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *out_ip_be = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

/* Check if string looks like dotted-decimal IP (no hostname chars). */
static int is_dotted_ip(const char *s) {
    if (!s || !*s) return 0;
    size_t i = 0;
    int dots = 0;
    while (s[i]) {
        char c = s[i];
        if (c >= '0' && c <= '9') { i++; continue; }
        if (c == '.') { dots++; i++; continue; }
        return 0;
    }
    return (dots == 3);
}

/* Parse /etc/hosts and lookup hostname. Returns 0 if found, -1 if not. */
static int kernel_hosts_lookup(const char *hostname, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    struct fs_file *f = fs_open("/etc/hosts");
    if (!f) return -1;
    char buf[2048];
    ssize_t n = fs_read(f, buf, sizeof(buf) - 1, 0);
    fs_file_free(f);
    if (n <= 0) return -1;
    buf[(size_t)n] = '\0';
    const char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '#' || !*p) {
            while (*p && *p != '\n') p++;
            continue;
        }
        char ip_str[64];
        size_t ii = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && ii < sizeof(ip_str) - 1)
            ip_str[ii++] = *p++;
        ip_str[ii] = '\0';
        if (ii == 0) continue;
        uint32_t ip_be = 0;
        if (parse_ipv4_dotted(ip_str, &ip_be) != 0) continue;
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != '#' && *p != '\n') {
            size_t hn = 0;
            char hn_buf[256];
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && hn < sizeof(hn_buf) - 1)
                hn_buf[hn++] = *p++;
            hn_buf[hn] = '\0';
            if (hn > 0) {
                size_t hl = 0;
                while (hostname[hl] && hn_buf[hl] && hostname[hl] == hn_buf[hl]) hl++;
                if (hostname[hl] == '\0' && hn_buf[hl] == '\0') {
                    *out_ip_be = ip_be;
                    return 0;
                }
            }
            while (*p == ' ' || *p == '\t') p++;
        }
        while (*p && *p != '\n') p++;
    }
    return -1;
}

/*
 * Full resolver: 1) dotted-decimal IP, 2) /etc/hosts, 3) DNS.
 * Returns 0 on success, -1 on failure.
 */
int kernel_resolve_full(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    if (is_dotted_ip(hostname) && parse_ipv4_dotted(hostname, out_ip_be) == 0)
        return 0;
    if (kernel_hosts_lookup(hostname, out_ip_be) == 0)
        return 0;
    if (net_stack_init() != 0) return -1;
    return kernel_dns_resolve(hostname, dns_ip_be, out_ip_be);
}

static void net_ensure_resolv_conf(uint32_t dns_be) {
    (void)dns_be;
    /* no-op: see syscall_net_ensure_resolv() */
}

static int ip_mask_prefix_len(uint32_t mask_be) {
    int n = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask_be & (1u << i)) n++;
        else break;
    }
    return n;
}

int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq);

int net_send_icmp_echo(ksock_net_t *s, uint32_t dst_ip_be, const uint8_t *icmp, size_t icmp_len) {
    if (!s || !icmp || icmp_len == 0) return -1;
    if (net_stack_init() != 0) return -1;
    /* Drain RX before send (limit 64) so old echo replies don't block next recv (second ping timeout). */
    { uint8_t drain[256]; for (int d = 0; d < 64; d++) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; } }
    /* 0.0.0.0 and 255.255.255.255: no host replies; send to gateway so user gets a reply. */
    if (dst_ip_be == 0 || dst_ip_be == 0xFFFFFFFFu) dst_ip_be = g_net.gw_be;
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    uint8_t dst_mac[6];
    if (nh == g_net.gw_be && g_net.gw_mac_valid) memcpy(dst_mac, g_net.gw_mac, 6);
    else {
        uint32_t arp_ms = 15000;
        if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) {
            /* Повтор ARP для шлюза (VMware иногда отвечает с задержкой). */
            if (nh == g_net.gw_be) {
                uint8_t drain[256];
                for (;;) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; }
                if (net_send_arp_request(nh) != 0) return -1;
                if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) return -1;
            } else
                return -1;
        }
        if (nh == g_net.gw_be) {
            memcpy(g_net.gw_mac, dst_mac, 6);
            g_net.gw_mac_valid = 1;
        }
    }
    s->last_dst_ip_be = dst_ip_be;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* Linux ping commonly uses SOCK_DGRAM + IPPROTO_ICMP:
           userspace passes payload only, kernel builds ICMP header. */
        size_t pkt_len = 8 + icmp_len;
        uint8_t *pkt = (uint8_t *)kmalloc(pkt_len);
        if (!pkt) return -1;
        memset(pkt, 0, pkt_len);
        pkt[0] = 8; /* Echo Request */
        pkt[1] = 0; /* code */
        uint16_t id = (uint16_t)((thread_current() ? thread_current()->tid : 1) & 0xFFFFu);
        uint16_t seq = ++s->next_echo_seq;
        pkt[4] = (uint8_t)(id >> 8); pkt[5] = (uint8_t)id;
        pkt[6] = (uint8_t)(seq >> 8); pkt[7] = (uint8_t)seq;
        memcpy(pkt + 8, icmp, icmp_len);
        uint16_t csum = ip_checksum16(pkt, pkt_len);
        pkt[2] = (uint8_t)(csum >> 8); pkt[3] = (uint8_t)csum;
        s->last_echo_id = id;
        s->last_echo_seq = seq;
        int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, pkt, pkt_len);
        kfree(pkt);
        return r;
    }

    /* SOCK_RAW path: userspace provides full ICMP packet including header. */
    if (icmp_len < 8) return -1;
    s->last_echo_id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    s->last_echo_seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    return net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, icmp, icmp_len);
}

static int net_try_parse_icmp_reply(const uint8_t *frame, size_t n, ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t *out_src_ip_be) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8 || !s || !out) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 0 || icmp[1] != 0) return 0; /* echo reply */
    uint16_t id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    uint16_t seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    if (id != s->last_echo_id || seq != s->last_echo_seq) return 0;
    uint32_t src_ip_be = be32(ip->src);
    {
        uint64_t now_ms = pit_get_time_ms();
        /* Drop immediate duplicates of the same ICMP echo-reply tuple.
           Helps with NIC/drain races where the same frame is observed repeatedly. */
        if (s->last_rx_echo_ms != 0 &&
            s->last_rx_src_ip_be == src_ip_be &&
            s->last_rx_echo_id == id &&
            s->last_rx_echo_seq == seq &&
            (now_ms - s->last_rx_echo_ms) < 1500u) {
            return 0;
        }
        s->last_rx_src_ip_be = src_ip_be;
        s->last_rx_echo_id = id;
        s->last_rx_echo_seq = seq;
        s->last_rx_echo_ms = now_ms;
    }
    size_t copy_len = 0;
    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* For datagram ICMP sockets, return full ICMP message (header+payload).
           Busybox ping expects to parse id/seq from the received buffer. */
        size_t icmp_len = (size_t)tot - ihl;
        if (icmp_len < 8) return 0;
        copy_len = (icmp_len > out_cap) ? out_cap : icmp_len;
        memcpy(out, icmp, copy_len);
    } else {
        /* Raw ICMP sockets expect IPv4 header included. */
        copy_len = (tot > out_cap) ? out_cap : tot;
        memcpy(out, ip, copy_len);
    }
    if (out_src_ip_be) *out_src_ip_be = src_ip_be;
    return (int)copy_len;
}

int net_recv_icmp_echo_reply(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be) {
    if (!s || !out || out_cap == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    while ((pit_get_time_ms() - start) < timeout_ms) {
        thread_t *tcur = thread_get_current_user();
        if (!tcur) tcur = thread_current();
        if (tcur && (tcur->pending_signals & (1ULL << (2 - 1)))) { ret = -4; break; } /* SIGINT */
        int n = net_recv_frame_any(frame, NET_FRAME_BUF);
        if (n > 0) {
            int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
            if (got > 0) { ret = got; break; }
        } else {
            int spun = 0;
            for (; spun < 200 && ret <= 0; spun++) {
                n = net_recv_frame_any(frame, NET_FRAME_BUF);
                if (n > 0) {
                    int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
                    if (got > 0) { ret = got; break; }
                    goto next_iter;
                }
            }
            if (spun >= 200) thread_sleep(1);
        }
next_iter:
        if (ret != 0) break;
    }
    kfree(frame);
    return ret;
}

enum {
    PING_TS_UNKNOWN = 0,
    PING_TS_NONE,
    PING_TS_U64_USEC,
    PING_TS_TIMEVAL64,
    PING_TS_TIMESPEC64,
    PING_TS_TIMEVAL32
};

int net_detect_ping_ts_fmt(const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len < 8) return PING_TS_NONE;
    uint64_t w0 = 0, w1 = 0;
    memcpy(&w0, payload + 0, sizeof(w0));
    if (payload_len >= 16) memcpy(&w1, payload + 8, sizeof(w1));

    /* gettimeofday timeval64: sec near Unix epoch, usec sub-second */
    if (payload_len >= 16 &&
        w0 > 1000000000ULL && w0 < 5000000000ULL &&
        w1 < 1000000ULL) return PING_TS_TIMEVAL64;

    /* clock_gettime timespec64: sec since boot/epoch, nsec sub-second */
    if (payload_len >= 16 &&
        w0 < 0x7FFFFFFFULL &&
        w1 < 1000000000ULL) return PING_TS_TIMESPEC64;

    /* Common "u64 usec" ping payload style. */
    if (w0 > 1000000ULL) return PING_TS_U64_USEC;

    if (payload_len >= 8) {
        uint32_t s32 = 0, us32 = 0;
        memcpy(&s32, payload + 0, sizeof(s32));
        memcpy(&us32, payload + 4, sizeof(us32));
        if (s32 > 1000000000U && s32 < 5000000000U && us32 < 1000000U) return PING_TS_TIMEVAL32;
    }

    return PING_TS_UNKNOWN;
}

/* BusyBox ping stores *(uint32_t*)icmp_data = monotonic_us() (see networking/ping.c). */
static void net_update_ping_ts_payload(uint8_t *payload, size_t payload_len, int fmt) {
    (void)fmt;
    if (!payload || payload_len < 4) return;
    uint32_t us = (uint32_t)(pit_get_time_ms() * 1000ULL);
    memcpy(payload, &us, sizeof(us));
}

int net_send_icmp_echo_timer_compat(ksock_net_t *s) {
    if (!s || s->last_dst_ip_be == 0 || s->last_req_len == 0) return -1;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        net_update_ping_ts_payload(s->last_req, s->last_req_len, s->last_req_ts_fmt);
        return net_send_icmp_echo(s, s->last_dst_ip_be, s->last_req, s->last_req_len);
    }

    if (s->last_req_len < 8) return -1;
    uint8_t *pkt = s->last_req;
    uint16_t seq = (uint16_t)((pkt[6] << 8) | pkt[7]);
    seq = (uint16_t)(seq + 1u);
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)seq;
    if (s->last_req_len > 8) {
        net_update_ping_ts_payload(pkt + 8, s->last_req_len - 8, s->last_req_ts_fmt);
    }
    pkt[2] = 0;
    pkt[3] = 0;
    {
        uint16_t csum = ip_checksum16(pkt, s->last_req_len);
        pkt[2] = (uint8_t)(csum >> 8);
        pkt[3] = (uint8_t)csum;
    }
    return net_send_icmp_echo(s, s->last_dst_ip_be, pkt, s->last_req_len);
}

struct fs_file *socket_file_get(thread_t *cur, int fd, ksock_net_t **out_sock) {
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return NULL;
    struct fs_file *f = cur->fds[fd];
    if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) return NULL;
    if (out_sock) *out_sock = (ksock_net_t *)f->driver_private;
    return f;
}

void net_debug_log_tls443_tx(ksock_net_t *s, const uint8_t *buf, size_t len, const char *path) {
    if (!s || !buf || len == 0) return;
    if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL || s->dns_tcp_udp_bridge)
        return;
    if (s->peer_port != 443u)
        return;
    static int left = 16;
    if (left <= 0)
        return;
    left--;
    qemu_debug_printf("HTTPS-TX[%s]: len=%llu first=%02x %02x %02x %02x %02x %02x %02x %02x tls=%d\n",
        path ? path : "?",
        (unsigned long long)len,
        (unsigned)(len > 0 ? buf[0] : 0),
        (unsigned)(len > 1 ? buf[1] : 0),
        (unsigned)(len > 2 ? buf[2] : 0),
        (unsigned)(len > 3 ? buf[3] : 0),
        (unsigned)(len > 4 ? buf[4] : 0),
        (unsigned)(len > 5 ? buf[5] : 0),
        (unsigned)(len > 6 ? buf[6] : 0),
        (unsigned)(len > 7 ? buf[7] : 0),
        (len >= 3 && buf[0] == 0x16 && buf[1] == 0x03) ? 1 : 0);
}

/* Linux /proc/net/tcp IPv4 hex: byte-reverse of network-order IP (see /proc/net/tcp). */
static uint32_t ip_be_to_proc_net_hex(uint32_t ip_be) {
    return ((ip_be & 0xFFu) << 24) | ((ip_be & 0xFF00u) << 8)
         | ((ip_be >> 8) & 0xFF00u) | ((ip_be >> 24) & 0xFFu);
}

static unsigned procfs_tcp_port_hex(uint16_t port_host) {
    return (unsigned)(((port_host & 0xFFu) << 8) | ((port_host >> 8) & 0xFFu));
}

ssize_t procfs_net_snap_tcp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            unsigned lport_hex = procfs_tcp_port_hex(s->local_port);
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 1000u);
            if (s->tcp_listening && s->local_port != 0) {
                n = snprintf((char *)buf + w, w < size ? size - w : 0,
                    "%4d: %08X:%04X 00000000:0000 0A %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                    sl++, lhx, lport_hex, 0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
                if (n < 0) return (ssize_t)w;
                w += (size_t)n;
                if (w + 256 >= size) return (ssize_t)w;
                continue;
            }
            if (!s->tcp.used) continue;
            uint32_t rhx = ip_be_to_proc_net_hex(s->peer_ip_be);
            unsigned rport_hex = procfs_tcp_port_hex(s->peer_port);
            unsigned st = s->tcp.established ? 1u : 2u;
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, lport_hex, rhx, rport_hex, st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_udp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_DGRAM_LOCAL || s->protocol != IPPROTO_UDP_LOCAL) continue;
            if (s->local_port == 0 && !s->connected) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            uint32_t rhx = s->connected ? ip_be_to_proc_net_hex(s->peer_ip_be) : 0u;
            uint32_t rp = s->connected ? (uint32_t)(s->peer_port & 0xFFFFu) : 0u;
            unsigned st = 7u;
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 50000u);
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, (unsigned)(s->local_port & 0xFFFFu), rhx, rp, st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_tcp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n");
}

ssize_t procfs_net_snap_udp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n");
}

ssize_t procfs_net_snap_raw(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
}

ssize_t procfs_net_snap_raw6(char *buf, size_t size) {
    return procfs_net_snap_raw(buf, size);
}

ssize_t procfs_net_snap_unix(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "Num       RefCount Protocol Flags    Type St Inode Path\n");
}

ssize_t procfs_net_snap_arp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "IP address       HW type     Flags       HW address            Mask     Device\n");
    if (n < 0) return 0;
    w += (size_t)n;
    if (!g_net.ready) return (ssize_t)w;
    if (g_net.gw_be != 0 && g_net.gw_mac_valid) {
        n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                     "%u.%u.%u.%u   0x1         0x2         %02x:%02x:%02x:%02x:%02x:%02x     *        eth0\n",
                     (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                     (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF),
                     g_net.gw_mac[0], g_net.gw_mac[1], g_net.gw_mac[2],
                     g_net.gw_mac[3], g_net.gw_mac[4], g_net.gw_mac[5]);
        if (n > 0) w += (size_t)n;
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_dev(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "Inter-|   Receive                                                |  Transmit\n"
                     " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
    if (n < 0) return 0;
    w += (size_t)n;
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "  lo: 0        0       0    0    0    0     0          0         0        0       0    0    0    0     0       0\n");
    if (n > 0) w += (size_t)n;
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "eth0: 0        0       0    0    0    0     0          0         0        0       0    0    0    0     0       0\n");
    if (n > 0) w += (size_t)n;
    return (ssize_t)w;
}

ssize_t procfs_net_snap_route(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
                     "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
    if (n < 0) return 0;
    w += (size_t)n;
    if (!g_net.ready) return (ssize_t)w;
    /* default route via gateway */
    n = snprintf((char *)buf + w, (w < size) ? (size - w) : 0,
                 "eth0\t%08X\t%08X\t0003\t0\t0\t0\t%08X\t0\t0\t0\n",
                 0u, ip_be_to_proc_net_hex(g_net.gw_be), ip_be_to_proc_net_hex(g_net.mask_be));
    if (n > 0) w += (size_t)n;
    return (ssize_t)w;
}

void sockaddr_in6_v4mapped_fill(sockaddr_in6_k *s6, uint32_t ip_be, uint16_t port_host)
{
    memset(s6, 0, sizeof(*s6));
    s6->sin6_family = AF_INET6;
    s6->sin6_port = be16(port_host);
    memset(s6->sin6_addr, 0, 10);
    s6->sin6_addr[10] = 0xff;
    s6->sin6_addr[11] = 0xff;
    {
        uint32_t s_addr = be32(ip_be);
        memcpy(s6->sin6_addr + 12, &s_addr, 4);
    }
}

/* connect/sendto: Linux glibc often passes AF_INET6 (v4-mapped or ::1). Returns 0 or errno. */
int user_sockaddr_to_ipv4_peer(const void *addr_u, size_t addrlen, sockaddr_in_k *out) {
    if (!out) return EFAULT;
    if (!addr_u || addrlen < 2) return EFAULT;
    if (!user_range_ok(addr_u, addrlen)) return EFAULT;
    uint16_t fam = 0;
    if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return EFAULT;
    if (fam == 1) return ECONNREFUSED;
    if (fam == AF_INET_LOCAL) {
        if (addrlen < sizeof(sockaddr_in_k)) return EINVAL;
        if (copy_from_user_raw(out, addr_u, sizeof(*out)) != 0) return EFAULT;
        /* Trust sa_family at addr_u; glibc padding/quirks can leave sin_family != 2 in the copy. */
        out->sin_family = AF_INET_LOCAL;
        return 0;
    }
    if (fam == AF_INET6) {
        if (addrlen < sizeof(sockaddr_in6_k)) return EINVAL;
        sockaddr_in6_k s6;
        if (copy_from_user_raw(&s6, addr_u, sizeof(s6)) != 0) return EFAULT;
        int v4m = 1;
        for (int i = 0; i < 10; i++) {
            if (s6.sin6_addr[i]) v4m = 0;
        }
        if (s6.sin6_addr[10] != 0xff || s6.sin6_addr[11] != 0xff) v4m = 0;
        /* Some getaddrinfo paths pass IPv4 in the low 32 bits without ::ffff prefix. */
        int v4lo = 1;
        for (int i = 0; i < 12; i++) {
            if (s6.sin6_addr[i]) v4lo = 0;
        }
        memset(out, 0, sizeof(*out));
        out->sin_family = AF_INET_LOCAL;
        out->sin_port = s6.sin6_port;
        if (v4m || v4lo) {
            memcpy(&out->sin_addr, s6.sin6_addr + 12, 4);
            return 0;
        }
        int lo6 = 1;
        for (int i = 0; i < 15; i++) {
            if (s6.sin6_addr[i]) lo6 = 0;
        }
        if (lo6 && s6.sin6_addr[15] == 1) {
            out->sin_addr = 0x0100007Fu; /* 127.0.0.1 s_addr as on Linux LE */
            return 0;
        }
        /* No IPv6 stack: not EAFNOSUPPORT — glibc/wget treats that as fatal and may surface bogus OOM. */
        return ENETUNREACH;
    }
    /* Same as IPv6: avoid EAFNOSUPPORT so glibc can try other addresses / paths. */
    return ENETUNREACH;
}

/* Normalize fs_mkdir internal negative codes to Linux errno. */
int fs_mkdir_errno(int r) {
    if (r == -4 || r == -17) return EEXIST;
    if (r == -2) return ENOENT;
    if (r == -3) return ENOTDIR;
    if (r == -5) return ENOMEM;
    return EIO;
}

typedef struct __attribute__((packed)) {
    uint8_t rtgen_family;
} rtgenmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifi_family;
    uint8_t  __ifi_pad;
    uint16_t ifi_type;
    int32_t  ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
} ifinfomsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifa_family;
    uint8_t  ifa_prefixlen;
    uint8_t  ifa_flags;
    uint8_t  ifa_scope;
    uint32_t ifa_index;
} ifaddrmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
} rtmsg_k;

typedef struct __attribute__((packed)) {
    uint16_t rta_len;
    uint16_t rta_type;
} rtattr_k;

static inline size_t nl_align4(size_t n) { return (n + 3u) & ~3u; }

static int nl_append_blob(uint8_t *buf, size_t cap, size_t *off, const void *data, size_t len) {
    if (!buf || !off || !data) return -1;
    if (*off + len > cap) return -1;
    memcpy(buf + *off, data, len);
    *off += len;
    return 0;
}

static int nl_append_attr_u32(uint8_t *buf, size_t cap, size_t *off, uint16_t type, uint32_t v) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + sizeof(uint32_t));
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (nl_append_blob(buf, cap, off, &v, sizeof(v)) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_append_attr_blob(uint8_t *buf, size_t cap, size_t *off, uint16_t type, const void *data, size_t data_len) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + data_len);
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (data_len && nl_append_blob(buf, cap, off, data, data_len) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_msg_begin(uint8_t *buf, size_t cap, size_t *off, size_t *msg_start, uint16_t type, uint16_t flags, uint32_t seq, uint32_t pid) {
    if (!buf || !off || !msg_start) return -1;
    *msg_start = *off;
    nlmsghdr_k h;
    memset(&h, 0, sizeof(h));
    h.nlmsg_type = type;
    h.nlmsg_flags = flags;
    h.nlmsg_seq = seq;
    h.nlmsg_pid = pid;
    return nl_append_blob(buf, cap, off, &h, sizeof(h));
}

static int nl_msg_end(uint8_t *buf, size_t cap, size_t *off, size_t msg_start) {
    if (!buf || !off || msg_start > *off || msg_start + sizeof(nlmsghdr_k) > cap) return -1;
    size_t mlen = *off - msg_start;
    ((nlmsghdr_k *)(buf + msg_start))->nlmsg_len = (uint32_t)mlen;
    size_t need = nl_align4(mlen);
    while ((*off - msg_start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq) {
    if (!s) return -1;
    if (net_stack_init() != 0) return -1;
    enum {
        NLMSG_DONE_LOCAL = 3,
        NLM_F_MULTI_LOCAL = 0x2,
        RTM_NEWLINK_LOCAL = 16, RTM_GETLINK_LOCAL = 18,
        RTM_NEWADDR_LOCAL = 20, RTM_GETADDR_LOCAL = 22,
        RTM_NEWROUTE_LOCAL = 24, RTM_GETROUTE_LOCAL = 26,
        IFLA_ADDRESS_LOCAL = 1, IFLA_BROADCAST_LOCAL = 2, IFLA_IFNAME_LOCAL = 3, IFLA_MTU_LOCAL = 4,
        IFLA_LINK_LOCAL = 5, IFLA_QDISC_LOCAL = 6, IFLA_STATS_LOCAL = 7, IFLA_TXQLEN_LOCAL = 13,
        IFLA_OPERSTATE_LOCAL = 16, IFLA_LINKMODE_LOCAL = 17, IFLA_GROUP_LOCAL = 27,
        IFA_ADDRESS_LOCAL = 1, IFA_LOCAL_LOCAL = 2, IFA_LABEL_LOCAL = 3, IFA_FLAGS_LOCAL = 8,
        RTA_DST_LOCAL = 1, RTA_OIF_LOCAL = 4, RTA_GATEWAY_LOCAL = 5, RTA_PREFSRC_LOCAL = 7,
        /* Interface flags */
        IFF_UP_LOCAL = 0x1, IFF_BROADCAST_LOCAL = 0x2, IFF_LOOPBACK_LOCAL = 0x8,
        IFF_RUNNING_LOCAL = 0x40, IFF_NOARP_LOCAL = 0x80, IFF_LOWER_UP_LOCAL = 0x10000,
        IFF_MULTICAST_LOCAL = 0x1000
    };
    size_t off = 0;
    uint16_t msg_type = 0;
    if (req_type == RTM_GETLINK_LOCAL) msg_type = RTM_NEWLINK_LOCAL;
    else if (req_type == RTM_GETADDR_LOCAL) msg_type = RTM_NEWADDR_LOCAL;
    else if (req_type == RTM_GETROUTE_LOCAL) msg_type = RTM_NEWROUTE_LOCAL;
    else return -1;

    if (req_type == RTM_GETLINK_LOCAL) {
        /* Interface 1: lo (loopback) */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifinfomsg_k ifi;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 772; /* ARPHRD_LOOPBACK */
        ifi.ifi_index = 1;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_LOOPBACK_LOCAL | IFF_RUNNING_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "lo", 3) != 0) return -1;
        { uint32_t mtu = 65536; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 0; /* IF_OPER_UNKNOWN */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "noqueue", 8) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Interface 2: eth0 */
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 1; /* ARPHRD_ETHER */
        ifi.ifi_index = 2;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_BROADCAST_LOCAL | IFF_RUNNING_LOCAL | IFF_MULTICAST_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "eth0", 5) != 0) return -1;
        { uint32_t mtu = 1500; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 6; /* IF_OPER_UP */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_ADDRESS_LOCAL, g_net.mac, 6) != 0) return -1;
        { uint8_t brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_BROADCAST_LOCAL, brd, 6) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "fq_codel", 9) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    } else if (req_type == RTM_GETADDR_LOCAL) {
        /* Address for lo: 127.0.0.1/8 */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifaddrmsg_k ifa;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = 8;
        ifa.ifa_scope = 254; /* RT_SCOPE_HOST */
        ifa.ifa_index = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = 0x0100007Fu; /* 127.0.0.1 in little-endian for network order */
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "lo", 3) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Address for eth0 */
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        ifa.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */
        ifa.ifa_index = 2;
        ifa.ifa_flags = 0x80; /* IFA_F_PERMANENT */
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = be32(g_net.ip_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        { uint32_t brd = be32((g_net.ip_be & g_net.mask_be) | ~g_net.mask_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, 4 /* IFA_BROADCAST */, &brd, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "eth0", 5) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    } else {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        rtmsg_k rm;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_table = 254;
        rm.rtm_protocol = 3;
        rm.rtm_scope = 0;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t gw = be32(g_net.gw_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_GATEWAY_LOCAL, &gw, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_dst_len = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        rm.rtm_table = 254;
        rm.rtm_protocol = 2;
        rm.rtm_scope = 253;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t dst = be32(g_net.ip_be & (g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u));
          uint32_t src = be32(g_net.ip_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_DST_LOCAL, &dst, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_PREFSRC_LOCAL, &src, 4) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }

    {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, NLMSG_DONE_LOCAL, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }
    s->nl_rx_len = off;
    s->nl_rx_off = 0;
    return 0;
}

