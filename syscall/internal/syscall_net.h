#pragma once

#include <net_tcp.h>
#include <spinlock.h>
#include <fs.h>

/* ---------- Minimal IPv4/ICMP raw socket backend (for ping) ---------- */
#define SYSCALL_FTYPE_SOCKET  0x534F434Bu

#define AF_INET_LOCAL         2
#define AF_UNSPEC             0   /* treat as AF_INET for getaddrinfo fallback */
#define AF_INET6              10  /* Linux value; we stub to AF_INET */
#define AF_NETLINK_LOCAL      16
#define SOCK_STREAM_LOCAL     1
#define SOCK_DGRAM_LOCAL      2
#define SOCK_RAW_LOCAL        3
/* Linux: SOCK_NONBLOCK == O_NONBLOCK (glibc sets this in socket type / fcntl). */
#define O_NONBLOCK_LINUX      0x800
/* F_GETFL must include accmode; 0 breaks glibc fdopen/wget (bogus "out of memory"). */
#define O_RDWR_LINUX          2
#define IPPROTO_ICMP_LOCAL    1
#define IPPROTO_TCP_LOCAL     6
#define IPPROTO_UDP_LOCAL     17
#define NETLINK_ROUTE_LOCAL   0

#define ETH_TYPE_IPV4         0x0800
#define ETH_TYPE_ARP          0x0806

typedef struct unix_stream_conn {
    uint8_t q01[8192];
    size_t q01_head;
    size_t q01_tail;
    size_t q01_count;
    uint8_t q10[8192];
    size_t q10_head;
    size_t q10_tail;
    size_t q10_count;
    int closed[2];
    int refs;
    spinlock_t lock;
} unix_stream_conn_t;

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
    uint16_t len;
    uint16_t csum;
} udp_hdr_t;

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

typedef struct __attribute__((packed)) {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} arp_hdr_t;

typedef struct {
    int sock_domain;
    /* socket(AF_INET6) is IPv4 internally; getsockname must still report v4-mapped sockaddr_in6. */
    int ipv6_stub;
    /* socket(AF_UNIX) is created as IPv4 internally; nscd uses connect(sockaddr_un). */
    int unix_domain_stub;
    int unix_bound;
    int unix_listening;
    char unix_path[108];
    /* AF_UNIX stream endpoint/listener state */
    struct unix_stream_conn *unix_conn;
    int unix_end; /* 0 or 1 endpoint index inside unix_conn */
    struct fs_file *unix_accept_q[16];
    int unix_accept_head;
    int unix_accept_tail;
    int unix_accept_count;
    spinlock_t unix_accept_lock;
    int type_base;
    int protocol;
    int connected;
    uint32_t peer_ip_be;
    uint16_t peer_port;
    uint16_t local_port;
    int rx_has_pending;
    size_t rx_pending_len;
    size_t rx_pending_off;
    uint32_t rx_pending_src_ip_be;
    uint16_t rx_pending_src_port;
    uint8_t rx_pending[2048];
    uint32_t last_dst_ip_be;
    uint16_t last_echo_id;
    uint16_t last_echo_seq;
    uint16_t next_echo_seq;
    uint32_t last_rx_src_ip_be;
    uint16_t last_rx_echo_id;
    uint16_t last_rx_echo_seq;
    uint64_t last_rx_echo_ms;
    int last_req_ts_fmt;
    size_t last_req_len;
    uint8_t last_req[2048];
    uint32_t nl_pid;
    uint32_t nl_groups;
    uint32_t nl_peer_pid;
    uint8_t nl_rx[8192];
    size_t nl_rx_len;
    size_t nl_rx_off;
    /* glibc tries TCP :53 first; many routers RST -> ECONNREFUSED. Fake connect and use UDP for DNS. */
    int dns_tcp_udp_bridge;
    int nonblock; /* O_NONBLOCK: recv must not fake-EAGAIN after an internal short timeout */
    int tcp_listening; /* INET stream socket in listen() state */
    net_tcp_conn_t tcp;
    int kref; /* references from fs_file handles sharing this ksock */
} ksock_net_t;

typedef struct {
    int inited;
    int ready;
    uint8_t mac[6];
    uint32_t ip_be;
    uint32_t mask_be;
    uint32_t gw_be;
    uint32_t dns_be;
    uint16_t ip_id;
    uint8_t gw_mac[6];
    int gw_mac_valid;
} net_state_t;

typedef struct __attribute__((packed)) {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
} sockaddr_nl_k;

typedef struct __attribute__((packed)) {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
} nlmsghdr_k;


typedef struct __attribute__((packed)) {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
} sockaddr_in_k;

typedef struct __attribute__((packed)) {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
} sockaddr_in6_k;


extern volatile int g_net_tcp_connect_active;
extern int g_net_tcp_sniff_left;
extern uint8_t g_tcp_xmit_mac[6];
extern int g_tcp_xmit_mac_valid;

static inline uint16_t be16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint32_t be32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

void net_pump_all_tcp(thread_t *cur);

int unix_sockaddr_path_from_user(const void *addr_u, size_t addrlen, char *out, size_t out_cap, int *is_abstract);
int unix_acceptq_push(ksock_net_t *listener, struct fs_file *pending_f);
struct fs_file *unix_acceptq_pop(ksock_net_t *listener);
ksock_net_t *unix_find_listener_by_path(const char *path);
size_t unix_stream_avail_to_read(const ksock_net_t *s);
size_t unix_stream_avail_to_write(const ksock_net_t *s);
int unix_stream_peer_closed(const ksock_net_t *s);
ssize_t unix_stream_write_from_user(ksock_net_t *s, const void *buf_u, size_t len);
ssize_t unix_stream_read_to_user(ksock_net_t *s, void *buf_u, size_t len, int peek);
void ksock_rx_pending_normalize(ksock_net_t *s);
size_t ksock_rx_pending_avail(const ksock_net_t *s);
void ksock_rx_pending_install(ksock_net_t *s, int rn);
void net_nic_drain_to_rxq(int budget);
void net_pump_listen_handshake(void);
void net_rxq_flush(void);
int net_rxq_peek_udp_payload_for_sock(ksock_net_t *s);
int ip_same_subnet(uint32_t a_be, uint32_t b_be, uint32_t mask_be);
int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms);
int net_send_udp_datagram(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t payload_len);
uint16_t net_alloc_ephemeral_port(void);
int net_recv_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be, uint16_t *out_src_port);
int net_udp_recv_into_pending(ksock_net_t *s);
void net_make_tcp_ops(net_tcp_ops_t *ops, net_tcp_conn_t *match);
void fork_inherit_fd_table(thread_t *child, thread_t *parent);
ksock_net_t *net_tcp_find_listener(uint16_t port);
void net_pump_tcp_sock(ksock_net_t *s, int rounds);
int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq);
int net_send_icmp_echo(ksock_net_t *s, uint32_t dst_ip_be, const uint8_t *icmp, size_t icmp_len);
int net_recv_icmp_echo_reply(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be);
int net_detect_ping_ts_fmt(const uint8_t *payload, size_t payload_len);
int net_send_icmp_echo_timer_compat(ksock_net_t *s);
struct fs_file *socket_file_get(thread_t *cur, int fd, ksock_net_t **out_sock);
void net_debug_log_tls443_tx(ksock_net_t *s, const uint8_t *buf, size_t len, const char *path);
void sockaddr_in6_v4mapped_fill(sockaddr_in6_k *s6, uint32_t ip_be, uint16_t port_host);
int user_sockaddr_to_ipv4_peer(const void *addr_u, size_t addrlen, sockaddr_in_k *out);
int fs_mkdir_errno(int r);
