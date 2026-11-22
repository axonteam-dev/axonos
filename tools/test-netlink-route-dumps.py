#!/usr/bin/env python3
"""Check rtnetlink dump and optional-query replies used by systemd-networkd."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("typedef struct __attribute__((packed)) {\n    uint16_t nl_family;")
end = source.index("\nstatic uint64_t last_syscall_debug", start)
handler = source[start:end]
peek_start = source.index("static int netlink_route_event_peek(")
peek_end = source.index("\n}\n", peek_start) + 3
event_peek = source[peek_start:peek_end]
host_start = source.index("#define NET_HOST_ROUTE_MAX")
host_end = source.index("\nstatic inline uint16_t be16", host_start)
host_routes = source[host_start:host_end]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define AF_INET_LOCAL 2
#define AF_INET6 10
#define AF_NETLINK_LOCAL 16
#define NETLINK_ROUTE_LOCAL 0
#define NETLINK_ROUTE_EVENT_DEPTH 16
#define NETLINK_ROUTE_EVENT_SIZE 256
#define KSOCK_REGISTRY_MAX 8
typedef struct { uint64_t cap_effective; } process_t;
typedef struct { process_t *process; uint64_t tid; } thread_t;
static process_t proc = {.cap_effective = 1ULL << 12};
static thread_t current = {.process = &proc, .tid = 7};
static thread_t *thread_get_current_user(void) { return &current; }
static thread_t *thread_current(void) { return &current; }
static int net_stack_init(void) { return 0; }
static int net_set_if_up(int up);
static int fake_link_up = 1;
static int e1000_link_is_up(void) { return fake_link_up; }
static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }
static int ip_mask_prefix_len(uint32_t mask) {
    int n = 0; for (int i = 31; i >= 0 && (mask & (1u << i)); i--) n++; return n;
}
static void klogprintf_logonly(const char *fmt, ...) { (void)fmt; }
typedef struct {
    uint8_t mac[6];
    int if_up;
    int ready;
    uint32_t ip_be, mask_be, gw_be, dns_be;
    int gw_mac_valid;
} net_state_t;
static net_state_t g_net;
static int net_apply_ipv4(uint32_t ip, uint32_t mask, uint32_t gw,
                          uint32_t dns, int from_dhcp) {
    (void)from_dhcp; g_net.ip_be = ip; g_net.mask_be = mask;
    g_net.gw_be = gw; g_net.dns_be = dns; g_net.ready = ip != 0; return 0;
}
static int net_set_if_up(int up) { g_net.if_up = !!up; return 0; }
static int net_delete_default_route(uint32_t gateway) {
    if (!g_net.gw_be || (gateway && gateway != g_net.gw_be)) return -ESRCH;
    g_net.gw_be = 0; g_net.gw_mac_valid = 0; return 0;
}
typedef struct {
    uint8_t data[NETLINK_ROUTE_EVENT_SIZE];
    size_t len;
    uint32_t group;
} netlink_route_event_t;
typedef struct {
    int sock_domain, protocol;
    uint32_t nl_pid;
    uint64_t nl_memberships;
    uint8_t nl_rx[8192];
    size_t nl_rx_len, nl_rx_off;
    unsigned nl_route_head, nl_route_count;
    netlink_route_event_t nl_route_events[NETLINK_ROUTE_EVENT_DEPTH];
} ksock_net_t;
static ksock_net_t *g_ksock_registry[KSOCK_REGISTRY_MAX];
typedef int spinlock_t;
static spinlock_t g_ksock_registry_lock;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    (void)lock; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)lock; (void)flags;
}
''' + host_routes + event_peek + handler + r'''
static void check_optional_error(uint16_t type, uint32_t seq) {
    ksock_net_t sock = {.nl_pid = 123};
    nlmsghdr_k request = {.nlmsg_len = sizeof(request), .nlmsg_type = type,
                          .nlmsg_seq = seq, .nlmsg_pid = 123};
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    assert(sock.nl_rx_len == sizeof(nlmsghdr_k) + sizeof(int32_t) + sizeof(request));
    const nlmsghdr_k *reply = (const nlmsghdr_k *)sock.nl_rx;
    int32_t error = 0;
    memcpy(&error, sock.nl_rx + sizeof(*reply), sizeof(error));
    assert(reply->nlmsg_type == 2 /* NLMSG_ERROR */);
    assert(reply->nlmsg_seq == seq);
    assert(error == -EOPNOTSUPP);
}
static uint32_t link_flags_for(int index) {
    ksock_net_t sock = {.nl_pid = 123};
    struct {
        nlmsghdr_k header;
        ifinfomsg_k info;
    } request = {
        .header = {.nlmsg_len = sizeof(request),
                   .nlmsg_type = 18 /* RTM_GETLINK */,
                   .nlmsg_flags = 0x301 /* REQUEST|ROOT|MATCH */,
                   .nlmsg_seq = 306, .nlmsg_pid = 123},
        .info = {.ifi_family = 0, .ifi_index = 0},
    };
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    size_t off = 0;
    while (off + sizeof(nlmsghdr_k) <= sock.nl_rx_len) {
        const nlmsghdr_k *header = (const nlmsghdr_k *)(sock.nl_rx + off);
        assert(header->nlmsg_len >= sizeof(*header));
        assert(header->nlmsg_len <= sock.nl_rx_len - off);
        if (header->nlmsg_type == 16 /* RTM_NEWLINK */ &&
            header->nlmsg_len >= sizeof(*header) + sizeof(ifinfomsg_k)) {
            const ifinfomsg_k *ifi = (const ifinfomsg_k *)(header + 1);
            if (ifi->ifi_index == index)
                return ifi->ifi_flags;
        }
        off += nl_align4(header->nlmsg_len);
    }
    assert(!"link missing from RTM_GETLINK dump");
    return 0;
}
static void check_single_link_query(void) {
    struct {
        nlmsghdr_k header;
        ifinfomsg_k info;
    } request = {
        .header = {.nlmsg_len = sizeof(request),
                   .nlmsg_type = 18 /* RTM_GETLINK */,
                   .nlmsg_flags = 1 /* NLM_F_REQUEST */,
                   .nlmsg_seq = 308, .nlmsg_pid = 123},
        .info = {.ifi_family = 0, .ifi_index = 2},
    };
    ksock_net_t sock = {.nl_pid = 123};
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    assert(sock.nl_rx_off == 0);
    assert(sock.nl_rx_len >= sizeof(nlmsghdr_k) + sizeof(ifinfomsg_k));
    const nlmsghdr_k *reply = (const nlmsghdr_k *)sock.nl_rx;
    assert(reply->nlmsg_type == 16 /* RTM_NEWLINK */);
    assert(reply->nlmsg_flags == 0);
    assert(reply->nlmsg_seq == 308 && reply->nlmsg_pid == 123);
    assert(reply->nlmsg_len == sock.nl_rx_len); /* no unrelated link or NLMSG_DONE */
    const ifinfomsg_k *info = (const ifinfomsg_k *)(reply + 1);
    assert(info->ifi_index == 2);
}
static void check_link_name_query(void) {
    struct {
        nlmsghdr_k header;
        ifinfomsg_k info;
        rtattr_k name_attr;
        char name[5];
    } request = {
        .header = {.nlmsg_len = sizeof(request),
                   .nlmsg_type = 18 /* RTM_GETLINK */,
                   .nlmsg_flags = 1 /* NLM_F_REQUEST */,
                   .nlmsg_seq = 309, .nlmsg_pid = 123},
        .info = {.ifi_family = 0, .ifi_index = 0},
        .name_attr = {.rta_len = sizeof(rtattr_k) + 5, .rta_type = 3},
        .name = "eth0",
    };
    ksock_net_t sock = {.nl_pid = 123};
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    const nlmsghdr_k *reply = (const nlmsghdr_k *)sock.nl_rx;
    assert(reply->nlmsg_type == 16 /* RTM_NEWLINK */);
    assert(reply->nlmsg_seq == 309 && reply->nlmsg_pid == 123);
    assert(reply->nlmsg_len == sock.nl_rx_len);
    const ifinfomsg_k *info = (const ifinfomsg_k *)(reply + 1);
    assert(info->ifi_index == 2);
}
static void change_link_flags(uint16_t type, uint32_t flags, uint32_t change) {
    struct {
        nlmsghdr_k header;
        ifinfomsg_k info;
    } request;
    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = type;
    request.header.nlmsg_seq = 307;
    request.header.nlmsg_pid = 123;
    request.info.ifi_index = 2;
    request.info.ifi_flags = flags;
    request.info.ifi_change = change;

    ksock_net_t sock = {.nl_pid = 123};
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    assert(sock.nl_rx_len == sizeof(nlmsghdr_k) + sizeof(int32_t) +
                            sizeof(nlmsghdr_k));
    const int32_t *error = (const int32_t *)(sock.nl_rx + sizeof(nlmsghdr_k));
    assert(*error == 0);
}
static void check_address_notifications(void) {
    ksock_net_t sender = {.nl_pid = 123, .sock_domain = AF_NETLINK_LOCAL,
                          .protocol = NETLINK_ROUTE_LOCAL, .nl_memberships = 1u << 4};
    ksock_net_t subscriber = {.sock_domain = AF_NETLINK_LOCAL, .protocol = NETLINK_ROUTE_LOCAL,
                              .nl_memberships = 1u << 4};
    ksock_net_t other = {.sock_domain = AF_NETLINK_LOCAL, .protocol = NETLINK_ROUTE_LOCAL};
    g_ksock_registry[0] = &sender;
    g_ksock_registry[1] = &subscriber;
    g_ksock_registry[2] = &other;
    struct {
        nlmsghdr_k header;
        ifaddrmsg_k ifa;
        rtattr_k attr;
        uint32_t ip;
    } request = {
        .header = {.nlmsg_len = sizeof(request), .nlmsg_type = 20, .nlmsg_seq = 99},
        .ifa = {.ifa_family = AF_INET_LOCAL, .ifa_prefixlen = 24, .ifa_index = 2},
        .attr = {.rta_len = 8, .rta_type = 2}, .ip = 0x0f02000au,
    };
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(g_net.ip_be == 0x0a00020fu);
    assert(sender.nl_rx_len > 0); /* independent ACK */
    assert(sender.nl_route_count == 1 && subscriber.nl_route_count == 1);
    assert(other.nl_route_count == 0);
    netlink_route_event_t event;
    assert(netlink_route_event_peek(&subscriber, &event, 0));
    assert(event.group == 5);
    const nlmsghdr_k *header = (const nlmsghdr_k *)event.data;
    assert(header->nlmsg_type == 20 && header->nlmsg_seq == 0 && header->nlmsg_pid == 0);
    const ifaddrmsg_k *ifa = (const ifaddrmsg_k *)(header + 1);
    assert(ifa->ifa_index == 2 && ifa->ifa_prefixlen == 24);
    uint32_t ip;
    assert(netlink_get_attr_u32((const uint8_t *)(ifa + 1),
                                header->nlmsg_len - sizeof(*header) - sizeof(*ifa),
                                2, &ip) == 0 && ip == request.ip);
    assert(netlink_route_event_peek(&subscriber, &event, 1));
    assert(!netlink_route_event_peek(&subscriber, NULL, 0));
    request.header.nlmsg_type = 21; /* RTM_DELADDR */
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(netlink_route_event_peek(&subscriber, &event, 1));
    assert(((const nlmsghdr_k *)event.data)->nlmsg_type == 21);
    g_ksock_registry[0] = g_ksock_registry[1] = g_ksock_registry[2] = NULL;
}
static void check_dhcp_host_and_default_routes(void) {
    ksock_net_t sender = {.nl_pid = 123, .sock_domain = AF_NETLINK_LOCAL,
                          .protocol = NETLINK_ROUTE_LOCAL, .nl_memberships = 1u << 6};
    ksock_net_t monitor = {.sock_domain = AF_NETLINK_LOCAL,
                           .protocol = NETLINK_ROUTE_LOCAL, .nl_memberships = 1u << 6};
    g_ksock_registry[0] = &sender;
    g_ksock_registry[1] = &monitor;
    struct {
        nlmsghdr_k h;
        rtmsg_k route;
        rtattr_k dst_attr;
        uint32_t dst;
        rtattr_k oif_attr;
        uint32_t oif;
    } request = {
        .h = {.nlmsg_len = sizeof(request), .nlmsg_type = 24,
              .nlmsg_flags = 0x600, .nlmsg_seq = 123},
        .route = {.rtm_family = AF_INET_LOCAL, .rtm_dst_len = 32, .rtm_table = 254,
                  .rtm_protocol = 16, .rtm_scope = 253, .rtm_type = 1},
        .dst_attr = {.rta_len = 8, .rta_type = 1}, .dst = 0x0202000au,
        .oif_attr = {.rta_len = 8, .rta_type = 4}, .oif = 2,
    };
    g_net.ready = 1;
    g_net.ip_be = 0x0a00020fu;
    g_net.mask_be = 0xffffff00u;
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(*(int32_t *)(sender.nl_rx + sizeof(nlmsghdr_k)) == 0);
    assert(net_host_route_is_direct(0x0a000202u));
    assert(!net_host_route_is_direct(0x0a000203u));
    assert(!g_net.gw_be); /* A host route must never become the default gateway. */
    netlink_route_event_t event;
    assert(netlink_route_event_peek(&monitor, &event, 1));
    const nlmsghdr_k *notify = (const nlmsghdr_k *)event.data;
    assert(event.group == 7 && notify->nlmsg_type == 24);
    assert(notify->nlmsg_seq == 0 && notify->nlmsg_pid == 0 && notify->nlmsg_flags == 0);
    assert(event.len == sizeof(request));

    ksock_net_t dump = {.nl_pid = 123};
    assert(netlink_build_route_dump(&dump, 26, 55, 0, 1) == 0);
    const nlmsghdr_k *host = (const nlmsghdr_k *)dump.nl_rx;
    assert(host->nlmsg_type == 24 && host->nlmsg_seq == 55);
    const rtmsg_k *host_route = (const rtmsg_k *)(host + 1);
    assert(host_route->rtm_dst_len == 32 && host_route->rtm_scope == 253);

    /* A duplicate exclusive add fails and publishes no event. */
    sender.nl_rx_len = sender.nl_rx_off = 0;
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(*(int32_t *)(sender.nl_rx + sizeof(nlmsghdr_k)) == -EEXIST);
    assert(!netlink_route_event_peek(&monitor, NULL, 0));

    request.h.nlmsg_type = 21 + 4; /* RTM_DELROUTE */
    sender.nl_rx_len = sender.nl_rx_off = 0;
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(!net_host_route_is_direct(0x0a000202u));
    assert(netlink_route_event_peek(&monitor, &event, 1));
    assert(((nlmsghdr_k *)event.data)->nlmsg_type == 25);

    request.h.nlmsg_type = 24;
    request.h.nlmsg_flags = 0x400;
    request.route.rtm_dst_len = 0;
    request.route.rtm_scope = 0;
    request.dst_attr.rta_type = 5; /* RTA_GATEWAY */
    sender.nl_rx_len = sender.nl_rx_off = 0;
    assert(netlink_apply_request(&sender, (const uint8_t *)&request, sizeof(request)) == 0);
    assert(g_net.gw_be == 0x0a000202u);
    assert(netlink_route_event_peek(&monitor, &event, 1));
    assert(((nlmsghdr_k *)event.data)->nlmsg_type == 24);
    g_ksock_registry[0] = g_ksock_registry[1] = NULL;
}
int main(void) {
    check_optional_error(38 /* RTM_GETQDISC */, 101);
    check_optional_error(42 /* RTM_GETTCLASS */, 102);
    check_optional_error(34 /* RTM_GETRULE */, 103);
    check_optional_error(106 /* RTM_GETNEXTHOP */, 104);

    ksock_net_t sock = {.nl_pid = 123};
    nlmsghdr_k request = {.nlmsg_len = sizeof(request),
                          .nlmsg_type = 30 /* RTM_GETNEIGH */,
                          .nlmsg_seq = 205, .nlmsg_pid = 123};
    assert(netlink_apply_request(&sock, (const uint8_t *)&request,
                                 sizeof(request)) == 0);
    assert(sock.nl_rx_len == sizeof(nlmsghdr_k));
    const nlmsghdr_k *done = (const nlmsghdr_k *)sock.nl_rx;
    assert(done->nlmsg_type == 3 /* NLMSG_DONE */);
    assert(done->nlmsg_flags & 2 /* NLM_F_MULTI */);
    assert(done->nlmsg_seq == 205);
    assert(done->nlmsg_pid == 123);

    check_single_link_query();
    check_link_name_query();

    /* Report the real admin state so networkd brings eth0 up and starts RX. */
    const uint32_t admin_link = 0x1u | 0x40u | 0x10000u;
    const uint32_t link_base = 0x2u | 0x1000u;
    g_net.if_up = 0;
    fake_link_up = 1;
    assert((link_flags_for(2) & (admin_link | link_base)) == link_base);
    change_link_flags(16 /* RTM_NEWLINK */, 0x1u, 0x1u /* IFF_UP */);
    assert(g_net.if_up);
    assert((link_flags_for(2) & (admin_link | link_base)) ==
           (admin_link | link_base));

    /* Attribute-only updates carry no IFF_UP change mask and must preserve it. */
    change_link_flags(19 /* RTM_SETLINK */, 0, 0);
    assert(g_net.if_up);
    fake_link_up = 0;
    assert((link_flags_for(2) & admin_link) == 0x1u);
    change_link_flags(19 /* RTM_SETLINK */, 0, 0x1u /* IFF_UP */);
    assert(!g_net.if_up);
    check_address_notifications();
    check_dhcp_host_and_default_routes();

    puts("PASS: rtnetlink dumps, DHCP host/default routes, and multicast notifications");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-netlink-dumps-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
