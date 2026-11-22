#!/usr/bin/env python3
"""Test sysfs network-class publication and the udev add event path."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("enum {\n    NET_SYSFS_UEVENT = 1,")
end = source.index("\nstatic int net_set_if_up(", start)
implementation = source[start:end]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#define AF_NETLINK_LOCAL 16
#define NETLINK_KOBJECT_UEVENT_LOCAL 15
#define KSOCK_REGISTRY_MAX 8
typedef int spinlock_t;
static spinlock_t g_ksock_registry_lock;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    (void)lock; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)lock; (void)flags;
}
typedef struct {
    int sock_domain, protocol;
    uint32_t nl_pid, nl_groups;
    uint8_t nl_rx[8192];
    size_t nl_rx_len, nl_rx_off;
    uint32_t nl_rx_sender_pid, nl_rx_sender_groups, nl_rx_cred_pid;
    uint32_t nl_rx_sender_uid, nl_rx_sender_gid;
} ksock_net_t;
static ksock_net_t *g_ksock_registry[KSOCK_REGISTRY_MAX];
static uint32_t g_kobject_uevent_seqnum;
static struct { uint8_t mac[6]; int if_up; } g_net = {
    .mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
};
static int fake_link_up = 1;
static int e1000_link_is_up(void) { return fake_link_up; }
static int net_stack_init(void) { return 0; }
typedef ssize_t (*sysfs_show_t)(char *, size_t, void *);
typedef ssize_t (*sysfs_store_t)(const char *, size_t, void *);
struct sysfs_attr { sysfs_show_t show; sysfs_store_t store; void *priv; };
typedef struct { char path[128]; struct sysfs_attr attr; mode_t mode; } file_record_t;
typedef struct { char path[128], target[128]; } link_record_t;
static file_record_t files[64];
static link_record_t links[16];
static size_t file_count, link_count;
static int sysfs_mkdir(const char *path) { (void)path; return 0; }
static int sysfs_create_file(const char *path, const struct sysfs_attr *attr) {
    assert(file_count < sizeof(files) / sizeof(files[0]));
    snprintf(files[file_count].path, sizeof(files[file_count].path), "%s", path);
    files[file_count++].attr = *attr;
    return 0;
}
static int sysfs_create_symlink(const char *path, const char *target) {
    assert(link_count < sizeof(links) / sizeof(links[0]));
    snprintf(links[link_count].path, sizeof(links[link_count].path), "%s", path);
    snprintf(links[link_count++].target, sizeof(links[0].target), "%s", target);
    return 0;
}
static int sysfs_chmod(const char *path, mode_t mode) {
    for (size_t i = 0; i < file_count; i++) {
        if (strcmp(files[i].path, path) == 0) {
            files[i].mode = mode;
            return 0;
        }
    }
    return -1;
}
''' + implementation + r'''
static file_record_t *find_file(const char *path) {
    for (size_t i = 0; i < file_count; i++)
        if (strcmp(files[i].path, path) == 0) return &files[i];
    return NULL;
}
static int has_field(const ksock_net_t *sock, const char *field) {
    size_t off = 0;
    while (off < sock->nl_rx_len) {
        const char *item = (const char *)sock->nl_rx + off;
        if (strcmp(item, field) == 0) return 1;
        off += strlen(item) + 1;
    }
    return 0;
}
int main(void) {
    syscall_net_sysfs_publish();
    file_record_t *index = find_file("/sys/devices/virtual/net/eth0/ifindex");
    file_record_t *address = find_file("/sys/devices/virtual/net/eth0/address");
    file_record_t *state = find_file("/sys/devices/virtual/net/eth0/operstate");
    file_record_t *uevent = find_file("/sys/devices/virtual/net/eth0/uevent");
    assert(index && address && state && uevent && uevent->attr.store);
    /* networkd runs unprivileged and reads uevent while enumerating devices. */
    assert(uevent->mode == (S_IFREG | 0644));
    char value[128] = {0};
    assert(uevent->attr.show(value, sizeof(value), uevent->attr.priv) > 0);
    assert(strcmp(value, "INTERFACE=eth0\nIFINDEX=2\n") == 0);
    memset(value, 0, sizeof(value));
    assert(index->attr.show(value, sizeof(value), index->attr.priv) == 2);
    assert(strcmp(value, "2\n") == 0);
    memset(value, 0, sizeof(value));
    assert(address->attr.show(value, sizeof(value), address->attr.priv) > 0);
    assert(strcmp(value, "02:00:00:00:00:02\n") == 0);
    memset(value, 0, sizeof(value));
    assert(state->attr.show(value, sizeof(value), state->attr.priv) == 5);
    assert(strcmp(value, "down\n") == 0);
    g_net.if_up = 1;
    memset(value, 0, sizeof(value));
    assert(state->attr.show(value, sizeof(value), state->attr.priv) == 3);
    assert(strcmp(value, "up\n") == 0);

    int found_class_link = 0;
    for (size_t i = 0; i < link_count; i++)
        if (strcmp(links[i].path, "/sys/class/net/eth0") == 0 &&
            strcmp(links[i].target, "../../devices/virtual/net/eth0") == 0)
            found_class_link = 1;
    assert(found_class_link);

    ksock_net_t subscribed = {.sock_domain = AF_NETLINK_LOCAL,
                              .protocol = NETLINK_KOBJECT_UEVENT_LOCAL,
                              .nl_groups = 1};
    ksock_net_t unbound = {.sock_domain = AF_NETLINK_LOCAL,
                           .protocol = NETLINK_KOBJECT_UEVENT_LOCAL};
    g_ksock_registry[0] = &subscribed;
    g_ksock_registry[1] = &unbound;
    assert(uevent->attr.store("add\n", 4, uevent->attr.priv) == 4);
    assert(subscribed.nl_rx_len > 0);
    assert(strcmp((char *)subscribed.nl_rx,
                  "add@/devices/virtual/net/eth0") == 0);
    assert(has_field(&subscribed, "ACTION=add"));
    assert(has_field(&subscribed, "SUBSYSTEM=net"));
    assert(has_field(&subscribed, "INTERFACE=eth0"));
    assert(has_field(&subscribed, "IFINDEX=2"));
    assert(has_field(&subscribed, "SEQNUM=1"));
    assert(subscribed.nl_rx_sender_pid == 0);
    assert(subscribed.nl_rx_sender_groups == 1);
    assert(subscribed.nl_rx_cred_pid == 0);
    assert(subscribed.nl_rx_sender_uid == 0 && subscribed.nl_rx_sender_gid == 0);
    assert(unbound.nl_rx_len == 0);

    /* udevd's processed-device notification uses multicast group 2. */
    ksock_net_t udev_sender = {.sock_domain = AF_NETLINK_LOCAL,
                               .protocol = NETLINK_KOBJECT_UEVENT_LOCAL};
    ksock_net_t udev_monitor = {.sock_domain = AF_NETLINK_LOCAL,
                                .protocol = NETLINK_KOBJECT_UEVENT_LOCAL,
                                .nl_groups = 2};
    ksock_net_t udev_worker = {.sock_domain = AF_NETLINK_LOCAL,
                               .protocol = NETLINK_KOBJECT_UEVENT_LOCAL,
                               .nl_pid = 5678};
    g_ksock_registry[2] = &udev_sender;
    g_ksock_registry[3] = &udev_monitor;
    g_ksock_registry[4] = &udev_worker;
    const char udev_message[] = "libudev\0header\0ACTION=add\0";
    assert(netlink_uevent_deliver(&udev_sender, udev_message,
                                  sizeof(udev_message), 0, 2,
                                  77, 123, 0, 0) == 0);
    assert(udev_monitor.nl_rx_len == sizeof(udev_message));
    assert(memcmp(udev_monitor.nl_rx, udev_message,
                  sizeof(udev_message)) == 0);
    assert(udev_monitor.nl_rx_sender_pid == 77);
    assert(udev_monitor.nl_rx_sender_groups == 2);
    assert(udev_monitor.nl_rx_cred_pid == 123);
    assert(udev_monitor.nl_rx_sender_uid == 0 &&
           udev_monitor.nl_rx_sender_gid == 0);
    assert(udev_sender.nl_rx_len == 0); /* no multicast loopback */
    assert(subscribed.nl_rx_len > 0); /* group-1 kernel event is untouched */

    /* Workers accept unicast only from the manager socket's bound port ID. */
    assert(netlink_uevent_deliver(&udev_sender, udev_message,
                                  sizeof(udev_message), 5678, 0,
                                  77, 123, 0, 0) == 0);
    assert(udev_worker.nl_rx_len == sizeof(udev_message));
    assert(udev_worker.nl_rx_sender_pid == 77);
    assert(udev_worker.nl_rx_sender_groups == 0);
    assert(udev_worker.nl_rx_cred_pid == 123);
    puts("PASS: kernel uevents and userspace UDEV multicast with credentials");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-sysfs-net-", dir="/tmp/opencode") as tmp:
    source_path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source_path.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(source_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
