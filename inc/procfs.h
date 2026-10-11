#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>
#include <stat.h>

int procfs_register(void);
int procfs_unregister(void);
int procfs_mount(const char *path);
int procfs_fill_stat(struct fs_file *file, struct stat *st);

/*
 * /proc/cmdline must expose the command line the firmware/bootloader actually
 * handed us (systemd reads it to resolve TERM and init selection). Captured
 * once from Multiboot2 in core/entry/init.c.
 */
void procfs_set_kernel_cmdline(const char *cmdline, size_t len);

/* /proc/net/* snapshots (syscall64/syscall.c: walks per-thread socket fds). */
ssize_t procfs_net_snap_tcp(char *buf, size_t size);
ssize_t procfs_net_snap_udp(char *buf, size_t size);
ssize_t procfs_net_snap_tcp6(char *buf, size_t size);
ssize_t procfs_net_snap_udp6(char *buf, size_t size);
ssize_t procfs_net_snap_raw(char *buf, size_t size);
ssize_t procfs_net_snap_raw6(char *buf, size_t size);
ssize_t procfs_net_snap_unix(char *buf, size_t size);
ssize_t procfs_net_snap_arp(char *buf, size_t size);
ssize_t procfs_net_snap_dev(char *buf, size_t size);
ssize_t procfs_net_snap_route(char *buf, size_t size);
ssize_t procfs_net_snap_dhcp(char *buf, size_t size);
ssize_t procfs_net_store_dhcp(const char *buf, size_t size);

/* /proc/keys (keyring listing). */
ssize_t procfs_show_keys(char *buf, size_t size);

