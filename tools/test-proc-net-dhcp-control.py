#!/usr/bin/env python3
"""Check the /proc/net/dhcp control write used by `echo 1 > /proc/net/dhcp`."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
procfs = (root / "fs/virt/procfs.c").read_text()

start = dispatch.index("ssize_t procfs_net_store_dhcp(")
end = dispatch.index("\n}\n", start) + 3
store = dispatch[start:end]

# The shell's "echo 1 > /proc/net/dhcp" opens the procfs control with O_TRUNC.
# The VFS must accept that (pseudo-fs no-op) and the file must be writable for
# root so the store callback is reached at all.
stat_start = procfs.index("int procfs_fill_stat(")
stat_end = procfs.index("\n}\n", stat_start) + 3
assert "h->kind == 7 && h->file_id == 60" in procfs[stat_start:stat_end]
assert "S_IFREG | 0644" in procfs[stat_start:stat_end]
assert "if (fs_open_truncate_is_noop(file)) return 0;" in dispatch

program = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef struct process { int unused; } process_t;
typedef struct thread { process_t *process; uint32_t euid; } thread_t;

static thread_t g_thread = { .euid = 0 };
static int g_capable = 1;
static int g_net_dhcp_pending;
static int g_net_dhcp_cancel;
static int dhcp_requests;
static int dhcp_applies;

static thread_t *thread_current(void) { return &g_thread; }
static thread_t *thread_get_current_user(void) { return &g_thread; }

#define AXON_CAP_NET_ADMIN 12
static __attribute__((unused)) int
syscall_task_capable(const thread_t *task, unsigned capability) {
    (void)task;
    (void)capability;
    return g_capable;
}

static int net_request_dhcp(void) {
    dhcp_requests++;
    g_net_dhcp_pending = 1;
    return 0;
}

static int net_apply_ipv4(uint32_t ip, uint32_t mask, uint32_t gw,
                          uint32_t dns, int from_dhcp) {
    (void)ip; (void)mask; (void)gw; (void)dns; (void)from_dhcp;
    dhcp_applies++;
    return 0;
}
''' + store + r'''

int main(void) {
    assert(procfs_net_store_dhcp(NULL, 4) == -EFAULT);
    assert(procfs_net_store_dhcp("1\n", 0) == 0);

    g_capable = 0;
    g_thread.euid = 1;
    assert(procfs_net_store_dhcp("1\n", 2) == -EPERM);
    assert(dhcp_requests == 0);
    g_capable = 1;
    g_thread.euid = 0;

    /* "echo 1 > /proc/net/dhcp" writes "1\n" and requests a lease. */
    assert(procfs_net_store_dhcp("1\n", 2) == 2);
    assert(dhcp_requests == 1 && g_net_dhcp_pending == 1);

    assert(procfs_net_store_dhcp("renew\n", 6) == 6);
    assert(dhcp_requests == 2);

    /* "echo 0 > /proc/net/dhcp" drops the address and cancels a pending run. */
    assert(procfs_net_store_dhcp("0\n", 2) == 2);
    assert(dhcp_applies == 1 && g_net_dhcp_cancel == 1 &&
           g_net_dhcp_pending == 0);

    assert(procfs_net_store_dhcp("garbage\n", 8) == -EINVAL);
    puts("PASS: /proc/net/dhcp accepts 1/renew and 0/release with CAP_NET_ADMIN");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-proc-dhcp-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
