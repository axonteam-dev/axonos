#!/usr/bin/env python3
"""Exercise the NETLINK_GENERIC protocol validation used by socket(2)."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int netlink_socket_normalize_protocol(")
end = source.index("\n#define ETH_TYPE_IPV4", start)
helper = source[start:end]
socket_case = source[source.index("case SYS_socket: { /* socket(domain, type, protocol) */"):
                     source.index("case SYS_bind: { /* bind */")]
sendto_case = source[source.index("case 44: { /* sendto */"):
                     source.index("case 45: { /* recvfrom */")]
assert "NETLINK_GENERIC_LOCAL 16" in source
assert "netlink_socket_normalize_protocol(protocol," in socket_case
assert "if (s->protocol != NETLINK_ROUTE_LOCAL) return ret_err(EOPNOTSUPP);" in sendto_case

fixture = r'''
#include <assert.h>
#include <errno.h>
#define NETLINK_ROUTE_LOCAL 0
#define NETLINK_KOBJECT_UEVENT_LOCAL 15
#define NETLINK_GENERIC_LOCAL 16
''' + helper + r'''
int main(void) {
    int normalized = -1;
    assert(netlink_socket_normalize_protocol(0, &normalized) == 0);
    assert(normalized == NETLINK_ROUTE_LOCAL);
    assert(netlink_socket_normalize_protocol(15, &normalized) == 0);
    assert(normalized == NETLINK_KOBJECT_UEVENT_LOCAL);
    assert(netlink_socket_normalize_protocol(16, &normalized) == 0);
    assert(normalized == NETLINK_GENERIC_LOCAL);
    assert(netlink_socket_normalize_protocol(99, &normalized) == -EPROTONOSUPPORT);
    assert(netlink_socket_normalize_protocol(16, 0) == -EINVAL);
}
'''

with tempfile.TemporaryDirectory(prefix="axon-netlink-generic-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: NETLINK_GENERIC sockets accepted; unsupported protocols stay rejected")
