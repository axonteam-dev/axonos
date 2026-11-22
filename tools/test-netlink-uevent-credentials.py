#!/usr/bin/env python3
"""Test the SCM_CREDENTIALS ancillary message used by udev netlink."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()

start = source.index("static size_t netlink_uevent_credentials_cmsg(")
end = source.index("\nstatic struct fs_file *scm_fd_lookup(", start)
implementation = source[start:end]

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SOL_SOCKET_LINUX 1
#define SCM_CREDENTIALS_LINUX 2
typedef struct {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
} cmsghdr_k;
''' + implementation + r'''
int main(void) {
    uint8_t control[40];
    memset(control, 0xa5, sizeof(control));
    assert(netlink_uevent_credentials_cmsg(control, 32, 0, 0, 0) == 32);

    cmsghdr_k header;
    memcpy(&header, control, sizeof(header));
    assert(header.cmsg_len == 28); /* CMSG_LEN(sizeof(struct ucred)) */
    assert(header.cmsg_level == SOL_SOCKET_LINUX);
    assert(header.cmsg_type == SCM_CREDENTIALS_LINUX);

    uint32_t credentials[3] = {1, 1, 1};
    memcpy(credentials, control + sizeof(header), sizeof(credentials));
    assert(credentials[0] == 0); /* kernel sender */
    assert(credentials[1] == 0);
    assert(credentials[2] == 0);
    assert(control[28] == 0 && control[29] == 0 &&
           control[30] == 0 && control[31] == 0); /* CMSG_SPACE padding */

    memset(control, 0, sizeof(control));
    assert(netlink_uevent_credentials_cmsg(control, 32, 123, 1000, 1001) == 32);
    memcpy(&header, control, sizeof(header));
    assert(header.cmsg_len == 28);
    memcpy(credentials, control + sizeof(header), sizeof(credentials));
    assert(credentials[0] == 123 && credentials[1] == 1000 &&
           credentials[2] == 1001); /* userspace UDEV multicast sender */

    memset(control, 0xa5, sizeof(control));
    assert(netlink_uevent_credentials_cmsg(control, 31, 0, 0, 0) == 0);
    assert(control[0] == 0xa5); /* insufficient space leaves output untouched */
    assert(netlink_uevent_credentials_cmsg(NULL, sizeof(control), 0, 0, 0) == 0);
    puts("PASS: kernel/user uevent credentials cmsg layout and truncation boundary");
}
'''

setsockopt_start = source.index("case 54: { /* setsockopt */")
setsockopt_end = source.index("case 55: { /* getsockopt */", setsockopt_start)
setsockopt = source[setsockopt_start:setsockopt_end]
assert "optname == 16 /* SO_PASSCRED */" in setsockopt
assert "s->sock_domain == AF_NETLINK_LOCAL" in setsockopt
assert "s->protocol == NETLINK_KOBJECT_UEVENT_LOCAL" in setsockopt
assert "s->passcred = !!enabled;" in setsockopt

recvmsg_start = source.index("case 47: { /* recvmsg */")
recvmsg_end = source.index("case SYS_sysinfo:", recvmsg_start)
recvmsg = source[recvmsg_start:recvmsg_end]
assert "s->protocol == NETLINK_KOBJECT_UEVENT_LOCAL && s->passcred" in recvmsg
assert "netlink_uevent_credentials_cmsg(" in recvmsg
assert "m.msg_controllen = clen;" in recvmsg
assert "m.msg_flags |= MSG_CTRUNC_LINUX;" in recvmsg
assert "s->nl_rx_len = s->nl_rx_off = 0;" in recvmsg

sendmsg_start = source.index("case 46: { /* sendmsg -> map to sendto for first iov */")
sendmsg_end = source.index("case 307: { /* sendmmsg", sendmsg_start)
sendmsg = source[sendmsg_start:sendmsg_end]
assert "s->protocol == NETLINK_KOBJECT_UEVENT_LOCAL" in sendmsg
assert "netlink_uevent_deliver(" in sendmsg
assert "dst_groups != 2u" in sendmsg

poll_start = source.index("static short fd_file_poll_revents(")
poll_end = source.index("static short fd_poll_revents(", poll_start)
poll = source[poll_start:poll_end]
netlink_poll = poll[poll.index("if ((events & POLLIN_K) && s->sock_domain == AF_NETLINK_LOCAL)"):
                    poll.index("} else if (s->unix_domain_stub)")]
assert "s->nl_rx_off < s->nl_rx_len" in netlink_poll
assert "POLLHUP_K" not in netlink_poll

with tempfile.TemporaryDirectory(prefix="axon-uevent-cred-", dir="/tmp/opencode") as tmp:
    source_path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source_path.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(source_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
