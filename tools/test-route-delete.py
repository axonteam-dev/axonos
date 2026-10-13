#!/usr/bin/env python3
"""Exercise actual default-route deletion semantics; legacy DHCP loop must end."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int net_delete_default_route(")
body = source[start:source.index("\n}\n", start) + 3]
assert source.count("net_delete_default_route(be32(") == 2
program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
static struct { uint32_t gw_be; int gw_mac_valid; } g_net;
''' + body + r'''
int main(void) {
    assert(net_delete_default_route(0) == -ESRCH);
    g_net.gw_be = 0x0a000202; g_net.gw_mac_valid = 1;
    assert(net_delete_default_route(0x0a000201) == -ESRCH);
    assert(g_net.gw_be == 0x0a000202 && g_net.gw_mac_valid);
    unsigned deletes = 0;
    while (net_delete_default_route(0) == 0) {
        assert(++deletes < 2); /* old ioctl always succeeded here */
    }
    assert(deletes == 1 && !g_net.gw_be && !g_net.gw_mac_valid);
    g_net.gw_be = 0x0a000202;
    assert(net_delete_default_route(0x0a000202) == 0);
    assert(net_delete_default_route(0x0a000202) == -ESRCH);
    puts("PASS: default-route deletion matches gateway and returns ESRCH when absent; DHCP delete loop terminates");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-route-delete-") as tmp:
    c = Path(tmp) / "test.c"; binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
