#!/usr/bin/env python3
"""Exercise the kernel's AF_UNIX writev loop with a mocked stream writer."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("                if (s->unix_domain_stub && s->type_base == SOCK_STREAM_LOCAL) {", source.index("case SYS_writev:"))
end = source.index("                kfree(flat);\n                ssize_t wr", start)
snippet = source[start:end]
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define SOCK_STREAM_LOCAL 1
typedef struct { int unix_domain_stub, type_base; } ksock_net_t;
struct iovec_k { uint64_t base, len; };
static char output[16];
static size_t count, limit;
static void kfree(void *p) { (void)p; }
static uint64_t ret_err(int e) { return (uint64_t)-e; }
static ssize_t net_sock_write_userspace(void *cur, int fd, ksock_net_t *s, const void *p, size_t n) {
    (void)cur; (void)fd; (void)s;
    if (n > limit - count) n = limit - count;
    memcpy(output + count, p, n); count += n;
    return (ssize_t)n;
}
static uint64_t write_vectors(struct iovec_k *iov, int iovcnt) {
    ksock_net_t sock = {1, 1}, *s = &sock; void *flat = 0, *cur = 0; int fd = 0;
''' + snippet + r'''
    return 999;
}
int main(void) {
    struct iovec_k v[] = {{0, 0}, {(uintptr_t)"AB", 2}, {(uintptr_t)"CD", 2}};
    limit = 16; assert(write_vectors(v, 3) == 4); assert(count == 4 && !memcmp(output, "ABCD", 4));
    count = 0; limit = 3; assert(write_vectors(v, 3) == 3); assert(count == 3 && !memcmp(output, "ABC", 3));
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-writev-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: AF_UNIX writev handles empty iovecs and short writes")
