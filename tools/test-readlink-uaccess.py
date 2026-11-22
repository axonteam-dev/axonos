#!/usr/bin/env python3
"""Guard readlink output spans against wraparound and out-of-range buffers."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static inline int user_range_ok(const void *uaddr, size_t nbytes) {")
end = source.index("\nstatic inline int user_recv_range_ok", start)
helper = source[start:end]
readlink = source[source.index("case SYS_readlink: {"):
                   source.index("case SYS_link: {", source.index("case SYS_readlinkat: {"))]
assert readlink.count("user_range_ok(buf, bufsiz)") == 2

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#define USER_STACK_TOP ((uintptr_t)0x60000000ULL)
#define PAGE_SIZE_2M ((uintptr_t)0x200000ULL)
#define MMIO_IDENTITY_LIMIT ((uintptr_t)0x100000000ULL)
''' + helper + r'''
int main(void) {
    assert(user_range_ok((void *)(uintptr_t)0x100000, 7));
    assert(!user_range_ok(NULL, 1));
    assert(!user_range_ok((void *)(uintptr_t)(MMIO_IDENTITY_LIMIT - 4), 8));
    assert(!user_range_ok((void *)(uintptr_t)-8, 16));
}
'''

with tempfile.TemporaryDirectory(prefix="axon-readlink-uaccess-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: readlink and readlinkat reject wrapped or out-of-range output spans")
