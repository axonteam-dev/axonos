#!/usr/bin/env python3
"""Exercise the getdents name-copy code with Linux filename bytes."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index('                const char *nm_raw = (const char*)(kbuf + in_off + 8);')
end = source.index('                /* PrivateTmp backing dentries', start)
fragment = source[start:end]
fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
static void check(const unsigned char *name, size_t len) {
    unsigned char record[264] = {0};
    memcpy(record + 8, name, len);
    unsigned char *kbuf = record;
    size_t in_off = 0, name_len_use = len;
''' + fragment + r'''
    assert(nlen == len);
    assert(memcmp(nm, name, len) == 0);
    assert(nm[len] == '\0');
}
int main(void) {
    const unsigned char utf8[] = { 'c', 'a', 'f', 0xc3, 0xa9 };
    const unsigned char raw[] = { 'x', 0xff, '\n', 'y' };
    check(utf8, sizeof(utf8));
    check(raw, sizeof(raw));
}
'''
with tempfile.TemporaryDirectory(prefix="axon-getdents-bytes-", dir="/tmp/opencode") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: getdents preserves UTF-8, non-UTF-8, and control bytes")
