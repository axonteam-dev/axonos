#!/usr/bin/env python3
"""The x86-64 creat syscall must use open's create/truncate semantics."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
header = (root / "inc/syscall.h").read_text()
assert "#define SYS_creat   85" in header
start = source.index("        case SYS_creat:")
end = source.index("        case SYS_open: {", start)
route = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define SYS_creat 85
#define SYS_open 2
static uint64_t dispatch(int nr, uint64_t a1, uint64_t a2, uint64_t a3) {
    switch (nr) {
''' + route + r'''
        case SYS_open:
            assert(a1==0x1234);
            assert(a2==(1|0100|01000));
            assert(a3==0640);
            return 7;
        default: return (uint64_t)-38;
    }
}
int main(void) {
    assert(dispatch(85, 0x1234, 0640, 0)==7);
    puts("PASS: creat(85) routes mode to open with O_WRONLY|O_CREAT|O_TRUNC");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-creat-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
