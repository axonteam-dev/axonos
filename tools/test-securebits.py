#!/usr/bin/env python3
"""Exercise the securebits prctl path required for systemd service exec."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("            if (option == PR_GET_SECUREBITS)")
snippet = source[start:source.index("            if (option == PR_SET_NAME)", start)]
program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
enum { PR_GET_SECUREBITS = 27, PR_SET_SECUREBITS = 28 };
typedef struct { unsigned int secure_bits; } process_t;
typedef struct { unsigned int euid; } thread_t;
static uint64_t ret_err(int err) { return (uint64_t)-(int64_t)err; }
static uint64_t check(int option, unsigned long arg2, process_t *p, thread_t *cur) {
''' + snippet + r'''
    return ret_err(EINVAL);
}
int main(void) {
    process_t p = {0};
    thread_t root = {.euid = 0}, user = {.euid = 100};
    assert(check(PR_GET_SECUREBITS, 0, &p, &root) == 0);
    assert(check(PR_SET_SECUREBITS, 1, &p, &root) == 0);
    assert(check(PR_SET_SECUREBITS, 3, &p, &root) == 0);
    assert(check(PR_GET_SECUREBITS, 0, &p, &root) == 3);
    assert(check(PR_SET_SECUREBITS, 0, &p, &root) == ret_err(EPERM));
    assert(check(PR_SET_SECUREBITS, 4, &p, &user) == ret_err(EPERM));
    assert(check(PR_SET_SECUREBITS, 256, &p, &root) == ret_err(EINVAL));
    puts("PASS: securebits get/set, locked bits, privilege and invalid masks");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-securebits-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
