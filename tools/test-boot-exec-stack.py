#!/usr/bin/env python3
"""Exercise the actual boot stack-switch trampoline under the host ABI."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static uintptr_t lo, hi;
static int ran;
static int inner(const char *path, const char *const *argv, const char *const *envp) {
    volatile unsigned char local = 0;
    uintptr_t p = (uintptr_t)&local;
    assert(p >= lo && p < hi);
    assert(path[0] == 'x' && argv[0][0] == 'a' && envp[0][0] == 'e');
    ran = 1;
    return 123;
}
extern int boot_exec_call_on_stack(const char *, const char *const *,
    const char *const *, int (*)(const char *, const char *const *,
    const char *const *), void *);
int main(void) {
    void *buf = malloc(128 * 1024);
    assert(buf);
    lo = (uintptr_t)buf; hi = lo + 128 * 1024;
    const char *args[] = { "arg", NULL }, *env[] = { "env", NULL };
    volatile int old_stack = 9;
    int result = boot_exec_call_on_stack("x", args, env, inner, (void *)hi);
    assert(result == 123 && ran && old_stack == 9);
    free(buf);
    puts("PASS: boot exec stack trampoline switches and restores the stack");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-boot-stack-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), str(root / "core/boot_exec_stack.S"),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
