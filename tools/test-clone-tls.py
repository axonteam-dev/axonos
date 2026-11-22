#!/usr/bin/env python3
"""Linux clone installs TLS without faulting in or accessing the TLS page."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
clone = source[source.index("        case SYS_clone: {"):
               source.index("        case SYS_clone3: {")]
clone3 = source[source.index("        case SYS_clone3: {"):]
clone3 = clone3[:clone3.index("        case ", 10)]
for name, body in (("clone", clone), ("clone3", clone3)):
    assert "clone_ensure_user_va(cur->mm, tls," not in body, name
    assert "child->user_fs_base = tls;" in body, name

# A real Linux oracle: the child never uses its deliberately inaccessible FS
# base and exits normally. The glibc clone wrapper returns through raw exit.
fixture = r'''
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
static int child(void *arg) { (void)arg; return 0; }
int main(void) {
    void *stack = mmap(0, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *tls = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED || tls == MAP_FAILED) return 2;
    int pid = clone(child, (char *)stack + 65536, SIGCHLD | CLONE_SETTLS,
                    0, 0, tls, 0);
    if (pid < 0) { perror("clone"); return 1; }
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) return 3;
    puts("PASS: clone accepts inaccessible TLS without accessing it");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-clone-tls-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
