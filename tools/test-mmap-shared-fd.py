#!/usr/bin/env python3
"""mmap must prefer the shared fd table over a stale thread mirror."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_mmap.c").read_text()
i = source.index("static struct fs_file *user_mmap_fd_get(")
helper = source[i:source.index("\n}\n", i) + 3]
assert source.count("user_mmap_fd_get(tcur ? tcur : cur,") == 4
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#define THREAD_MAX_FD 8
struct fs_file { const char *path; };
typedef struct process { struct fs_file *fds[THREAD_MAX_FD]; } process_t;
typedef struct thread { process_t *process; struct fs_file *fds[THREAD_MAX_FD]; } thread_t;
''' + helper + r'''
int main(void) {
    struct fs_file dbus = {"libdbus"}, xfce = {"libxfce4ui"};
    process_t process = {0};
    thread_t a = {.process=&process}, b = {.process=&process};
    /* B closes/reuses fd 3; A's mirror still holds its old file. */
    a.fds[3]=&dbus; b.fds[3]=&xfce; process.fds[3]=&xfce;
    assert(user_mmap_fd_get(&a, 3) == &xfce);
    assert(user_mmap_fd_get(&b, 3) == &xfce);
    process.fds[3]=NULL;
    assert(user_mmap_fd_get(&a, 3) == &dbus); /* existing syscall fallback */
    a.process=NULL;
    assert(user_mmap_fd_get(&a, 3) == &dbus);
    assert(!user_mmap_fd_get(&a, -1));
    assert(!user_mmap_fd_get(&a, THREAD_MAX_FD));
    assert(!user_mmap_fd_get(NULL, 3));
    puts("PASS: mmap selects the shared process fd instead of a stale thread fd");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mmap-shared-fd-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
