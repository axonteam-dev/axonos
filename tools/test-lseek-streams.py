#!/usr/bin/env python3
"""Compile the actual lseek dispatch case and check stream seek semantics."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("        case SYS_lseek: {")
end = source.index("        case SYS_ftruncate:", start)
case = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef int64_t off_t;
enum { SYS_lseek = 8, THREAD_MAX_FD = 4, EBADF = 9, EINVAL = 22,
       ESPIPE = 29, FS_TYPE_PIPE = 2, SYSCALL_FTYPE_SOCKET = 3 };
struct fs_file { int type; off_t pos, size; };
struct thread { struct fs_file *fds[THREAD_MAX_FD]; };
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static uint64_t call(struct thread *cur, int num, uint64_t a1,
                     uint64_t a2, uint64_t a3) {
    switch (num) {
''' + case + r'''
    default: return ret_err(EINVAL);
    }
}
int main(void) {
    struct fs_file pipe = { .type=FS_TYPE_PIPE, .pos=10 };
    struct fs_file sock = { .type=SYSCALL_FTYPE_SOCKET };
    struct fs_file file = { .pos=10, .size=20 };
    struct thread t = { .fds={ &pipe, &sock, &file, NULL } };
    assert((int64_t)call(&t, SYS_lseek, 0, (uint64_t)-1, 1) == -ESPIPE);
    assert((int64_t)call(&t, SYS_lseek, 1, 0, 0) == -ESPIPE);
    assert(pipe.pos == 10 && sock.pos == 0);
    assert(call(&t, SYS_lseek, 2, (uint64_t)-1, 1) == 9);
    assert((int64_t)call(&t, SYS_lseek, 3, 0, 0) == -EBADF);
    puts("PASS: actual lseek dispatch rejects pipe and socket seeks with ESPIPE");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-lseek-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
