#!/usr/bin/env python3
"""Compare the actual regular-file poll fallback against host Linux at EOF."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("    /* Linux vfs_poll() defaults")
tail = source[start:source.index("\n}\n", start) + 3]
program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
enum {
    FS_TYPE_REG = 1, FS_TYPE_DIR = 2,
    POLLIN_K = POLLIN, POLLOUT_K = POLLOUT,
    POLLRDNORM_K = POLLRDNORM, POLLWRNORM_K = POLLWRNORM
};
struct fs_file { int type; off_t pos; size_t size; const char *path; };
static short kernel_regular_poll(struct fs_file *f, short events) {
    short revents = 0;
''' + tail + r'''
static void compare(int fd, struct fs_file *f) {
    short masks[] = {POLLIN, POLLOUT, POLLIN | POLLOUT, POLLPRI,
                     POLLRDNORM, POLLWRNORM, POLLIN | POLLHUP, 0};
    for (unsigned i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        struct pollfd p = {.fd = fd, .events = masks[i]};
        assert(poll(&p, 1, 0) >= 0);
        assert(kernel_regular_poll(f, masks[i]) == p.revents);
    }
}
int main(int argc, char **argv) {
    assert(argc == 2);
    int fd = open(argv[1], O_CREAT | O_RDWR | O_TRUNC, 0600); assert(fd >= 0);
    const char text[] = "populated 0\nfrozen 0\n";
    assert(write(fd, text, sizeof(text) - 1) == sizeof(text) - 1);
    struct fs_file f = {.type = FS_TYPE_REG, .path = "/sys/fs/cgroup/openrc.dmesg/cgroup.events",
                       .size = sizeof(text) - 1};
    assert(lseek(fd, 0, SEEK_SET) == 0);
    compare(fd, &f);
    /* BusyBox's read builtin checks ppoll before *every* byte, including EOF. */
    for (size_t i = 0; i <= f.size; i++) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        struct timespec ts = {0};
        assert(ppoll(&p, 1, &ts, NULL) == 1 && (p.revents & POLLIN));
        assert(kernel_regular_poll(&f, POLLIN) == POLLIN);
        char ch;
        ssize_t n = read(fd, &ch, 1);
        assert(n == (i < f.size ? 1 : 0));
        f.pos += n;
    }
    compare(fd, &f);
    assert(lseek(fd, 10000, SEEK_SET) == 10000); f.pos = 10000;
    compare(fd, &f); /* beyond EOF */
    assert(ftruncate(fd, 0) == 0); f.pos = 0; f.size = 0;
    compare(fd, &f); /* empty regular file */
    close(fd);
    fd = open(".", O_RDONLY | O_DIRECTORY); assert(fd >= 0);
    f.type = FS_TYPE_DIR; compare(fd, &f); close(fd);
    puts("PASS: regular-file poll/ppoll readiness matches Linux before/at/beyond EOF and for directories");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-poll-eof-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(Path(tmp) / "events")], check=True)
