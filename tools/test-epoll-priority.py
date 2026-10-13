#!/usr/bin/env python3
"""Compare priority/readable event translation with real Linux pipe epoll."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>
enum {
    EPOLLIN_K = EPOLLIN, EPOLLPRI_K = EPOLLPRI, EPOLLOUT_K = EPOLLOUT,
    EPOLLERR_K = EPOLLERR, EPOLLHUP_K = EPOLLHUP, EPOLLRDHUP_K = 0x2000,
    POLLIN_K = POLLIN, POLLPRI_K = POLLPRI, POLLOUT_K = POLLOUT,
    POLLERR_K = POLLERR, POLLHUP_K = POLLHUP, POLLRDHUP_K = 0x2000
};
''' + function("static int epoll_interest_to_poll(") + function("static uint32_t poll_to_epoll_revents(") + r'''
int main(void) {
    assert(!(epoll_interest_to_poll(EPOLLPRI) & POLLIN));
    assert(epoll_interest_to_poll(EPOLLPRI) & POLLPRI);
    assert(poll_to_epoll_revents(POLLIN, EPOLLPRI) == 0);
    assert(poll_to_epoll_revents(POLLPRI, EPOLLIN) == 0);
    assert(poll_to_epoll_revents(POLLPRI, EPOLLPRI) == EPOLLPRI);
    assert(poll_to_epoll_revents(POLLIN | POLLPRI, EPOLLIN | EPOLLPRI) == (EPOLLIN | EPOLLPRI));
    int fds[2]; assert(pipe(fds) == 0);
    assert(write(fds[1], "x", 1) == 1);
    uint32_t masks[] = {EPOLLPRI, EPOLLIN, EPOLLIN | EPOLLPRI};
    for (unsigned i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        int ep = epoll_create1(0); assert(ep >= 0);
        struct epoll_event interest = {.events = masks[i], .data.fd = fds[0]}, event = {0};
        assert(epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &interest) == 0);
        int n = epoll_wait(ep, &event, 1, 0); assert(n >= 0);
        struct pollfd p = {.fd = fds[0], .events = epoll_interest_to_poll(masks[i])};
        assert(poll(&p, 1, 0) >= 0);
        uint32_t kernel = poll_to_epoll_revents(p.revents, masks[i]);
        assert(kernel == (n ? event.events : 0));
        close(ep);
    }
    close(fds[0]); close(fds[1]);
    puts("PASS: epoll PRI and IN stay distinct; actual translation matches Linux pipe epoll");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-epoll-pri-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
