#!/usr/bin/env python3
"""Regress Linux epoll keying and watch lifetime across fork/close."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
fs_source = (root / "fs/fs.c").read_text()


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


types_start = dispatch.index(
    "typedef struct {\n    int fd;\n    struct fs_file *file;"
)
types_end = dispatch.index("static kepoll_t *g_kepoll_sets;", types_start)
types = dispatch[types_start:types_end] + "static kepoll_t *g_kepoll_sets;\n"
helpers = "\n".join(
    function(dispatch, signature)
    for signature in (
        "static void epoll_remove_item(",
        "void epoll_notify_file_closed(",
        "static int epoll_find_item(kepoll_t *ep, int fd, const struct fs_file *file) {",
    )
)
fd_api_start = fs_source.index("void fs_file_fd_open(")
fd_api = fs_source[fd_api_start:fs_source.index("\nvoid fs_file_free(", fd_api_start)]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef struct fs_file { int fd_refcount; } fs_file;
enum { EPOLL_MAX_ITEMS = 256 };
static int fs_file_fd_count(const struct fs_file *file);
void epoll_notify_file_closed(struct fs_file *file);
''' + types + helpers + "\n" + fd_api + r'''
int main(void) {
    fs_file watched = {0}, reused_fd = {0};
    kepoll_t parent_epoll = {0}, inherited_epoll = {0};
    parent_epoll.next = &inherited_epoll;
    g_kepoll_sets = &parent_epoll;

    /* Same OFD is inherited across fork; the epoll instance is shared too. */
    fs_file_fd_open(&watched); /* parent's fd */
    fs_file_fd_open(&watched); /* child's inherited fd */
    fs_file_fd_open(&reused_fd); /* a different OFD later reusing fd 4 */
    parent_epoll.nitems = 3;
    parent_epoll.items[0] = (epoll_item_t){.fd = 4, .file = &watched};
    parent_epoll.items[1] = (epoll_item_t){.fd = 5, .file = &watched};
    parent_epoll.items[2] = (epoll_item_t){.fd = 4, .file = &reused_fd};
    inherited_epoll.nitems = 1;
    inherited_epoll.items[0] = (epoll_item_t){.fd = 4, .file = &watched};

    /* Linux key is (fd, open file description), allowing dup aliases and reuse. */
    assert(epoll_find_item(&parent_epoll, 4, &watched) == 0);
    assert(epoll_find_item(&parent_epoll, 5, &watched) == 1);
    assert(epoll_find_item(&parent_epoll, 4, &reused_fd) == 2);
    assert(epoll_find_item(&parent_epoll, 5, &reused_fd) == -1);

    /* Child closes its inherited fd: shared watch must survive for the parent. */
    assert(fs_file_fd_close(&watched) == 1);
    assert(parent_epoll.nitems == 3 && inherited_epoll.nitems == 1);
    assert(epoll_find_item(&parent_epoll, 4, &watched) >= 0);

    /* Last descriptor close removes every copy of that OFD's watch globally. */
    assert(fs_file_fd_close(&watched) == 0);
    assert(parent_epoll.nitems == 1 && inherited_epoll.nitems == 0);
    assert(epoll_find_item(&parent_epoll, 4, &watched) == -1);
    assert(epoll_find_item(&parent_epoll, 4, &reused_fd) >= 0);

    assert(fs_file_fd_close(&reused_fd) == 0);
    assert(parent_epoll.nitems == 0);
    puts("PASS: fork/dup descriptors preserve epoll watches until the final close; fd reuse is keyed by OFD");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-epoll-fork-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(c), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

# Ensure the syscall path uses the same open-file key and polls the retained file,
# rather than resolving a possibly reused numeric fd during epoll_wait().
ctl_start = dispatch.index("case 233: { /* epoll_ctl")
wait_start = dispatch.index("case 232: /* epoll_wait", ctl_start)
ctl = dispatch[ctl_start:wait_start]
wait_end = dispatch.index("default:", wait_start)
wait = dispatch[wait_start:wait_end]
assert "epoll_find_item(ep, fd, tf)" in ctl
assert "ep->items[ep->nitems].file = tf;" in ctl
assert "fd_file_poll_revents(wait_thr, it->file, want)" in wait
assert "fork_child_socket_file" not in dispatch
assert "fs_file_fd_open(pf);" in dispatch[
    dispatch.index("static void fork_inherit_fd_table("):dispatch.index(
        "/* Final unref", dispatch.index("static void fork_inherit_fd_table(")
    )
]
