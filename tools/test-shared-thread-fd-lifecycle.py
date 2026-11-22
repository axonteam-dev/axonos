#!/usr/bin/env python3
"""Exercise the kernel's descriptor ownership code with ASan on the host."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
thread = (root / "cpu/thread/thread.c").read_text()
fs = (root / "fs/fs.c").read_text()


def block(source, start):
    """Extract a function or loop including its balanced brace-delimited body."""
    begin = source.index(start)
    opening = source.index("{", begin)
    depth = 1
    pos = opening + 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[begin:pos]


if "static void thread_forget_shared_fds(" in dispatch:
    exit_cleanup = block(dispatch, "static void thread_forget_shared_fds(")
else:
    # The old code is inline in SYS_exit. Execute that exact loop to establish
    # that a sibling closing a worker-opened descriptor causes a UAF.
    exit_case = dispatch[dispatch.index("        case SYS_exit: {"):]
    old_loop = block(exit_case, "for (int fd = 0; fd < THREAD_MAX_FD; ++fd)")
    exit_cleanup = "static void thread_forget_shared_fds(thread_t *cur) {\n" + old_loop + "\n}"

mirror_helper = ""
if "static void thread_fd_clear_mirrors(" in thread:
    mirror_helper = block(thread, "static void thread_fd_clear_mirrors(")

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define AXON_PRODUCTION 1
#define THREAD_MAX_FD 16
#define PROCESS_MAX_FD 16
#define FS_TYPE_PIPE 1
#define FS_TYPE_SOCKET 2
#define FS_TYPE_EPOLL 3
#define FS_TYPE_EVENTFD 4
#define FS_TYPE_SIGNALFD 5
#define FS_TYPE_INOTIFY 6
#define FS_TYPE_TIMERFD 7
typedef struct fs_file { int refcount, fd_refcount, type; const char *path; void *driver_private; } fs_file;
typedef struct thread thread_t;
typedef struct process {
    thread_t *leader;
    fs_file *fds[PROCESS_MAX_FD];
    unsigned char fd_cloexec[PROCESS_MAX_FD];
    uint64_t rlim_nofile_cur;
} process_t;
struct thread { process_t *process; fs_file *fds[THREAD_MAX_FD]; int ring, state; uint64_t tid; char name[32]; };
enum { THREAD_RUNNING = 1 };
static thread_t *current;
static thread_t *all[8];
static int all_count;
static int destroys, notices;
static thread_t *thread_current(void) { return current; }
static thread_t *thread_get_current_user(void) { return current; }
static int thread_get_count(void) { return all_count; }
static thread_t *thread_get_by_index(int i) { return all[i]; }
static int fs_file_account(fs_file *f) { (void)f; return 0; }
static int fs_pipe_is_write_end(fs_file *f) { (void)f; return 0; }
#define devel_printf(...) ((void)0)
static void epoll_notify_file_closed(fs_file *f) { (void)f; notices++; }
static void fs_ofd_lock_release(fs_file *f) { (void)f; }
static void ns_release_file(fs_file *f) { (void)f; }
static void fs_file_unaccount(fs_file *f) { (void)f; }
static void pipe_release_end(fs_file *f) { (void)f; }
static void kfree(void *p) { free(p); }
static void destroy(fs_file *f) { destroys++; free(f); }
#define net_fs_file_destroy destroy
#define epoll_fs_file_destroy destroy
#define eventfd_fs_file_destroy destroy
#define signalfd_fs_file_destroy destroy
#define inotify_fs_file_destroy destroy
#define timerfd_fs_file_destroy destroy
struct fs_ops { void (*release)(fs_file *); };
struct fs_driver { struct fs_ops *ops; };
static struct fs_driver *g_drivers[1];
static int g_drivers_count;
static int fs_file_matches_driver(struct fs_driver *d, fs_file *f) { (void)d; (void)f; return 0; }
static int heap_ptr_is_kmalloc(void *p) { (void)p; return 1; }
#define klogprintf(...) ((void)0)
typedef int spinlock_t;
static spinlock_t sched_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { (void)l; *f = 0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)l; (void)f; }
#define thread_count all_count
#define threads all
''' + "\n" + "\n".join(block(fs, name) for name in (
    "void fs_file_get(", "void fs_file_fd_open(", "int fs_file_fd_close(",
    "void fs_file_free("
)) + "\n" + mirror_helper + "\n" + "\n".join(block(thread, name) for name in (
    "int thread_fd_alloc(", "int thread_fd_close_for(", "int thread_fd_dup(",
    "int thread_fd_dup2("
)) + "\n" + block(dispatch, "static void fork_inherit_fd_table(") + "\n" + exit_cleanup + r'''

static fs_file *new_file(void) {
    fs_file *f = calloc(1, sizeof(*f));
    assert(f); f->refcount = 1; f->type = FS_TYPE_SOCKET; return f;
}
int main(void) {
    process_t p = { .rlim_nofile_cur = THREAD_MAX_FD };
    thread_t leader = { .process = &p, .ring = 3, .state = THREAD_RUNNING };
    thread_t worker = { .process = &p, .ring = 3, .state = THREAD_RUNNING };
    p.leader = &leader; all[0] = &leader; all[1] = &worker; all_count = 2;
    current = &worker;
    fork_inherit_fd_table(&worker, &leader);
    fs_file *file = new_file();
    int fd = thread_fd_alloc(file);
    assert(fd >= 0 && file->refcount == 1 && file->fd_refcount == 1);
    current = &leader;
    assert(thread_fd_close_for(&leader, fd) == 0);
    assert(destroys == 1);
    assert(worker.fds[fd] == NULL);
    thread_forget_shared_fds(&worker);
    assert(destroys == 1 && notices == 1);
    /* Inherited thread mirrors do not add a descriptor reference. */
    current = &leader;
    file = new_file();
    fd = thread_fd_alloc(file);
    fork_inherit_fd_table(&worker, &leader);
    assert(file->refcount == 1 && worker.fds[fd] == file);
    assert(thread_fd_close_for(&leader, fd) == 0);
    assert(destroys == 2 && worker.fds[fd] == NULL);
    thread_forget_shared_fds(&worker);
    assert(destroys == 2);
    /* Replacing another thread's descriptor also invalidates its mirror. */
    current = &worker;
    fs_file *old = new_file();
    int oldfd = thread_fd_alloc(old);
    current = &leader;
    fs_file *replacement = new_file();
    int newfd = thread_fd_alloc(replacement);
    assert(thread_fd_dup2(newfd, oldfd) == oldfd);
    assert(destroys == 3 && worker.fds[oldfd] == NULL);
    thread_forget_shared_fds(&worker);
    assert(p.fds[oldfd] == replacement && replacement->refcount == 2);
    assert(thread_fd_close_for(&leader, oldfd) == 0);
    assert(thread_fd_close_for(&leader, newfd) == 0 && destroys == 4);
    puts("PASS: sibling close followed by worker exit");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-shared-fds-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-g", "-O1", "-Wall", "-Wextra",
                    "-Wno-unused-function", "-Wno-unused-variable",
                    "-fsanitize=address,undefined", "-no-pie", str(c), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
