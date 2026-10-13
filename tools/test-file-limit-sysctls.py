#!/usr/bin/env python3
"""Exercise actual sysctl stores, file-object accounting and fd soft limits."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
fs = (root / "fs/fs.c").read_text()
proc = (root / "fs/virt/procfs.c").read_text()
threads = (root / "cpu/thread/thread.c").read_text()


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
typedef long ssize_t;
#define PROCESS_MAX_FD 2048
#define THREAD_MAX_FD 2048
struct fs_file { int limit_accounted, refcount; void *driver_private; };
typedef struct { struct fs_file *fds[2048]; uint64_t rlim_nofile_cur; } process_t;
typedef struct { int ring, euid; process_t *process; struct fs_file *fds[2048]; } thread_t;
static thread_t caller = {.ring = 3, .euid = 1000};
static thread_t *thread_current(void) { return &caller; }
static thread_t *thread_get_current_user(void) { return &caller; }
typedef struct { int held; } spinlock_t;
static spinlock_t file_limit_lock;
static uint64_t file_limit_max = 65536, file_limit_count;
static uint32_t nr_open_limit = PROCESS_MAX_FD;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->held); l->held = 1; *f = 0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->held); l->held = 0; }
''' + "\n".join(function(fs, sig) for sig in (
    "uint64_t fs_file_max_get(", "uint32_t fs_nr_open_get(",
    "int fs_file_max_set(", "int fs_nr_open_set(",
    "int fs_file_account(", "static void fs_file_unaccount(",
)) + "\n" + function(threads, "int thread_fd_alloc(") + r'''
enum { SYSCTL_HOSTNAME=20, SYSCTL_DOMAINNAME=21, SYSCTL_FILE_MAX=30, SYSCTL_NR_OPEN=31 };
struct procfs_handle { int kind, file_id; };
static int uts_hostname_set(const char *s, size_t n) { (void)s; (void)n; return 0; }
static int uts_domainname_set(const char *s, size_t n) { (void)s; (void)n; return 0; }
static ssize_t procfs_net_store_dhcp(const char *s, size_t n) { (void)s; (void)n; return -1; }
''' + function(proc, "static ssize_t procfs_write(") + r'''
int main(void) {
    struct procfs_handle h = {.kind=9, .file_id=SYSCTL_FILE_MAX};
    struct fs_file sysctl = {.driver_private=&h};
    assert(procfs_write(&sysctl, "100\n", 4, 0) == -13);
    caller.euid = 0;
    assert(procfs_write(&sysctl, "9223372036854775807", 19, 0) == 19);
    assert(fs_file_max_get() == 0x7fffffffffffffffULL);
    assert(procfs_write(&sysctl, "18446744073709551616", 20, 0) == -22);
    assert(procfs_write(&sysctl, "1x", 2, 0) == -22);
    assert(procfs_write(&sysctl, "0", 1, 0) == -22);
    h.file_id=SYSCTL_NR_OPEN;
    assert(fs_nr_open_get() == PROCESS_MAX_FD);
    int v=0x7fffffff;
    for (;;) {
        v &= ~7;
        assert(v >= 1024); /* systemd's halving loop can reach the actual ceiling */
        if (fs_nr_open_get() >= (uint32_t)v) break;
        assert(fs_nr_open_set(v) == -22); v /= 2;
    }
    assert(procfs_write(&sysctl, "64\n", 3, 10) == 3 && fs_nr_open_get() == 64);
    assert(fs_nr_open_set(63) == -22 && fs_nr_open_set(2049) == -22);
    assert(fs_nr_open_set(PROCESS_MAX_FD) == 0);
    assert(fs_file_max_set(2) == 0); caller.euid=1000;
    struct fs_file a={0}, b={0}, c={0};
    process_t p={.rlim_nofile_cur=2}; caller.process=&p;
    assert(thread_fd_alloc(&a)==0 && thread_fd_alloc(&b)==1);
    assert(file_limit_count==2 && thread_fd_alloc(&c)==-24); /* EMFILE */
    p.rlim_nofile_cur=3;
    assert(thread_fd_alloc(&c)==-23 && !p.fds[2]); /* ENFILE */
    assert(fs_file_account(&a)==0 && file_limit_count==2); /* duplicate references don't count again */
    fs_file_unaccount(&a); p.fds[0]=NULL; caller.fds[0]=NULL;
    assert(thread_fd_alloc(&c)==0 && file_limit_count==2);
    caller.euid=0; struct fs_file admin={0};
    assert(fs_file_account(&admin)==0); /* privileged recovery may exceed file-max */
    fs_file_unaccount(&b); fs_file_unaccount(&c); fs_file_unaccount(&admin);
    assert(file_limit_count==0);
    puts("PASS: file-max/nr_open parse, permissions, real accounting, EMFILE/ENFILE and systemd ceiling fallback");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-file-sysctl-") as tmp:
    c = Path(tmp)/"test.c"; binary=Path(tmp)/"test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
