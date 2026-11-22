#!/usr/bin/env python3
"""Exercise actual procfs formatters with procps-style status PID parsing."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
src = (root / "fs/virt/procfs.c").read_text()
comm = src[src.index("static void procfs_sanitize_comm"):src.index("/* kind 18 targets")]
formatters = src[src.index("static ssize_t procfs_show_stat("):src.index("static ssize_t procfs_show_statm(")]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef struct process { unsigned pid; unsigned long long cap_inheritable, cap_permitted,
 cap_effective, capability_bounding, cap_ambient; unsigned no_new_privs, seccomp_mode; } process_t;
typedef struct thread { process_t *process; int tid, parent_tid, pgid, sid, nice;
 unsigned uid, euid, suid, gid, egid, sgid; char name[32];
 unsigned long long utime_ticks, stime_ticks, start_ticks, user_brk_base; } thread_t;
struct procfs_handle { int pid, is_task; };
struct procfs_proc_mem { uint64_t vsize_bytes; unsigned long rss_pages, data_pages, stack_pages; };
#define PROCESS_CAP_MASK 0ULL
static process_t process = {.pid = 42};
static thread_t leader = {.process = &process, .tid = 11, .name = "leader"};
static thread_t worker = {.process = &process, .tid = 77, .name = "worker"};
static thread_t *procfs_thread_by_id(int id) { return id == 42 ? &leader : NULL; }
static thread_t *thread_get(int id) { return id == 77 ? &worker : id == 11 ? &leader : NULL; }
static int thread_get_count(void) { return 2; }
static thread_t *thread_get_by_index(int i) { return i ? &worker : &leader; }
static int procfs_tgid(const thread_t *t) { return t->process->pid; }
static int process_ppid(thread_t *t) { (void)t; return 1; }
static char procfs_state_char(const thread_t *t) { (void)t; return 'S'; }
static uint64_t pit_get_frequency(void) { return 100; }
static void procfs_calc_proc_mem(thread_t *t, struct procfs_proc_mem *m) { (void)t; memset(m, 0, sizeof(*m)); }
static unsigned ns_pid_local(process_t *p) { return p->pid; }
''' + comm + formatters + r'''
/* procps readproc status2proc: Threads selects Tgid, otherwise Pid. */
static int procps_pid(const char *s) {
    int tgid = 0, pid = 0, threads = 0;
    for (; *s; s = strchr(s, '\n') + 1) {
        if (!strncmp(s, "Tgid:", 5)) tgid = atoi(s + 5);
        if (!strncmp(s, "Pid:", 4)) pid = atoi(s + 4);
        if (!strncmp(s, "Threads:", 8)) threads = atoi(s + 8);
        if (!strchr(s, '\n')) break;
    }
    return threads ? tgid : pid;
}
int main(void) {
    char buf[4096];
    struct procfs_handle h = {.pid = 42};
    assert(procfs_show_status(buf, sizeof(buf), &h) > 0);
    assert(procps_pid(buf) == 42);
    assert(strstr(buf, "Tgid:\t42\nPid:\t42\n"));
    /* Reproduce the old output: removing Tgid makes procps report PID 0. */
    char old[4096];
    strcpy(old, buf);
    char *tgid = strstr(old, "Tgid:\t42\n");
    memmove(tgid, tgid + strlen("Tgid:\t42\n"), strlen(tgid + strlen("Tgid:\t42\n")) + 1);
    assert(procps_pid(old) == 0);
    assert(procfs_show_stat(buf, sizeof(buf), &h) > 0 && atoi(buf) == 42);
    h.pid = 77; h.is_task = 1;
    assert(procfs_show_status(buf, sizeof(buf), &h) > 0);
    assert(procps_pid(buf) == 42);
    assert(strstr(buf, "Tgid:\t42\nPid:\t77\n"));
    assert(procfs_show_stat(buf, sizeof(buf), &h) > 0 && atoi(buf) == 77);
    puts("PASS: procps PID and task stat/status IDs");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-procfs-pids-", dir="/tmp/opencode") as tmp:
    source, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    source.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
