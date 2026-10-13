#!/usr/bin/env python3
"""Check visibility of the full OpenRC -> ifup -> udhcpc -> hook process chain."""
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
#include <string.h>
struct thread;
typedef struct process {
    struct process *parent;
    struct thread *leader;
    uint64_t pid;
} process_t;
typedef struct thread { process_t *process; uint64_t tid; char name[32]; } thread_t;
static int openrc_services_stage = 1;
static uint64_t process_pid(thread_t *t) { return t->process->pid; }
static uint64_t pit_get_time_ms(void) { return 1000; }
static struct {
    uint64_t pid, progress_ms, number, arg1;
    int active;
    unsigned reports;
    char read_path[96];
} init_progress[64];
''' + function("static int openrc_spawn_family(") + function("static int init_runtime_thread(") + function("static void init_monitor_note_spawn(") + r'''
int main(void) {
    process_t processes[12] = {0}; thread_t threads[12] = {0};
    for (unsigned i = 0; i < 12; i++) {
        threads[i].tid = i + 1; threads[i].process = &processes[i];
        processes[i].pid = i + 2; processes[i].leader = &threads[i];
        if (i) processes[i].parent = &processes[i - 1];
        strcpy(threads[i].name, i ? "/bin/sh" : "/sbin/openrc");
    }
    strcpy(threads[3].name, "/sbin/ifup");
    strcpy(threads[4].name, "/sbin/udhcpc");
    strcpy(threads[6].name, "/sbin/ip");
    for (unsigned i = 1; i < 12; i++) {
        assert(openrc_spawn_family(&threads[i]));
        init_monitor_note_spawn(&threads[i]);
        assert(init_progress[i + 1].pid == processes[i].pid);
        assert(init_progress[i + 1].progress_ms == 1000);
        assert(init_progress[i + 1].number == UINT64_MAX); /* visible even before first syscall */
    }
    strcpy(threads[0].name, "unrelated");
    processes[0].parent = &processes[11]; /* bounded traversal even on a cycle */
    assert(!openrc_spawn_family(&threads[11]));
    processes[0].parent = NULL;
    processes[0].pid = 1; strcpy(threads[0].name, "/usr/lib/systemd/systemd");
    assert(init_runtime_thread(&threads[0]));
    puts("PASS: deep DHCP hook descendants and pre-syscall fork children remain visible to init monitor");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-init-descendants-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
