#!/usr/bin/env python3
"""Verify opt-in verbose tracing and logarithmic sampling of shell byte reads."""
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
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
typedef struct { uint64_t tid, pid; } thread_t;
struct fs_file { const char *path; off_t pos; };
static int init_verbose_trace;
static struct { char read_path[96]; } init_progress[64];
static int init_runtime_thread(thread_t *t) { return t != NULL; }
static uint64_t process_pid(thread_t *t) { return t->pid; }
static unsigned logs, console_logs;
static char last[512];
static void klogprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(last, sizeof(last), fmt, ap); va_end(ap);
    logs++; console_logs++;
}
static void klogprintf_logonly(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(last, sizeof(last), fmt, ap); va_end(ap);
    logs++;
}
''' + function("void syscall_configure_init_trace(") + function("static void init_trace_read(") + r'''
int main(void) {
    syscall_configure_init_trace(NULL);
    syscall_configure_init_trace("init.trace=10 noinit.trace=1 init.trace=1extra");
    assert(!init_verbose_trace);
    syscall_configure_init_trace("  quiet\tinit.trace=1 root=/dev/test ");
    assert(init_verbose_trace);
    init_verbose_trace = 0;
    thread_t t = {.tid = 6, .pid = 118};
    struct fs_file f = {.path = "/proc/1/cgroup"};
    for (off_t i = 0; i < 16384; i++) {
        f.pos = i + 1;
        init_trace_read(&t, &f, 3, i, 1, 1);
    }
    assert(logs == 15); /* powers of two, not 16384 log records */
    assert(console_logs == 0); /* normal boot does not synchronously render reads */
    assert(strstr(last, "path=/proc/1/cgroup") && strstr(last, "pos=16383->16384"));
    init_trace_read(&t, &f, 3, f.pos, 0, 1);
    assert(logs == 16 && strstr(last, "ret=0"));
    assert(strcmp(init_progress[6].read_path, f.path) == 0);
    init_verbose_trace = 1;
    f.path = "/etc/rc.conf"; f.pos = 1;
    init_trace_read(&t, &f, 4, 0, 1, 1);
    assert(logs == 17 && strstr(last, "sample=1"));
    assert(console_logs == 1);
    init_verbose_trace = 0;
    for (unsigned i = 0; i < 1000; i++)
        init_trace_read(&t, &f, 4, f.pos, 0, 1);
    assert(logs == 128); /* finite console overhead even for repeated EOF */
    puts("PASS: init verbose tracing is opt-in; byte reads use bounded logarithmic sampling");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-init-trace-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
