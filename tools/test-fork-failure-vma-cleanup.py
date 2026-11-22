#!/usr/bin/env python3
"""An unpublished failed fork must release its tid-owned VMA mirrors."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void fork_stop_child(")
end = source.index("\n}\n", start) + 2
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef struct process { struct process *parent; void *leader; } process_t;
typedef struct { uint64_t tid; process_t *process; } thread_t;
static int sequence, removed, stopped, reaped, discarded;
static void user_vma_remove_all_for_tid(uint64_t tid) {
    assert(tid == 42 && sequence++ == 0); removed++;
}
static void thread_stop(int tid) { assert(tid == 42 && sequence++ == 1); stopped++; }
static int thread_reap(int tid) { assert(tid == 42 && sequence++ == 2); reaped++; return 0; }
static int process_discard(process_t *p, process_t *c) {
    assert(p && c && sequence++ == 3 && !c->leader); discarded++; return 0;
}
''' + source[start:end] + r'''
int main(void) {
    process_t parent = {0}, child_process = {&parent, (void *)1};
    thread_t child = {42, &child_process};
    fork_stop_child(&child);
    assert(!child.process && removed == 1 && stopped == 1 && reaped == 1 && discarded == 1);
    fork_stop_child(NULL);
    puts("PASS: unpublished fork failure releases tid VMA records before reaping");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-fork-vma-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
