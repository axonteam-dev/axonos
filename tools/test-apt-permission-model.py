#!/usr/bin/env python3
"""Compile and exercise the kernel's actual DAC helpers against a small VFS."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
helpers = source[source.index("static int syscall_id_in_group_as"):
                 source.index("static int syscall_parent_access")]
transition = source[source.index("static void process_uid_all_cap_transition"):
                    source.index("static int syscall_namespace_flags_allowed")]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned uid_t;
typedef unsigned gid_t;
#define AXON_NGROUPS_MAX 32
#define AXON_CAP_DAC_OVERRIDE 1
#define AXON_CAP_DAC_READ_SEARCH 2
#define S_IFDIR 0040000
struct stat { unsigned st_mode, st_uid, st_gid; };
typedef struct { int ngroups; gid_t groups[32]; uint64_t cap_permitted, cap_effective, cap_ambient; unsigned keep_caps, secure_bits; } process_t;
typedef struct { uid_t uid, euid; gid_t gid, egid; int ngroups; gid_t groups[32]; process_t *process; } thread_t;
static int syscall_task_capable(const thread_t *t, unsigned c) {
    return t && (t->process ? !!(t->process->cap_effective & (1ULL << c)) : t->euid == 0);
}
static int vfs_stat(const char *path, struct stat *s) {
    *s = (struct stat){S_IFDIR | 0755, 0, 0};
    if (!strcmp(path, "/var/lib/apt/lists/partial"))
        *s = (struct stat){S_IFDIR | 0700, 100, 0};
    else if (!strcmp(path, "/private"))
        *s = (struct stat){S_IFDIR | 0700, 0, 0};
    else if (!strcmp(path, "/group"))
        *s = (struct stat){S_IFDIR | 0070, 222, 123};
    else if (!strcmp(path, "/plain"))
        *s = (struct stat){0100000 | 0644, 222, 123};
    else if (strcmp(path, "/") && strcmp(path, "/var") &&
             strcmp(path, "/var/lib") && strcmp(path, "/var/lib/apt") &&
             strcmp(path, "/var/lib/apt/lists") && strcmp(path, "/private/file"))
        return -1;
    return 0;
}
''' + helpers + transition + r'''
int main(void) {
    process_t p = {.cap_permitted = 6};
    thread_t t = {.uid = 0, .euid = 100, .gid = 0, .egid = 65534, .process = &p};
    const char *partial = "/var/lib/apt/lists/partial";
    /* APT: real root, effective _apt, no effective DAC capabilities. */
    assert(syscall_path_access(&t, partial, 3) == 0);
    t.euid = 101;
    assert(syscall_path_access(&t, partial, 3) == 13);
    assert(syscall_path_access_as(&t, partial, 3, 1) == 0);
    assert(syscall_path_access(&t, "/private/file", 4) == 13);
    t.uid = 101;
    assert(syscall_path_access_as(&t, "/private/file", 4, 1) == 13);
    t.egid = 123;
    assert(syscall_path_access(&t, "/group", 3) == 0);
    assert(syscall_path_access_as(&t, "/group", 3, 1) == 13);
    p.ngroups = 1; p.groups[0] = 123;
    assert(syscall_path_access_as(&t, "/group", 3, 1) == 0);
    p.cap_effective = 1ULL << AXON_CAP_DAC_READ_SEARCH;
    assert(syscall_path_access(&t, "/plain", 4) == 0);
    assert(syscall_path_access(&t, "/plain", 1) == 13);
    p.cap_effective = 1ULL << AXON_CAP_DAC_OVERRIDE;
    assert(syscall_path_access(&t, "/plain", 1) == 13);
    assert(syscall_path_access(&t, "/private", 1) == 0);
    p.cap_permitted = 6; p.cap_effective = 6;
    process_uid_all_cap_transition(&p, 0, 100, 1, 1, 1);
    assert(p.cap_effective == 0 && p.cap_permitted == 6);
    process_uid_all_cap_transition(&p, 100, 0, 1, 1, 1);
    assert(p.cap_effective == 6 && p.cap_permitted == 6);
    process_uid_all_cap_transition(&p, 0, 100, 1, 1, 0);
    assert(p.cap_effective == 0 && p.cap_permitted == 0);
    process_uid_all_cap_transition(&p, 100, 0, 1, 0, 1);
    assert(p.cap_effective == 0 && p.cap_permitted == 0);
    p.cap_effective = p.cap_permitted = 6; p.keep_caps = 1;
    process_uid_all_cap_transition(&p, 0, 100, 1, 1, 0);
    assert(p.cap_effective == 0 && p.cap_permitted == 6);
    p.secure_bits = 4; p.cap_effective = 6; p.keep_caps = 0;
    process_uid_all_cap_transition(&p, 0, 100, 1, 1, 0);
    assert(p.cap_effective == 6 && p.cap_permitted == 6);
    puts("PASS: APT effective identity, real access IDs, groups, traversal and DAC caps");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-apt-dac-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
