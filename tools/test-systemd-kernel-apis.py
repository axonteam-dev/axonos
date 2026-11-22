#!/usr/bin/env python3
"""Test Linux capability-bounding and scheduler APIs used by Debian systemd."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
begin = source.index("static uint64_t syscall_prctl_capbset(")
keep_begin = source.index("static uint64_t syscall_prctl_keepcaps(", begin)
nnp_begin = source.index("static uint64_t syscall_prctl_no_new_privs(", keep_begin)
ambient_begin = source.index("static uint64_t syscall_prctl_ambient(", nnp_begin)
seccomp_begin = source.index("static uint64_t syscall_seccomp_load(", ambient_begin)
sched_begin = source.index("static int syscall_sched_attr_validate(", ambient_begin)
uid_begin = source.index("static void process_uid_all_cap_transition(", sched_begin)
personality_begin = source.index("static uint64_t syscall_personality(")
personality_end = source.index("\n}\n", personality_begin) + 3

fixture = (r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#define PROCESS_CAP_LAST 40
#define AXON_CAP_SETPCAP 8
typedef struct process {
    uint64_t capability_bounding, cap_effective;
    uint64_t cap_permitted, cap_inheritable, cap_ambient;
    unsigned secure_bits;
    unsigned keep_caps;
    uint8_t no_new_privs;
    uint32_t personality;
} process_t;
typedef struct thread { process_t *process; unsigned euid; uint64_t tid; int pgid; uint16_t ioprio; } thread_t;
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static uint64_t process_pid(const thread_t *t) { return t ? t->tid : 0; }
static int syscall_task_capable(thread_t *t, unsigned cap) {
    return t && t->euid == 0 && cap <= PROCESS_CAP_LAST;
}
''' + source[begin:keep_begin] + source[keep_begin:ambient_begin] +
    source[ambient_begin:seccomp_begin] + source[sched_begin:uid_begin] +
    source[personality_begin:personality_end] + r'''
int main(void) {
    process_t p = {.capability_bounding=(1ULL << 41)-1,
                   .cap_effective=(1ULL << 41)-1};
    process_t unpriv = {.capability_bounding=(1ULL << 41)-1};
    thread_t root = {.process=&p,.euid=0,.tid=42,.pgid=42};
    thread_t user = {.process=&unpriv,.euid=1000,.tid=43,.pgid=43};
    assert(syscall_prctl_capbset(&root, 23, 40) == 1);
    assert(syscall_prctl_capbset(&root, 24, 40) == 0);
    assert(syscall_prctl_capbset(&root, 23, 40) == 0);
    assert((int64_t)syscall_prctl_capbset(&root, 23, 41) == -EINVAL);
    assert((int64_t)syscall_prctl_capbset(&user, 24, 12) == -EPERM);
    assert((int64_t)syscall_prctl_capbset(NULL, 23, 12) == -ESRCH);
    assert(syscall_prctl_keepcaps(&root, 7, 0) == 0);
    assert(syscall_prctl_keepcaps(&root, 8, 1) == 0);
    assert(syscall_prctl_keepcaps(&root, 7, 0) == 1);
    assert((int64_t)syscall_prctl_keepcaps(&user, 8, 1) == -EPERM);
    assert((int64_t)syscall_prctl_keepcaps(&root, 8, 2) == -EINVAL);
    assert(syscall_prctl_keepcaps(&user, 8, 0) == 0);
    assert(syscall_prctl_keepcaps(&root, 7, 0) == 1);
    assert(syscall_prctl_no_new_privs(&user, 39, 0) == 0);
    assert(syscall_prctl_no_new_privs(&user, 38, 1) == 0);
    assert(syscall_prctl_no_new_privs(&user, 39, 0) == 1);
    assert((int64_t)syscall_prctl_no_new_privs(&user, 38, 0) == -EINVAL);
    p.cap_permitted = p.cap_inheritable = p.capability_bounding = 1ULL << 12;
    assert(syscall_prctl_ambient(&root, 2, 12) == 0); /* RAISE */
    assert(syscall_prctl_ambient(&root, 1, 12) == 1); /* IS_SET */
    assert(syscall_prctl_ambient(&root, 3, 12) == 0); /* LOWER */
    assert(syscall_prctl_ambient(&root, 1, 12) == 0);
    p.secure_bits = 1u << 6;
    assert((int64_t)syscall_prctl_ambient(&root, 2, 12) == -EPERM);
    assert(syscall_prctl_ambient(&root, 4, 0) == 0); /* CLEAR_ALL */
    assert(syscall_sched_attr_validate(5, 0, 0, 0, 0, 0, 0) == 0); /* SCHED_IDLE */
    assert(syscall_sched_attr_validate(3, 1, 0, 0, 0, 0, 0) == 0); /* BATCH/reset */
    assert(syscall_sched_attr_validate(1, 0, 0, 1, 0, 0, 0) == EOPNOTSUPP);
    assert(syscall_sched_attr_validate(5, 0, 0, 1, 0, 0, 0) == EINVAL);
    assert(syscall_sched_attr_validate(0, 0, 20, 0, 0, 0, 0) == EINVAL);
    assert(syscall_personality(&root, 0xffffffffUL) == 0); /* PER_LINUX query */
    assert(syscall_personality(&root, 0) == 0); /* LockPersonality setup */
    assert((int64_t)syscall_personality(&root, 8) == -EOPNOTSUPP);
    assert(syscall_ioprio_set(&root, 1, 0, (3u << 13)) == 0); /* IDLE */
    assert(syscall_ioprio_get(&root, 1, 0) == (3u << 13));
    assert((int64_t)syscall_ioprio_set(&user, 1, 0, (1u << 13)) == -EPERM);
    assert((int64_t)syscall_ioprio_set(&root, 1, 99, (3u << 13)) == -ESRCH);
    puts("PASS: systemd capability, scheduler, personality and ioprio APIs");
}
''')

with tempfile.TemporaryDirectory(prefix="axon-systemd-apis-", dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
