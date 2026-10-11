#!/usr/bin/env python3
"""Exercise the keyctl permission operation used by systemd service exec."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/keyring.c").read_text()
start = source.index("    case KEYCTL_SETPERM: {")
case = source[start:source.index("\n    case KEYCTL_UPDATE:", start)]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define KEYCTL_SETPERM 5
typedef struct { int held; } spinlock_t;
typedef struct { uint32_t serial, uid, perms; } kr_slot_t;
typedef struct { uint32_t euid; } thread_t;
static spinlock_t g_kr_lock;
static kr_slot_t key = {.serial = 42, .uid = 100};
static thread_t caller = {.euid = 100};
static void acquire(spinlock_t *lock) { assert(!lock->held); lock->held = 1; }
static void release(spinlock_t *lock) { assert(lock->held); lock->held = 0; }
static kr_slot_t *slot_by_serial(uint32_t serial) { return serial == 42 ? &key : NULL; }
static thread_t *thread_get_current_user(void) { return &caller; }
static long keyctl_setperm(int cmd, long a2, long a3) {
    switch (cmd) {
''' + case + r'''
    default: return -38;
    }
}
int main(void) {
    assert(keyctl_setperm(KEYCTL_SETPERM, 42, 0x003f0000) == 0);
    assert(key.perms == 0x003f0000 && !g_kr_lock.held);
    caller.euid = 101;
    assert(keyctl_setperm(KEYCTL_SETPERM, 42, 1) == -1);
    assert(key.perms == 0x003f0000 && !g_kr_lock.held);
    caller.euid = 0;
    assert(keyctl_setperm(KEYCTL_SETPERM, 42, 0x001f0000) == 0);
    assert(keyctl_setperm(KEYCTL_SETPERM, 99, 1) == -126);
    assert(!g_kr_lock.held);
    puts("PASS: keyctl SETPERM honors ownership and updates invocation key");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-keyctl-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
