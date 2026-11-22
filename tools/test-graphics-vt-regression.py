#!/usr/bin/env python3
"""Host exercise of real devfs VT path parsing and graphics owner cleanup."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
devfs = (root / 'fs/virt/devfs.c').read_text()
syscalls = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()

def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define DEVFS_TTY_COUNT 12
static int active = 1, modes[DEVFS_TTY_COUNT], restored = -1, reblit = -1;
static int devfs_get_active(void) { return active; }
typedef struct process { int dummy; } process_t;
typedef struct thread { process_t *process; uint64_t tid; } thread_t;
static int console_kbd_mode = 1;
static process_t *console_graphics_owner[DEVFS_TTY_COUNT];
static uint64_t console_graphics_owner_tid[DEVFS_TTY_COUNT];
static int video_set_vt_graphics(int vt, int mode) { modes[vt] = mode; return 0; }
static int video_vt_graphics(int vt) { return modes[vt]; }
static void devfs_tty_restore_sane(int vt) { restored = vt; }
static int devfs_tty_leave_alt_screen(int vt) { (void)vt; return 0; }
static void devfs_tty_force_reblit(int vt) { reblit = vt; }
''' + function(devfs, 'static int devfs_vt_number(const char *s) {') + '\n' + \
    function(devfs, 'static int devfs_path_to_tty(const char *path) {') + '\n' + \
    function(syscalls, 'static int console_graphics_vt_owned_by(int vt, thread_t *t) {') + '\n' + \
    function(syscalls, 'static void console_kd_reset_for_dead_owner(thread_t *owner, int tty_idx) {') + r'''
int main(void) {
    assert(devfs_path_to_tty("/dev/tty0") == 1);
    assert(devfs_path_to_tty("/dev/vc/0") == 1);
    assert(devfs_path_to_tty("/dev/tty2") == 1);
    assert(devfs_path_to_tty("/dev/vc/2") == 1);
    assert(devfs_path_to_tty("/dev/tty2bad") == -1);
    active = 0;
    assert(devfs_path_to_tty("/dev/tty0") == 0);
    process_t p, other, unrelated;
    thread_t owner = { &p, 10 }, child = { &unrelated, 11 };
    console_graphics_owner[1] = &p; modes[1] = 1;
    console_graphics_owner[2] = &other; modes[2] = 1;
    console_kd_reset_for_dead_owner(&child, 1);
    assert(modes[1] && restored == -1);
    console_kd_reset_for_dead_owner(&owner, -1);
    assert(!modes[1] && modes[2] && restored == 1 && reblit == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='graphics-vt-', dir='/tmp/opencode') as tmp:
    c = Path(tmp) / 'test.c'
    binary = Path(tmp) / 'test'
    c.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: VT aliases and owner-specific graphics cleanup')
