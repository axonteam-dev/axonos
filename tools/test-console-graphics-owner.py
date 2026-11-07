#!/usr/bin/env python3
"""Unrelated session children must not return Xorg's console to text mode."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int console_kbd_mode =")
end = source.index("#define mark_user_identity_range_2m_sys", start)
assert "console_graphics_owner = cur ? cur->process : NULL;" in source
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define DEVFS_TTY_COUNT 8
typedef struct process { int id; } process_t;
typedef struct thread { process_t *process; uint64_t tid; } thread_t;
static int graphics, repaint, restore;
static void video_set_kd_mode(int mode) { graphics=mode; }
static int video_set_vt_graphics(int tty, int mode) { (void)tty; graphics=mode; return 0; }
static void devfs_tty_restore_sane(int tty) { (void)tty; restore++; }
static int devfs_tty_leave_alt_screen(int tty) { (void)tty; return 0; }
static void devfs_tty_force_reblit(int tty) { (void)tty; repaint++; }
''' + source[start:end] + r'''
int main(void) {
    assert(console_graphics_wait_syscall(7) && console_graphics_wait_syscall(232));
    assert(console_graphics_wait_syscall(270) && console_graphics_wait_syscall(281));
    assert(console_graphics_wait_syscall(441) && !console_graphics_wait_syscall(1));
    process_t x={1}, child={2};
    thread_t xorg={&x,19}, worker={&x,20}, helper={&child,26}, no_process={NULL,30};
    console_graphics_owner=&x; console_graphics_owner_tid=19;
    graphics=1; kd_mode=1; console_kbd_mode=4;
    console_kd_reset_for_dead_owner(&helper,1);
    assert(graphics==1 && kd_mode==1 && console_kbd_mode==4 && !repaint && !restore);
    assert(console_graphics_owned_by(&worker));
    console_kd_reset_for_dead_owner(&xorg,1);
    assert(!graphics && !kd_mode && console_kbd_mode==1 && repaint==1 && restore==1);
    console_graphics_owner_tid=30; graphics=1; kd_mode=1;
    console_kd_reset_for_dead_owner(&helper,1); assert(graphics);
    console_kd_reset_for_dead_owner(&no_process,1); assert(!graphics);
    puts("PASS: only graphics owner exit restores console; child exit leaves Xorg visible");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-console-owner-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
