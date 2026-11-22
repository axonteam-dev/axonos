#!/usr/bin/env python3
"""Compile the kernel VT state machine against deterministic host stubs."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
wait = dispatch[dispatch.index('if (req == 0x5607)'):]
wait = wait[:wait.index('if (req == TCSETS')]
assert 'devfs_get_active()' in wait and 'thread_has_interrupt_signal(cur)' in wait
release_ioctl = dispatch[dispatch.index('if (req == 0x5605)'):dispatch.index('/* For the remaining tty-specific ioctls')]
assert 'cur->attached_tty != vt_index && !syscall_task_capable(cur, 26)' in release_ioctl
keyboard = (root / "drv/input/keyboard.c").read_text()
assert keyboard.count('vt_request_switch_irq(') == 4
assert 'devfs_switch_tty(' not in keyboard
headers = {
    "devfs.h": "#define DEVFS_TTY_COUNT 12\nint devfs_get_active(void); int devfs_switch_tty(int);\n",
    "process.h": "#include <stddef.h>\nint process_signal_targets(void *, int, int);\n",
    "thread.h": "void thread_sleep(unsigned);\n",
    "spinlock.h": "typedef int spinlock_t;\nvoid acquire(spinlock_t *); void release(spinlock_t *);\n",
    "video.h": "int video_vt_graphics(int);\n",
}
program = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <errno.h>
#include <vt.h>
static int active, live[16], sent[16], sends[16], busy;
static jmp_buf done;
int devfs_get_active(void) { return active; }
int video_vt_graphics(int n) { (void)n; return 0; }
int devfs_switch_tty(int n) { if (busy) return -1; active = n; return 0; }
int process_signal_targets(void *p, int pid, int sig) {
    (void)p; if (!live[pid]) return 0;
    if (sig) { sent[pid] = sig; sends[pid]++; }
    return 1;
}
void acquire(int *p) { assert(!*p); *p = 1; }
void release(int *p) { assert(*p); *p = 0; }
void thread_sleep(unsigned ms) { assert(ms == 10); longjmp(done, 1); }
static void tick(void) { if (!setjmp(done)) vt_worker(); }
int main(void) {
    struct vt_mode_k a = {1, 0, 10, 12, 0}, b = {1, 0, 14, 15, 0}, got;
    live[2] = live[3] = 1;
    assert(!vt_set_mode(0, &a, 2));
    assert(!vt_set_mode(1, &b, 3));
    assert(!vt_get_mode(0, &got) && got.relsig == 10);
    assert(!vt_get_mode(1, &got) && got.relsig == 14);
    assert(vt_request_switch(12) == -EINVAL);
    vt_request_switch_irq(1); assert(active == 0 && !sent[2]);
    tick(); assert(active == 0 && sent[2] == 10);
    assert(!vt_request_switch(1) && sends[2] == 2 && active == 0);
    /* Linux permits a helper with the VT fd to deny or grant release. */
    assert(!vt_release(0, 0, 3) && active == 0);
    assert(!vt_request_switch(1) && active == 0);
    busy = 1; assert(!vt_release(0, 1, 3) && active == 0);
    tick(); assert(active == 0);
    assert(!vt_release(0, 0, 3));
    assert(!vt_request_switch(1) && active == 0);
    assert(!vt_release(0, 1, 3) && active == 0);
    busy = 0; tick(); assert(active == 1 && sent[3] == 15);
    assert(!vt_release(1, 2, 3));
    assert(!vt_release(1, 2, 3));
    assert(!vt_request_switch(0) && sent[3] == 14);
    live[3] = 0; tick(); tick();
    assert(active == 0 && sent[2] == 12);
    assert(!vt_release(0, 2, 2));
    a.mode = 9; assert(vt_set_mode(0, &a, 2) == -EINVAL);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vt-process-", dir="/tmp/opencode") as tmp:
    tmp = Path(tmp)
    for name, content in headers.items():
        (tmp / name).write_text(content)
    (tmp / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(tmp), "-I", str(root / "inc"),
                    str(root / "core/vt.c"), str(tmp / "test.c"),
                    "-o", str(tmp / "test")], check=True)
    subprocess.run([str(tmp / "test")], check=True)
print("PASS: VT_PROCESS handshake and deferred switch requests")
