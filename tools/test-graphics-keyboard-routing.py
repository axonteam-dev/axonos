#!/usr/bin/env python3
"""Graphics VT input goes to evdev, not the text VT, while Alt+Fn remains."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'drv/input/keyboard.c').read_text()
start = source.index('void keyboard_process_scancode(uint8_t scancode) {')
end = source.index('// Обрабатываем только нажатие клавиш', start)
prefix = source[start:end]
program = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#define KBD_DEBUG 0
static bool kbd_extended_prefix, ctrl_pressed, alt_pressed, shift_pressed;
static int graphics, grabbed, events, tty_events, switches, destination;
static void evdev_ps2_keyboard_byte(uint8_t c) { (void)c; events++; }
static int evdev_keyboard_grabbed(void) { return grabbed; }
static int video_kd_graphics(void) { return graphics; }
static void vt_request_switch_irq(int n) { switches++; destination = n; }
''' + prefix + r'''
        tty_events++;
}
int main(void) {
    graphics = 1;
    keyboard_process_scancode(0x1e); /* A: evdev only */
    assert(events == 1 && tty_events == 0);
    keyboard_process_scancode(0x38); keyboard_process_scancode(0x3b);
    keyboard_process_scancode(0xb8);
    assert(events == 4 && tty_events == 0 && switches == 1 && destination == 0);
    keyboard_process_scancode(0x1d); keyboard_process_scancode(0x38);
    keyboard_process_scancode(0x3b); keyboard_process_scancode(0xb8);
    keyboard_process_scancode(0x9d);
    assert(events == 9 && tty_events == 0 && switches == 2 && destination == 0);
    assert(!alt_pressed && !ctrl_pressed);
    const uint8_t fn[] = {0x3b,0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43,0x44,0x57,0x58};
    keyboard_process_scancode(0x38);
    for (int i = 0; i < 12; i++) {
        keyboard_process_scancode(fn[i]);
        assert(destination == i && switches == 3 + i);
    }
    keyboard_process_scancode(0xb8);
    graphics = 0; keyboard_process_scancode(0x1e);
    assert(tty_events == 1);
    grabbed = 1; keyboard_process_scancode(0x1e);
    assert(tty_events == 1);
}
'''
with tempfile.TemporaryDirectory(prefix='axon-graphics-keyboard-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: graphics VT routes keyboard to evdev and preserves Alt+Fn')
