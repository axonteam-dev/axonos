#!/usr/bin/env python3
"""Exercise both IRQ paths and the poll against a mocked 8042 FIFO."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
kbd = (root / 'drv/input/keyboard.c').read_text()
mouse = (root / 'drv/input/mouse.c').read_text()
drain = kbd[kbd.index('static spinlock_t g_kbd_drain_lock'):kbd.index('// Обработка одного байта сканкода')]
irq = mouse[mouse.index('static void mouse_irq_handler('):mouse.index('\nint mouse_stream_available(', mouse.index('static void mouse_irq_handler('))]
program = r'''
#include <assert.h>
#include <stdint.h>
typedef int spinlock_t;
typedef int cpu_registers_t;
static uint8_t status[16], bytes[16], keys[16], mice[16];
static int head, tail, nk, nm, live = 1;
static unsigned int g_mouse_irq_count;
static uint8_t inb(int port) { return port == 0x64 ? (head < tail ? status[head] : 0) : bytes[head++]; }
static int ps2_aux_is_live(void) { return live; }
static void mouse_process_byte(uint8_t b) { mice[nm++] = b; }
static void keyboard_process_scancode(uint8_t b) { keys[nk++] = b; }
static void acquire(spinlock_t *p) { assert(!*p); *p = 1; }
static void release(spinlock_t *p) { assert(*p); *p = 0; }
static int try_acquire(spinlock_t *p) { if (*p) return 0; *p = 1; return 1; }
''' + drain.replace('static uint32_t g_kbd_left_makes = 0;', '') + irq + r'''
static void put(uint8_t st, uint8_t b) { status[tail] = st | 1; bytes[tail++] = b; }
int main(void) {
    put(0x20, 0x08); put(0, 0x1e); put(0x20, 0xe0);
    mouse_irq_handler(0);
    assert(g_mouse_irq_count == 1);
    assert(nk == 1 && keys[0] == 0x1e && nm == 2 && mice[1] == 0xe0);
    put(0, 0x30); put(0x20, 0x05); keyboard_handler(0);
    assert(nk == 2 && keys[1] == 0x30 && nm == 3 && mice[2] == 0x05);
    put(0x20, 0x08); keyboard_poll_drain(); assert(nm == 4);
    live = 0; put(0x20, 0x20); mouse_irq_handler(0);
    assert(nk == 3 && keys[2] == 0x20);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-ps2-drain-', dir='/tmp/opencode') as tmp:
    source, binary = Path(tmp) / 'test.c', Path(tmp) / 'test'
    source.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: IRQ1, IRQ12 and polling share status-based 8042 routing')
