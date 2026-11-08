#!/usr/bin/env python3
"""Run the real mouse initialization against a mocked i8042 and PIC."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'drv/input/mouse.c').read_text()
helpers = source[source.index('static int ps2_wait_input_empty'):source.index('static void mouse_stream_push')]
init = source[source.index('void ps2_mouse_init(void)'):]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#define PS2_CMD_PORT 0x64
#define PS2_DATA_PORT 0x60
typedef int cpu_registers_t;
static int g_ps2_aux_live, mask1, mask12, phase, readcmd, scenario, f6count, f4count, keys;
static unsigned int g_mouse_init_state;
static uint8_t q[32], st[32]; static int head, tail;
static void put(uint8_t s, uint8_t b) { st[tail]=s; q[tail++]=b; }
static uint8_t inb(int port) {
    if (port == 0x64) return head < tail ? st[head] | 1 : 0;
    assert(port == 0x60 && head < tail); return q[head++];
}
static void outb(int port, int v) {
    if (port == 0x80) return;
    if (port == 0x64) {
        if (v == 0xa9) { assert(mask1 && mask12); if (scenario != 3) put(0, 0); }
        if (v == 0x20) put(0, 0x45);
        if (v == 0x60) readcmd=1;
        if (v == 0xd4) phase=1;
    } else if (readcmd) { assert((v & 0x73) == 0x43); readcmd=0; }
    else if (phase) {
        phase=0;
        if (v == 0xf6) { f6count++; if (scenario == 1 && f6count == 1) { put(0, 0x1e); put(0x20, 0xfe); } else put(0x20, 0xfa); }
        if (v == 0xf4) { f4count++; if (scenario != 2) put(0x20, 0xfa); }
    }
}
static void keyboard_process_scancode(uint8_t b) { assert(b == 0x1e); keys++; }
static void pic_mask_irq(int n) { if (n == 1) mask1=1; else mask12=1; }
static void pic_unmask_irq(int n) { if (n == 1) mask1=0; else mask12=0; }
static void mouse_irq_handler(cpu_registers_t *r) { (void)r; }
static void idt_set_handler(int n, void (*f)(cpu_registers_t *)) { assert(n == 44 && f); }
static int devfs_create_char_node(const char *s, void *p) { (void)s; (void)p; return 0; }
static void mouse_register_sysfs(void) {}
static void qemu_debug_printf(const char *s) { (void)s; }
''' + helpers + init + r'''
int main(void) {
    for (scenario=0; scenario<4; scenario++) {
        head=tail=phase=readcmd=f6count=f4count=keys=g_ps2_aux_live=0;
        mask1=mask12=0;
        ps2_mouse_init();
        assert(!mask1);
        if (scenario < 2) { assert(g_ps2_aux_live && !mask12 && f4count == 1 && g_mouse_init_state == 1); }
        else { assert(!g_ps2_aux_live && mask12 && g_mouse_init_state == 2); }
        if (scenario == 1) assert(f6count == 2 && keys == 1);
    }
}
'''
with tempfile.TemporaryDirectory(prefix='axon-ps2-init-', dir='/tmp/opencode') as tmp:
    c, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    c.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: PS/2 probe masking, ACK retry, keyboard routing and failure handling')
