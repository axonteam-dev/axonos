#!/usr/bin/env python3
"""Run the actual PS/2 packet decoder with a mocked evdev queue."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/input/evdev.c").read_text()
start = source.index("void evdev_ps2_mouse_packet(")
end = source.index("\nint evdev_bytes_available(", start)
snippet = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#define EVDEV_MOUSE 0
#define EV_REL 2
#define EV_KEY 1
#define REL_X 0
#define REL_Y 1
#define BTN_LEFT 0x110
#define BTN_RIGHT 0x111
#define BTN_MIDDLE 0x112
struct evdev_dev { uint8_t btn; };
static struct evdev_dev g_evdev[1];
static int g_evdev_ready = 1, x, y, syncs;
static void evdev_queue(struct evdev_dev *d, int type, int code, int value) {
    (void)d; if (type == EV_REL && code == REL_X) x = value;
    if (type == EV_REL && code == REL_Y) y = value;
}
static void evdev_sync(struct evdev_dev *d) { (void)d; syncs++; }
''' + snippet + r'''
int main(void) {
    const uint8_t positive[] = {0x08, 200, 200};
    const uint8_t negative[] = {0x38, 56, 56};
    evdev_ps2_mouse_packet(positive); assert(x == 200 && y == -200 && syncs == 1);
    evdev_ps2_mouse_packet(negative); assert(x == -200 && y == 200 && syncs == 2);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ps2-motion-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: PS/2 motion sign comes from packet status byte")
