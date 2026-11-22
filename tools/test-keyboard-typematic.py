#!/usr/bin/env python3
"""Guard PS/2 typematic setup and IRQ-safe command ordering."""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "drv/input/keyboard.c").read_text()
start = source.index("void ps2_keyboard_init()")
end = source.index("// Получить символ", start)
setup = source[start:end]

mask = setup.index("pic_mask_irq(1)")
handler = setup.index("idt_set_handler(33, keyboard_handler)")
set_scancode = setup.index("ps2_kbd_send_ack(0x02)")
typematic = setup.index("ps2_kbd_send_ack(0xF3)")
typematic_arg = setup.index("ps2_kbd_send_ack(0x00)")
enable = setup.index("ps2_kbd_send_ack(0xF4)")
unmask = setup.index("pic_unmask_irq(1)")
assert mask < handler < set_scancode < typematic < typematic_arg < enable < unmask
assert "fastest repeat rate (about 30 characters/sec)" in setup
print("PASS: PS/2 ACKs are polled with IRQ1 masked; typematic set to fastest rate")
