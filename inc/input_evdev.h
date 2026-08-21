#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>

/* Linux drivers/input/evdev.c — /dev/input/eventN char nodes. */
void evdev_init(void);

int evdev_is_file(const struct fs_file *f);
int evdev_keyboard_grabbed(void);

/* IRQ: set-1 scancode (with E0 prefix bytes) and a complete PS/2 mouse packet. */
void evdev_ps2_keyboard_byte(uint8_t scancode);
void evdev_ps2_mouse_packet(const uint8_t pkt[3]);

ssize_t evdev_read(struct fs_file *f, void *buf, size_t size);
int evdev_bytes_available(const struct fs_file *f);
int evdev_ioctl(struct fs_file *f, uint32_t cmd, void *karg, size_t karg_len);
void evdev_release(struct fs_file *f);
