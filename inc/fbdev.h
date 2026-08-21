#pragma once

#include <stddef.h>
#include <stdint.h>
#include <uapi_linux_fb.h>

struct fs_file;

/* Register linear FB for /dev/fb0 (kva = first pixel, pa = physical of that byte). */
void fbdev_register_linear(void *kva, uint64_t fb_pa, size_t byte_len,
                           uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void fbdev_unregister(void);

int fbdev_is_active(void);
size_t fbdev_byte_len(void);

int fbdev_is_fb0_file(const struct fs_file *f);
/* Align mmap VA so (va % 2MiB) == (fb_pa % 2MiB); required for 2MiB PTEs. */
uintptr_t fbdev_mmap_align_va(uintptr_t addr);
/* Map user [addr, addr+len) to FB bytes [file_off, file_off+len); 2 MiB pages, WC via PCD|PWT. */
int fbdev_mmap_user(uintptr_t addr, size_t len, size_t file_off);
/* VMware SVGA (and similar) need FIFO UPDATE after CPU writes through mmap. */
void fbdev_sync_user_frontbuffer(void);

void fbdev_copy_to(void *dst, size_t offset, size_t n);
void fbdev_copy_from(size_t offset, const void *src, size_t n);

void fbdev_get_var(struct fb_var_screeninfo *v);
void fbdev_get_fix(struct fb_fix_screeninfo *f);
/* Validate FBIOPUT_VSCREENINFO / pan; 0 or -errno. */
int fbdev_check_var(const struct fb_var_screeninfo *v);
void fbdev_flush_display(void);

/*
 * Linux sysfs for Xorg libfbdevhw:
 *   /sys/bus/pci/devices/0000:BB:DD.F/graphics/fb0/   (PCI probe)
 *   /sys/class/graphics/fb0 -> ../../devices/platform/axonfb.0  (non-PCI Option "fbdev")
 */
void fbdev_sysfs_publish(uint8_t bus, uint8_t device, uint8_t function);
/* Call after sysfs_register()/mount — early video init runs before /sys exists. */
void fbdev_sysfs_publish_late(void);
