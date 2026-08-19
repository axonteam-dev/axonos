#include <fbdev.h>
#include <uapi_linux_fb.h>
#include <devfs.h>
#include <fs.h>
#include <paging.h>
#include <video.h>
#include <sysfs.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENODEV
#define ENODEV 19
#endif

static struct {
	void *kva;
	uint64_t pa;
	size_t len;
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t bpp;
	int active;
} g_fbdev;

/* Non-NULL devfs char-node private (must not be interpreted as tty or int marker). */
static char fbdev_devfs_tag;

void fbdev_register_linear(void *kva, uint64_t fb_pa, size_t byte_len,
                           uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
	memset(&g_fbdev, 0, sizeof(g_fbdev));
	if (!kva || byte_len == 0 || fb_pa == 0) {
		g_fbdev.active = 0;
		return;
	}
	g_fbdev.kva = kva;
	g_fbdev.pa = fb_pa;
	g_fbdev.len = byte_len;
	g_fbdev.width = width;
	g_fbdev.height = height;
	g_fbdev.pitch = pitch;
	g_fbdev.bpp = bpp;
	g_fbdev.active = 1;
	(void)devfs_create_char_node("/dev/fb0", (void *)&fbdev_devfs_tag);
	/* Linux DRM card node so X/docker probes succeed; fbdev remains the
	 * real scanout.  access("/dev/dri/card0") must not SKIP axon-tests. */
	(void)devfs_create_char_node("/dev/dri/card0", (void *)&fbdev_devfs_tag);
}

void fbdev_unregister(void) {
	g_fbdev.active = 0;
	memset(&g_fbdev, 0, sizeof(g_fbdev));
}

int fbdev_is_active(void) {
	return g_fbdev.active ? 1 : 0;
}

size_t fbdev_byte_len(void) {
	return g_fbdev.active ? g_fbdev.len : 0;
}

int fbdev_is_fb0_file(const struct fs_file *f) {
	return f && f->path && strcmp(f->path, "/dev/fb0") == 0;
}

void fbdev_copy_to(void *dst, size_t offset, size_t n) {
	if (!g_fbdev.active || n == 0 || !dst)
		return;
	memcpy(dst, (const uint8_t *)g_fbdev.kva + offset, n);
}

void fbdev_flush_display(void) {
	if (!g_fbdev.active)
		return;
	video_flush_region_pixels(0, 0, g_fbdev.width, g_fbdev.height);
	video_display_sync();
}

void fbdev_copy_from(size_t offset, const void *src, size_t n) {
	if (!g_fbdev.active || n == 0 || !src)
		return;
	memcpy((uint8_t *)g_fbdev.kva + offset, src, n);
	fbdev_flush_display();
}

int fbdev_mmap_user(uintptr_t addr, size_t len, size_t file_off) {
	if (!g_fbdev.active || len == 0)
		return -1;
	if ((uint64_t)file_off + (uint64_t)len > (uint64_t)g_fbdev.len)
		return -1;

	const uint64_t mask = (uint64_t)PAGE_SIZE_2M - 1ULL;
	uint64_t fb_start = g_fbdev.pa;
	uintptr_t end = addr + len;

	const uint64_t map_flags = (uint64_t)(PG_PRESENT | PG_RW | PG_US | PG_PCD | PG_PWT);

	for (uintptr_t u = addr & ~(uintptr_t)mask; u < end; u += (uintptr_t)PAGE_SIZE_2M) {
		uint64_t p = fb_start + (uint64_t)file_off + (uint64_t)((intptr_t)u - (intptr_t)addr);
		uint64_t pa_page = p & ~mask;
		if (map_page_2m((uint64_t)u, pa_page, map_flags) != 0)
			return -1;
	}
	return 0;
}

void fbdev_get_var(struct fb_var_screeninfo *v) {
	memset(v, 0, sizeof(*v));
	if (!g_fbdev.active)
		return;
	v->xres = g_fbdev.width;
	v->yres = g_fbdev.height;
	v->xres_virtual = g_fbdev.width;
	v->yres_virtual = g_fbdev.height;
	v->bits_per_pixel = g_fbdev.bpp ? g_fbdev.bpp : 32;
	v->activate = FB_ACTIVATE_NOW;
	v->vmode = FB_VMODE_NONINTERLACED;
	if (v->bits_per_pixel == 32 || v->bits_per_pixel == 24) {
		v->red.offset = 16;   v->red.length = 8;
		v->green.offset = 8;  v->green.length = 8;
		v->blue.offset = 0;   v->blue.length = 8;
		v->transp.offset = 24; v->transp.length = (v->bits_per_pixel == 32) ? 8u : 0u;
	} else if (v->bits_per_pixel == 16) {
		v->red.offset = 11;   v->red.length = 5;
		v->green.offset = 5;  v->green.length = 6;
		v->blue.offset = 0;   v->blue.length = 5;
	} else if (v->bits_per_pixel == 15) {
		v->red.offset = 10;   v->red.length = 5;
		v->green.offset = 5;  v->green.length = 5;
		v->blue.offset = 0;   v->blue.length = 5;
	}
}

void fbdev_get_fix(struct fb_fix_screeninfo *f) {
	memset(f, 0, sizeof(*f));
	if (!g_fbdev.active)
		return;
	strncpy(f->id, "axonfb", sizeof(f->id) - 1);
	f->smem_start = (unsigned long)g_fbdev.pa;
	f->smem_len = (uint32_t)g_fbdev.len;
	f->type = FB_TYPE_PACKED_PIXELS;
	f->visual = (g_fbdev.bpp >= 15) ? FB_VISUAL_TRUECOLOR : FB_VISUAL_PSEUDOCOLOR;
	f->line_length = g_fbdev.pitch;
	f->accel = FB_ACCEL_NONE;
}

int fbdev_check_var(const struct fb_var_screeninfo *v) {
	if (!g_fbdev.active)
		return -ENODEV;
	if (!v)
		return -EINVAL;
	if ((v->activate & FB_ACTIVATE_TEST) != 0)
		return 0;
	if (v->xres != g_fbdev.width || v->yres != g_fbdev.height)
		return -EINVAL;
	/* Depth 24 on 32bpp XRGB is normal for Linux fbdevhw. */
	if (v->bits_per_pixel && v->bits_per_pixel != g_fbdev.bpp) {
		if (!(g_fbdev.bpp == 32 && (v->bits_per_pixel == 24 || v->bits_per_pixel == 32)))
			return -EINVAL;
	}
	if (v->xoffset || v->yoffset)
		return -EINVAL;
	return 0;
}

static int g_sysfs_pending;
static uint8_t g_sysfs_bus, g_sysfs_dev, g_sysfs_fn;

static int fbdev_sysfs_publish_now(uint8_t bus, uint8_t device, uint8_t function) {
	char path[128];

	/* Probe: sysfs_root must exist (after sysfs_register). */
	if (sysfs_mkdir("/sys/class") != 0)
		return -1;

	/* Platform + class (non-PCI fbdev_open; target must NOT contain "devices/pci"). */
	(void)sysfs_mkdir("/sys/devices");
	(void)sysfs_mkdir("/sys/devices/platform");
	(void)sysfs_mkdir("/sys/devices/platform/axonfb.0");
	(void)sysfs_mkdir("/sys/class/graphics");
	if (sysfs_create_symlink("/sys/class/graphics/fb0",
				 "../../devices/platform/axonfb.0") != 0)
		return -1;

	/* PCI graphics/fb0 — Xorg FBDevPciProbe / fbdev_open_pci. */
	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/0000:%02x:%02x.%x",
		 bus, device, function);
	(void)sysfs_mkdir(path);
	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/0000:%02x:%02x.%x/graphics",
		 bus, device, function);
	(void)sysfs_mkdir(path);
	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/0000:%02x:%02x.%x/graphics/fb0",
		 bus, device, function);
	if (sysfs_mkdir(path) != 0)
		return -1;
	return 0;
}

void fbdev_sysfs_publish(uint8_t bus, uint8_t device, uint8_t function) {
	g_sysfs_bus = bus;
	g_sysfs_dev = device;
	g_sysfs_fn = function;
	g_sysfs_pending = 1;
	/* Early video init runs before sysfs_register — retry in publish_late. */
	if (fbdev_sysfs_publish_now(bus, device, function) == 0)
		g_sysfs_pending = 0;
}

void fbdev_sysfs_publish_late(void) {
	if (!g_sysfs_pending || !g_fbdev.active)
		return;
	if (fbdev_sysfs_publish_now(g_sysfs_bus, g_sysfs_dev, g_sysfs_fn) == 0)
		g_sysfs_pending = 0;
}
