/*
 * core/klog.c — kernel ring buffer log + /var/log/kernel
 *
 * Until klog_init(): messages go only to console + a fixed early buffer (no VFS).
 * klog_init() creates /var/log, flushes the early buffer to /var/log/kernel, then
 * each line is appended in a single fs_write (one contiguous buffer: timestamp + text).
 */

#include <klog.h>
#include <debug.h>
#include <vga.h>
#include <stdarg.h>
#include <stdio.h>
#include <fs.h>
#include <ramfs.h>
#include <stat.h>
#include <spinlock.h>
#include <string.h>
#include <apic_timer.h>
#include <pit.h>
#include <console.h>
#include <devfs.h>

static spinlock_t klog_lock;
static int klog_inited;

/* Early log ring: no kmalloc, safe before klog_init() and avoids fragile heap+vfs races. */
#define KLOG_EARLY_SZ (96 * 1024)
static char klog_early[KLOG_EARLY_SZ];
static size_t klog_early_used;

#define KLOG_TS_MAX 48
#define KLOG_MSG_MAX 900
#define KLOG_OUT_MAX 1024

uint64_t klog_tsc_base = 0;
uint64_t klog_time_base_usec = 0;
uint64_t klog_tsc_per_us = 0;
uint64_t klog_tsc_hz = 0;

static void klog_console_write_sync_tty(const char *s, size_t n) {
	/* Keep devfs tty cursor in sync for kernel log output so that interactive
	   tty programs don't overwrite logs (klogprintf bypasses /dev/tty writes). */
	if (!s || n == 0) return;
	struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
	if (!tty) {
		/* Fall back to VGA printf path. */
		kprintf("%.*s", (int)n, s);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		console_set_cursor(tty->cursor_x, tty->cursor_y);
		/* Literal cells only: klog timestamps start with '['.  Feeding them
		 * through kputchar's ANSI FSM after a stale ESC leaves "[H" glued onto
		 * boot lines (looks like a broken login clear). */
		console_putc_tty_literal((uint8_t)s[i],
			tty->current_attr ? tty->current_attr : 0x07);
		console_get_cursor(&tty->cursor_x, &tty->cursor_y);
	}
}

static uint64_t klog_get_time_us(void);

void klog_calibrate_tsc(void) {
	/* VM TSC hints can be inconsistent with the virtual timer. Keep klog on
	 * the same tick clock as sleep/poll/uptime so log time cannot drift. */
	klog_tsc_hz = 0;
	klog_tsc_per_us = 0;
	klog_tsc_base = 0;
	klog_time_base_usec = 0;
}

uint64_t time_monotonic_us(void) {
	return klog_get_time_us();
}

uint64_t time_monotonic_ms(void) {
	return klog_get_time_us() / 1000;
}

static uint64_t klog_get_time_us(void) {
	return pit_get_time_ms() * 1000;
}

static void klog_early_append(const char *p, size_t n) {
	if (!p || n == 0) return;
	if (klog_early_used + n > KLOG_EARLY_SZ) {
		static int once;
		if (!once) {
			once = 1;
			kprintf("klog: early buffer full; dropping further pre-init lines\n");
		}
		return;
	}
	memcpy(klog_early + klog_early_used, p, n);
	klog_early_used += n;
}

/* Caller must hold klog_lock + irq disabled. */
static void klog_flush_early_to_file(void) {
	if (klog_early_used == 0) return;
	struct fs_file *f = fs_create_file("/var/log/kernel");
	if (!f)
		f = fs_open("/var/log/kernel");
	if (!f)
		return;
	(void)fs_write(f, klog_early, klog_early_used, 0);
	fs_file_free(f);
	klog_early_used = 0;
}

void klog_init(void) {
	unsigned long irqf;
	acquire_irqsave(&klog_lock, &irqf);
	if (klog_inited) {
		release_irqrestore(&klog_lock, irqf);
		return;
	}
	(void)ramfs_mkdir("/var");
	(void)ramfs_mkdir("/var/log");
	klog_flush_early_to_file();
	klog_inited = 1;
	release_irqrestore(&klog_lock, irqf);
}

void klogprintf(const char *fmt, ...) {
	/*
	 * Format under the lock with IRQs off, then release before console/VFS.
	 * Painting VBE/tty cell-by-cell with IF=0 froze the machine for seconds
	 * per line (SSH connect sniff / any hot-path klog) and dropped NIC RX.
	 */
	char line[KLOG_OUT_MAX];
	size_t outlen = 0;
	int do_console = 0;
	int early = 0;
	int inited = 0;

	{
		unsigned long irqf;
		acquire_irqsave(&klog_lock, &irqf);

		char msg[KLOG_MSG_MAX];
		va_list ap;
		va_start(ap, fmt);
		int n = vsnprintf(msg, sizeof msg, fmt, ap);
		va_end(ap);
		if (n < 0) {
			release_irqrestore(&klog_lock, irqf);
			return;
		}
		size_t len = (size_t)n;
		if (len >= sizeof msg)
			len = sizeof msg - 1;
		if (len == 0 || msg[len - 1] != '\n') {
			if (len + 1 < sizeof msg)
				msg[len++] = '\n';
			else if (len > 0)
				msg[len - 1] = '\n';
		}

#ifdef KERNEL_LOG_TIME
		char ts[KLOG_TS_MAX];
		uint64_t usec = klog_get_time_us();
		uint64_t secs = usec / 1000000;
		uint64_t micros = usec % 1000000;
		int tn = snprintf(ts, sizeof ts, "[%5llu.%06llu] ",
				  (unsigned long long)secs, (unsigned long long)micros);
		size_t tslen = 0;
		if (tn > 0) {
			if ((size_t)tn < sizeof ts)
				tslen = (size_t)tn;
			else
				tslen = sizeof ts - 1u;
		}
		outlen = tslen + len;
		if (outlen + 1 > sizeof line) {
			size_t room = sizeof line - tslen - 1u;
			if (room > len)
				room = len;
			memcpy(line, ts, tslen);
			memcpy(line + tslen, msg, room);
			outlen = tslen + room;
		} else {
			memcpy(line, ts, tslen);
			memcpy(line + tslen, msg, len);
		}
		line[outlen] = '\0';
		do_console = 1;
#else
		outlen = len;
		if (outlen + 1 > sizeof line)
			outlen = sizeof line - 1u;
		memcpy(line, msg, outlen);
		line[outlen] = '\0';
#endif

		inited = klog_inited;
		if (!inited) {
			klog_early_append(line, outlen);
			early = 1;
		}

		release_irqrestore(&klog_lock, irqf);
	}

	if (do_console)
		klog_console_write_sync_tty(line, outlen);

#ifdef QEMU_LOG_ENABLE
	qemu_debug_printf("%s", line);
#endif

	if (early)
		return;

	if (inited) {
		struct fs_file *f = fs_open("/var/log/kernel");
		if (!f)
			f = fs_create_file("/var/log/kernel");
		if (f) {
			size_t off = (size_t)f->size;
			struct stat st;
			if (vfs_fstat(f, &st) == 0 && st.st_size >= 0)
				off = (size_t)st.st_size;
			(void)fs_write(f, line, outlen, off);
			fs_file_free(f);
		}
	}
}
