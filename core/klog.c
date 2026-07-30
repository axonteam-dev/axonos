/*
 * core/klog.c — Linux-style printk ring buffer
 *
 * Fixed-size circular buffer (like log_buf). Console + qemu debug get every
 * line; VFS is not a growing sink — unbounded /var/log/kernel appends used to
 * exhaust the kmalloc heap via ramfs krealloc.
 */

#include <klog.h>
#include <debug.h>
#include <vga.h>
#include <stdarg.h>
#include <stdio.h>
#include <fs.h>
#include <ramfs.h>
#include <spinlock.h>
#include <string.h>
#include <apic_timer.h>
#include <pit.h>
#include <devfs.h>
#include <stddef.h>

static spinlock_t klog_lock;
static int klog_inited;

/* Single ring for early + post-init (Linux log_buf). */
#define KLOG_RING_SZ (256 * 1024)
static char klog_ring[KLOG_RING_SZ];
static size_t klog_ring_pos;  /* next write offset */
static size_t klog_ring_len;  /* bytes valid (<= KLOG_RING_SZ) */

#define KLOG_TS_MAX 48
#define KLOG_MSG_MAX 900
#define KLOG_OUT_MAX 1024

uint64_t klog_tsc_base = 0;
uint64_t klog_time_base_usec = 0;
uint64_t klog_tsc_per_us = 0;
uint64_t klog_tsc_hz = 0;

static void klog_console_write_sync_tty(const char *s, size_t n) {
	if (!s || n == 0) return;
	if (devfs_is_ready())
		devfs_tty_console_write(s, n);
	else
		kprintf("%.*s", (int)n, s);
}

static uint64_t klog_rdtsc(void) {
	uint32_t lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

static uint64_t klog_get_time_us(void);

void klog_calibrate_tsc(void) {
	/*
	 * Measure TSC against the PIT tick clock (while IRQ0 still runs).
	 * Gives microsecond resolution for clock_gettime / gettimeofday; the
	 * tick clock alone only steps every 4 ms at HZ=250.
	 */
	klog_tsc_hz = 0;
	klog_tsc_per_us = 0;
	klog_tsc_base = 0;
	klog_time_base_usec = 0;

	uint32_t pit_hz = pit_frequency ? pit_frequency : 250u;
	uint64_t sample_ticks = (uint64_t)pit_hz / 10ull; /* ~100 ms */
	if (sample_ticks < 10ull)
		sample_ticks = 10ull;

	/* Align to a tick edge so the window is clean. */
	uint64_t edge = pit_get_ticks();
	uint32_t spins = 0;
	while (pit_get_ticks() == edge && ++spins < 50000000u)
		asm volatile("pause" ::: "memory");
	edge = pit_get_ticks();
	uint64_t tsc0 = klog_rdtsc();
	uint64_t target = edge + sample_ticks;
	spins = 0;
	while (pit_get_ticks() < target && ++spins < 200000000u)
		asm volatile("pause" ::: "memory");
	uint64_t tsc1 = klog_rdtsc();
	uint64_t got = pit_get_ticks() - edge;
	if (got < 5ull || tsc1 <= tsc0)
		return;

	uint64_t us = (got * 1000000ull) / (uint64_t)pit_hz;
	if (us == 0)
		return;
	uint64_t per_us = (tsc1 - tsc0) / us;
	if (per_us < 1ull || per_us > 100000ull)
		return; /* reject absurd rates (<1 MHz or >100 GHz TSC) */

	klog_tsc_per_us = per_us;
	klog_tsc_hz = per_us * 1000000ull;
	klog_tsc_base = tsc1;
	klog_time_base_usec = (pit_get_ticks() * 1000000ull) / (uint64_t)pit_hz;
	kprintf("TSC: calibrated %llu MHz (per_us=%llu)\n",
		(unsigned long long)(klog_tsc_hz / 1000000ull),
		(unsigned long long)klog_tsc_per_us);
}

void klog_reanchor_tsc(void) {
	if (!klog_tsc_per_us)
		return;
	/* Keep TSC µs continuous with the tick clock after APIC takes over. */
	klog_tsc_base = klog_rdtsc();
	klog_time_base_usec = pit_get_time_us();
}

uint64_t time_monotonic_us(void) {
	return klog_get_time_us();
}

uint64_t time_monotonic_ms(void) {
	return klog_get_time_us() / 1000;
}

static uint64_t klog_get_time_us(void) {
	if (klog_tsc_per_us) {
		uint64_t tsc = klog_rdtsc();
		uint64_t delta = tsc - klog_tsc_base;
		return klog_time_base_usec + delta / klog_tsc_per_us;
	}
	return pit_get_time_us();
}

/* Caller must hold klog_lock. Overwrite oldest when full. */
static void klog_ring_append(const char *p, size_t n) {
	size_t i;
	if (!p || n == 0)
		return;
	for (i = 0; i < n; i++) {
		klog_ring[klog_ring_pos] = p[i];
		klog_ring_pos++;
		if (klog_ring_pos >= KLOG_RING_SZ)
			klog_ring_pos = 0;
		if (klog_ring_len < KLOG_RING_SZ)
			klog_ring_len++;
	}
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
	/*
	 * Optional empty placeholder for userspace that stats the path.
	 * Do not seed or append the ring here — that was the OOM path.
	 */
	{
		struct fs_file *f = fs_create_file("/var/log/kernel");
		if (!f)
			f = fs_open("/var/log/kernel");
		if (f)
			fs_file_free(f);
	}
	klog_inited = 1;
	release_irqrestore(&klog_lock, irqf);
}

void klog_user_write(const char *s, size_t n) {
	unsigned long irqf;
	if (!s || n == 0)
		return;
	acquire_irqsave(&klog_lock, &irqf);
	klog_ring_append(s, n);
	release_irqrestore(&klog_lock, irqf);
	/* Mirror to console like a printk from userspace. */
	klog_console_write_sync_tty(s, n);
#ifdef QEMU_LOG_ENABLE
	qemu_debug_printf("%.*s", (int)n, s);
#endif
}

long klog_syslog_read_all(char *buf, size_t size) {
	unsigned long irqf;
	size_t n, start, i;
	if (!buf || size == 0)
		return 0;
	acquire_irqsave(&klog_lock, &irqf);
	n = klog_ring_len;
	if (n > size)
		n = size;
	if (klog_ring_len < KLOG_RING_SZ)
		start = 0;
	else
		start = klog_ring_pos;
	for (i = 0; i < n; i++)
		buf[i] = klog_ring[(start + i) % KLOG_RING_SZ];
	release_irqrestore(&klog_lock, irqf);
	return (long)n;
}

size_t klog_syslog_buf_size(void) {
	return KLOG_RING_SZ;
}

void klogprintf(const char *fmt, ...) {
	/*
	 * Format under the lock with IRQs off, then release before console.
	 * Painting VBE/tty cell-by-cell with IF=0 froze the machine for seconds
	 * per line and dropped NIC RX.
	 */
	char line[KLOG_OUT_MAX];
	size_t outlen = 0;
	int do_console = 0;

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
#else
		outlen = len;
		if (outlen + 1 > sizeof line)
			outlen = sizeof line - 1u;
		memcpy(line, msg, outlen);
		line[outlen] = '\0';
#endif
		do_console = 1;
		klog_ring_append(line, outlen);
		release_irqrestore(&klog_lock, irqf);
	}

	if (do_console)
		klog_console_write_sync_tty(line, outlen);

#ifdef QEMU_LOG_ENABLE
	qemu_debug_printf("%s", line);
#endif
}
