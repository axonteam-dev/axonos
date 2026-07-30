#pragma once

#include <stdint.h>
#include <stddef.h>

/* After ramfs_register(): create /var/log; log lines live in a fixed ring (printk-style). */
void klog_init(void);

/* Kernel printf → console + fixed ring buffer (+ qemu debug). */
void klogprintf(const char *fmt, ...);

/* /dev/kmsg and SYS_syslog: inject a message into the printk ring. */
void klog_user_write(const char *s, size_t n);
/* Copy ring bytes into buf; returns bytes copied (Linux SYSLOG_ACTION_READ_ALL). */
long klog_syslog_read_all(char *buf, size_t size);
size_t klog_syslog_buf_size(void);

/* Calibrate TSC-based high-resolution timestamping (non-blocking if APIC not ready). */
void klog_calibrate_tsc(void);
/* Re-sync TSC epoch to current tick clock (call after switching PIT→APIC). */
void klog_reanchor_tsc(void);

/* Set by klog_calibrate_tsc(); 0 until calibrated. Used for CLI-safe busy waits (e.g. SMP INIT/SIPI). */
extern uint64_t klog_tsc_per_us;
extern uint64_t klog_tsc_hz;

/* Monotonic time (us/ms) — same source as kernel log timestamps (TSC when calibrated). */
uint64_t time_monotonic_us(void);
uint64_t time_monotonic_ms(void);


