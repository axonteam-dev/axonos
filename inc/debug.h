#pragma once

#include <stdint.h>

struct thread;
typedef struct thread thread_t;

#ifndef AXON_PRODUCTION
#define AXON_PRODUCTION 0
#endif

/*
 * Development console/serial traces (COW, pipe, fork child, ash-watch, …).
 * Off by default. Prefer config.cfg (DEVEL_DEBUG=y), or override with
 * make CFLAGS_EXTRA='-DDEVEL_DEBUG=1'.
 */
#ifndef DEVEL_DEBUG
#define DEVEL_DEBUG 0
#endif

#ifndef AXON_FORK_DEBUG
#define AXON_FORK_DEBUG DEVEL_DEBUG
#endif

#if AXON_PRODUCTION
#undef DEVEL_DEBUG
#define DEVEL_DEBUG 0
#undef AXON_FORK_DEBUG
#define AXON_FORK_DEBUG 0
#endif

void kprintf(const char *fmt, ...);

#if DEVEL_DEBUG
#define devel_printf(...) kprintf(__VA_ARGS__)
#else
#define devel_printf(...) ((void)0)
#endif

void qemu_debug_printf(const char *format, ...);
void debug_serial_marker(const char *message);
/* User-visible trace: writes to cur->fds[1] (stdout) and qemu_debug_printf. */
void axon_user_dbg(thread_t *cur, const char *tag, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c);
/* OOM notify: uses only stack + write_serial, no kmalloc. Safe to call when heap exhausted. */
void oom_serial_notify(unsigned long long syscall_num, const char *name);
