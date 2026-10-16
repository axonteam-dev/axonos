#pragma once

#include <stdint.h>

/*
 * Linux kernel/time/timekeeping.c — CLOCK_REALTIME is xtime plus the
 * monotonic clocksource, not a CMOS read on every syscall.
 */
void timekeeping_init(void);
void ktime_get_real_ts64(int64_t *sec, int64_t *nsec);
void timekeeping_set_real_us(int64_t real_us);
void timekeeping_adjtime_us(int64_t offset_us);
