/*
 * Wall-clock timekeeping.
 *
 * Linux: kernel/time/timekeeping.c (ktime_get_real_ts64) and
 * kernel/time/timeconv.c (mktime64). Sample RTC once, then CLOCK_REALTIME
 * tracks the monotonic clocksource. Re-reading CMOS every syscall made
 * OpenPGP Date/Valid-Until checks jitter and broke apt-secure.
 */

#include <timekeeping.h>
#include <rtc.h>
#include <klog.h>

static int64_t tk_offs_real_us;
static int tk_ready;

/*
 * mktime64() — kernel/time/timeconv.c
 *
 * Converts Gregorian date to seconds since 1970-01-01 00:00:00 UTC.
 * month is 1..12, year is full (e.g. 2026).
 */
static int64_t mktime64(unsigned int year0, unsigned int mon0,
			unsigned int day, unsigned int hour,
			unsigned int min, unsigned int sec)
{
	unsigned int mon = mon0, year = year0;

	/* 1..12 -> 11,12,1..10 so February (leap day) is last. */
	if (0 >= (int)(mon -= 2)) {
		mon += 12;
		year -= 1;
	}

	return ((((int64_t)
		  (year / 4 - year / 100 + year / 400 + 367 * mon / 12 + day) +
		  year * 365 - 719499
		) * 24 + hour) * 60 + min) * 60 + sec;
}

void timekeeping_init(void)
{
	rtc_datetime_t dt;
	int64_t real_us;
	uint64_t mono_us;

	rtc_read_datetime(&dt);
	real_us = mktime64(dt.year, dt.month, dt.day,
			   dt.hour, dt.minute, dt.second) * 1000000ll;
	mono_us = time_monotonic_us();
	tk_offs_real_us = real_us - (int64_t)mono_us;
	tk_ready = 1;
}

void ktime_get_real_ts64(int64_t *sec, int64_t *nsec)
{
	uint64_t now;
	int64_t real_us;

	if (!tk_ready)
		timekeeping_init();
	now = time_monotonic_us();
	real_us = (int64_t)now + tk_offs_real_us;
	if (real_us < 0)
		real_us = 0;
	if (sec)
		*sec = real_us / 1000000;
	if (nsec)
		*nsec = (real_us % 1000000) * 1000;
}
