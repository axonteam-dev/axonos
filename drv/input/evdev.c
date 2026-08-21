/*
 * /dev/input/eventN — Linux drivers/input/evdev.c (ioctl + packet stream).
 *
 * uapi: include/uapi/linux/input.h, input-event-codes.h
 * Hardware mapping: drivers/input/keyboard/atkbd.c (set1) and
 * drivers/input/mouse/psmouse-base.c (REL_* / BTN_*).
 */

#include <input_evdev.h>
#include <uapi_linux_input.h>
#include <devfs.h>
#include <klog.h>
#include <spinlock.h>
#include <string.h>
#include <thread.h>
#include <timekeeping.h>

#ifndef EAGAIN
#define EAGAIN	11
#endif
#ifndef EINVAL
#define EINVAL	22
#endif
#ifndef ENODEV
#define ENODEV	19
#endif
#ifndef ENOTTY
#define ENOTTY	25
#endif
#ifndef EFAULT
#define EFAULT	14
#endif

#define EVDEV_QUEUE		64
#define EVDEV_KBD		0
#define EVDEV_MOUSE		1
#define EVDEV_NDEV		2
#define BITS_PER_LONG		64
#define NLONGS(bits)		(((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))

struct evdev_dev {
	const char *path;
	const char *name;
	const char *phys;
	struct input_id id;
	unsigned long evbit[NLONGS(EV_CNT)];
	unsigned long keybit[NLONGS(KEY_CNT)];
	unsigned long relbit[NLONGS(REL_CNT)];
	unsigned long mscbit[NLONGS(MSC_CNT)];
	unsigned long ledbit[NLONGS(LED_CNT)];
	unsigned long repbit[NLONGS(REP_CNT)];
	unsigned long propbit[NLONGS(INPUT_PROP_CNT)];
	unsigned long keystate[NLONGS(KEY_CNT)];
	struct input_event q[EVDEV_QUEUE];
	int head;
	int tail;
	int count;
	spinlock_t lock;
	struct fs_file *grabber;
	int clockid; /* CLOCK_MONOTONIC = 1, CLOCK_REALTIME = 0 */
	uint8_t btn;
};

static struct evdev_dev g_evdev[EVDEV_NDEV];
static int g_evdev_ready;
static uint8_t g_kbd_e0;
static uint8_t g_kbd_e1skip;

static void evdev_set_bit(unsigned long *addr, unsigned nr)
{
	addr[BIT_WORD(nr)] |= BIT_MASK(nr);
}

static int evdev_test_bit(const unsigned long *addr, unsigned nr)
{
	return (addr[BIT_WORD(nr)] & BIT_MASK(nr)) != 0;
}

static struct evdev_dev *evdev_from_file(const struct fs_file *f)
{
	int i;

	if (!f)
		return NULL;
	for (i = 0; i < EVDEV_NDEV; i++) {
		if (f->driver_private == &g_evdev[i])
			return &g_evdev[i];
	}
	if (f->path && strcmp(f->path, "/dev/input/event0") == 0)
		return &g_evdev[EVDEV_KBD];
	if (f->path && strcmp(f->path, "/dev/input/event1") == 0)
		return &g_evdev[EVDEV_MOUSE];
	return NULL;
}

int evdev_is_file(const struct fs_file *f)
{
	return evdev_from_file(f) != NULL;
}

int evdev_keyboard_grabbed(void)
{
	return g_evdev[EVDEV_KBD].grabber != NULL;
}

static void evdev_stamp(struct evdev_dev *d, struct input_event *ev)
{
	int64_t sec, nsec;
	uint64_t us;

	if (d->clockid == 0) {
		ktime_get_real_ts64(&sec, &nsec);
		ev->input_event_sec = (uint64_t)sec;
		ev->input_event_usec = (uint64_t)nsec / 1000ull;
		return;
	}
	us = time_monotonic_us();
	ev->input_event_sec = us / 1000000ull;
	ev->input_event_usec = us % 1000000ull;
}

static void evdev_queue(struct evdev_dev *d, uint16_t type, uint16_t code, int32_t value)
{
	struct input_event ev;
	unsigned long flags;

	evdev_stamp(d, &ev);
	ev.type = type;
	ev.code = code;
	ev.value = value;

	acquire_irqsave(&d->lock, &flags);
	if (d->count >= EVDEV_QUEUE) {
		/* Linux evdev: drop oldest and SYN_DROPPED on overflow. */
		d->head = (d->head + 1) % EVDEV_QUEUE;
		d->count--;
	}
	d->q[d->tail] = ev;
	d->tail = (d->tail + 1) % EVDEV_QUEUE;
	d->count++;
	release_irqrestore(&d->lock, flags);
}

static void evdev_sync(struct evdev_dev *d)
{
	evdev_queue(d, EV_SYN, SYN_REPORT, 0);
}

static void evdev_setup_keyboard(struct evdev_dev *d)
{
	unsigned i;

	d->path = "/dev/input/event0";
	d->name = "AT Translated Set 2 keyboard";
	d->phys = "isa0060/serio0/input0";
	d->id.bustype = BUS_I8042;
	d->id.vendor = 0x0001;
	d->id.product = 0x0001;
	d->id.version = 0xab41;
	d->clockid = 1; /* CLOCK_MONOTONIC — linux evdev_open default */
	evdev_set_bit(d->evbit, EV_SYN);
	evdev_set_bit(d->evbit, EV_KEY);
	evdev_set_bit(d->evbit, EV_MSC);
	evdev_set_bit(d->evbit, EV_LED);
	evdev_set_bit(d->evbit, EV_REP);
	evdev_set_bit(d->mscbit, MSC_SCAN);
	evdev_set_bit(d->ledbit, LED_NUML);
	evdev_set_bit(d->ledbit, LED_CAPSL);
	evdev_set_bit(d->ledbit, LED_SCROLLL);
	evdev_set_bit(d->repbit, REP_DELAY);
	evdev_set_bit(d->repbit, REP_PERIOD);
	/* atkbd set1 KEY_* is 1:1 for 1..88; plus the usual E0 keys. */
	for (i = 1; i <= 88; i++)
		evdev_set_bit(d->keybit, i);
	evdev_set_bit(d->keybit, KEY_KPENTER);
	evdev_set_bit(d->keybit, KEY_RIGHTCTRL);
	evdev_set_bit(d->keybit, KEY_KPSLASH);
	evdev_set_bit(d->keybit, KEY_SYSRQ);
	evdev_set_bit(d->keybit, KEY_RIGHTALT);
	for (i = KEY_HOME; i <= KEY_DELETE; i++)
		evdev_set_bit(d->keybit, i);
	evdev_set_bit(d->keybit, KEY_LEFTMETA);
	evdev_set_bit(d->keybit, KEY_RIGHTMETA);
	evdev_set_bit(d->keybit, KEY_COMPOSE);
}

static void evdev_setup_mouse(struct evdev_dev *d)
{
	d->path = "/dev/input/event1";
	d->name = "ImPS/2 Generic Mouse";
	d->phys = "isa0060/serio1/input0";
	d->id.bustype = BUS_I8042;
	d->id.vendor = 0x0002;
	d->id.product = 0x0001;
	d->id.version = 0x0000;
	d->clockid = 1;
	evdev_set_bit(d->evbit, EV_SYN);
	evdev_set_bit(d->evbit, EV_KEY);
	evdev_set_bit(d->evbit, EV_REL);
	evdev_set_bit(d->keybit, BTN_LEFT);
	evdev_set_bit(d->keybit, BTN_RIGHT);
	evdev_set_bit(d->keybit, BTN_MIDDLE);
	evdev_set_bit(d->relbit, REL_X);
	evdev_set_bit(d->relbit, REL_Y);
	evdev_set_bit(d->relbit, REL_WHEEL);
	evdev_set_bit(d->propbit, INPUT_PROP_POINTER);
}

void evdev_init(void)
{
	if (g_evdev_ready)
		return;
	memset(g_evdev, 0, sizeof(g_evdev));
	evdev_setup_keyboard(&g_evdev[EVDEV_KBD]);
	evdev_setup_mouse(&g_evdev[EVDEV_MOUSE]);
	(void)devfs_create_char_node("/dev/input/event0", &g_evdev[EVDEV_KBD]);
	(void)devfs_create_char_node("/dev/input/event1", &g_evdev[EVDEV_MOUSE]);
	g_evdev_ready = 1;
}

static uint16_t atkbd_e0_to_key(uint8_t make)
{
	switch (make) {
	case 0x1C: return KEY_KPENTER;
	case 0x1D: return KEY_RIGHTCTRL;
	case 0x35: return KEY_KPSLASH;
	case 0x37: return KEY_SYSRQ;
	case 0x38: return KEY_RIGHTALT;
	case 0x47: return KEY_HOME;
	case 0x48: return KEY_UP;
	case 0x49: return KEY_PAGEUP;
	case 0x4B: return KEY_LEFT;
	case 0x4D: return KEY_RIGHT;
	case 0x4F: return KEY_END;
	case 0x50: return KEY_DOWN;
	case 0x51: return KEY_PAGEDOWN;
	case 0x52: return KEY_INSERT;
	case 0x53: return KEY_DELETE;
	case 0x5B: return KEY_LEFTMETA;
	case 0x5C: return KEY_RIGHTMETA;
	case 0x5D: return KEY_COMPOSE;
	default: return 0;
	}
}

void evdev_ps2_keyboard_byte(uint8_t scancode)
{
	struct evdev_dev *d = &g_evdev[EVDEV_KBD];
	uint8_t make;
	int down;
	uint16_t key;
	unsigned long flags;

	if (!g_evdev_ready)
		return;
	if (scancode == 0xFA || scancode == 0xFE || scancode == 0xAA)
		return;
	if (g_kbd_e1skip) {
		g_kbd_e1skip--;
		return;
	}
	if (scancode == 0xE1) {
		g_kbd_e1skip = 5;
		g_kbd_e0 = 0;
		return;
	}
	if (scancode == 0xE0) {
		g_kbd_e0 = 1;
		return;
	}

	down = !(scancode & 0x80);
	make = scancode & 0x7Fu;
	if (g_kbd_e0) {
		g_kbd_e0 = 0;
		/* Fake shifts around Print Screen / pause — atkbd ignores. */
		if (make == 0x2A || make == 0x36)
			return;
		key = atkbd_e0_to_key(make);
	} else {
		key = make;
		if (key == 0 || key > 88)
			return;
		if (!evdev_test_bit(d->keybit, key))
			return;
	}
	if (!key || !evdev_test_bit(d->keybit, key))
		return;

	acquire_irqsave(&d->lock, &flags);
	if (down)
		evdev_set_bit(d->keystate, key);
	else
		d->keystate[BIT_WORD(key)] &= ~BIT_MASK(key);
	release_irqrestore(&d->lock, flags);

	evdev_queue(d, EV_MSC, MSC_SCAN, (int32_t)make);
	evdev_queue(d, EV_KEY, key, down ? 1 : 0);
	evdev_sync(d);
}

void evdev_ps2_mouse_packet(const uint8_t pkt[3])
{
	struct evdev_dev *d = &g_evdev[EVDEV_MOUSE];
	int dx, dy;
	uint8_t btn, old;
	int emit = 0;

	if (!g_evdev_ready || !pkt)
		return;
	if ((pkt[0] & 0xC0u) != 0)
		return;

	dx = (int8_t)pkt[1];
	dy = (int8_t)pkt[2];
	dy = -dy; /* PS/2 Y is up; Linux REL_Y is down */
	btn = pkt[0] & 0x07u;
	old = d->btn;

	if (dx) {
		evdev_queue(d, EV_REL, REL_X, dx);
		emit = 1;
	}
	if (dy) {
		evdev_queue(d, EV_REL, REL_Y, dy);
		emit = 1;
	}
	if ((btn ^ old) & 0x01) {
		evdev_queue(d, EV_KEY, BTN_LEFT, (btn & 0x01) ? 1 : 0);
		emit = 1;
	}
	if ((btn ^ old) & 0x02) {
		evdev_queue(d, EV_KEY, BTN_RIGHT, (btn & 0x02) ? 1 : 0);
		emit = 1;
	}
	if ((btn ^ old) & 0x04) {
		evdev_queue(d, EV_KEY, BTN_MIDDLE, (btn & 0x04) ? 1 : 0);
		emit = 1;
	}
	d->btn = btn;
	if (emit)
		evdev_sync(d);
}

int evdev_bytes_available(const struct fs_file *f)
{
	struct evdev_dev *d = evdev_from_file(f);
	unsigned long flags;
	int n;

	if (!d)
		return -ENOTTY;
	acquire_irqsave(&d->lock, &flags);
	n = d->count * (int)sizeof(struct input_event);
	release_irqrestore(&d->lock, flags);
	return n;
}

ssize_t evdev_read(struct fs_file *f, void *buf, size_t size)
{
	struct evdev_dev *d = evdev_from_file(f);
	uint8_t *out = buf;
	size_t got = 0;
	int nonblock;

	if (!d || !buf)
		return -ENODEV;
	if (size < sizeof(struct input_event))
		return -EINVAL;
	nonblock = f && (f->flags & 0x800);

	for (;;) {
		unsigned long flags;

		acquire_irqsave(&d->lock, &flags);
		while (got + sizeof(struct input_event) <= size && d->count > 0) {
			memcpy(out + got, &d->q[d->head], sizeof(struct input_event));
			d->head = (d->head + 1) % EVDEV_QUEUE;
			d->count--;
			got += sizeof(struct input_event);
		}
		release_irqrestore(&d->lock, flags);
		if (got > 0)
			return (ssize_t)got;
		if (nonblock)
			return -EAGAIN;
		thread_sleep(1);
	}
}

static int evdev_copy_bits(void *karg, size_t karg_len,
			   const unsigned long *bits, unsigned maxbit)
{
	size_t nbytes = NLONGS(maxbit + 1) * sizeof(unsigned long);

	if (!karg)
		return -EFAULT;
	if (karg_len < nbytes)
		nbytes = karg_len;
	memset(karg, 0, karg_len);
	if (nbytes)
		memcpy(karg, bits, nbytes);
	return 0;
}

static int evdev_copy_str(void *karg, size_t karg_len, const char *s)
{
	size_t n;

	if (!karg || karg_len == 0)
		return -EFAULT;
	memset(karg, 0, karg_len);
	if (!s)
		return 0;
	n = strlen(s);
	if (n >= karg_len)
		n = karg_len - 1;
	memcpy(karg, s, n);
	return 0;
}

int evdev_ioctl(struct fs_file *f, uint32_t cmd, void *karg, size_t karg_len)
{
	struct evdev_dev *d = evdev_from_file(f);
	unsigned nr = cmd & 0xffu;
	unsigned type = (cmd >> 8) & 0xffu;
	int version = EV_VERSION;
	unsigned rep[2] = { 250, 33 };

	if (!d)
		return -ENOTTY;
	if (type != 'E')
		return -ENOTTY;

	/* EVIOCGRAB: linux evdev_do_ioctl treats arg as a flag, not a pointer. */
	if (nr == 0x90) {
		int grab = 0;
		if (karg && karg_len >= sizeof(int))
			grab = *(int *)karg;
		if (grab)
			d->grabber = f;
		else if (d->grabber == f)
			d->grabber = NULL;
		return 0;
	}
	if (nr == 0x91) {
		if (d->grabber == f)
			d->grabber = NULL;
		return 0;
	}
	if (nr == 0xa0) {
		int clkid = 1;
		if (karg && karg_len >= sizeof(int))
			clkid = *(int *)karg;
		if (clkid != 0 && clkid != 1 && clkid != 4 && clkid != 7)
			return -EINVAL;
		d->clockid = (clkid == 0) ? 0 : 1;
		return 0;
	}
	if (nr == 0x01) {
		if (!karg || karg_len < sizeof(int))
			return -EFAULT;
		memcpy(karg, &version, sizeof(version));
		return 0;
	}
	if (nr == 0x02) {
		if (!karg || karg_len < sizeof(d->id))
			return -EFAULT;
		memcpy(karg, &d->id, sizeof(d->id));
		return 0;
	}
	if (nr == 0x03) {
		if (!karg || karg_len < sizeof(rep))
			return -EFAULT;
		memcpy(karg, rep, sizeof(rep));
		return 0;
	}
	if (nr == 0x06)
		return evdev_copy_str(karg, karg_len, d->name);
	if (nr == 0x07)
		return evdev_copy_str(karg, karg_len, d->phys);
	if (nr == 0x08)
		return evdev_copy_str(karg, karg_len, "");
	if (nr == 0x09)
		return evdev_copy_bits(karg, karg_len, d->propbit, INPUT_PROP_MAX);
	if (nr == 0x18)
		return evdev_copy_bits(karg, karg_len, d->keystate, KEY_MAX);
	if (nr == 0x19)
		return evdev_copy_bits(karg, karg_len, d->ledbit, LED_MAX);
	if (nr == 0x1a || nr == 0x1b) {
		if (!karg)
			return -EFAULT;
		memset(karg, 0, karg_len);
		return 0;
	}
	if (nr >= 0x20 && nr < 0x40) {
		unsigned ev = nr - 0x20;
		if (ev == 0)
			return evdev_copy_bits(karg, karg_len, d->evbit, EV_MAX);
		if (ev == EV_KEY)
			return evdev_copy_bits(karg, karg_len, d->keybit, KEY_MAX);
		if (ev == EV_REL)
			return evdev_copy_bits(karg, karg_len, d->relbit, REL_MAX);
		if (ev == EV_MSC)
			return evdev_copy_bits(karg, karg_len, d->mscbit, MSC_MAX);
		if (ev == EV_LED)
			return evdev_copy_bits(karg, karg_len, d->ledbit, LED_MAX);
		if (ev == EV_REP)
			return evdev_copy_bits(karg, karg_len, d->repbit, REP_MAX);
		if (!karg)
			return -EFAULT;
		memset(karg, 0, karg_len);
		return 0;
	}
	/* EVIOCGABS: we have no abs axes. */
	if (nr >= 0x40 && nr < 0x80)
		return -EINVAL;
	return -ENOTTY;
}

void evdev_release(struct fs_file *f)
{
	struct evdev_dev *d = evdev_from_file(f);

	if (!d)
		return;
	if (d->grabber == f)
		d->grabber = NULL;
}
