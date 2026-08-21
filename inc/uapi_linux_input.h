#pragma once

/*
 * Subset of Linux include/uapi/linux/input.h and input-event-codes.h
 * (x86_64 layout). Used by /dev/input/eventN — keep in sync with Linux ABI.
 */

#include <stdint.h>

#define EV_VERSION		0x010001

#define EV_SYN			0x00
#define EV_KEY			0x01
#define EV_REL			0x02
#define EV_ABS			0x03
#define EV_MSC			0x04
#define EV_SW			0x05
#define EV_LED			0x11
#define EV_REP			0x14
#define EV_MAX			0x1f
#define EV_CNT			(EV_MAX + 1)

#define SYN_REPORT		0
#define SYN_DROPPED		3

#define KEY_RESERVED		0
#define KEY_ESC			1
#define KEY_1			2
#define KEY_ENTER		28
#define KEY_LEFTCTRL		29
#define KEY_LEFTSHIFT		42
#define KEY_RIGHTSHIFT		54
#define KEY_LEFTALT		56
#define KEY_CAPSLOCK		58
#define KEY_F1			59
#define KEY_F10			68
#define KEY_F11			87
#define KEY_F12			88
#define KEY_KPENTER		96
#define KEY_RIGHTCTRL		97
#define KEY_KPSLASH		98
#define KEY_SYSRQ		99
#define KEY_RIGHTALT		100
#define KEY_HOME		102
#define KEY_UP			103
#define KEY_PAGEUP		104
#define KEY_LEFT		105
#define KEY_RIGHT		106
#define KEY_END			107
#define KEY_DOWN		108
#define KEY_PAGEDOWN		109
#define KEY_INSERT		110
#define KEY_DELETE		111
#define KEY_LEFTMETA		125
#define KEY_RIGHTMETA		126
#define KEY_COMPOSE		127
#define KEY_MAX			0x2ff
#define KEY_CNT			(KEY_MAX + 1)

#define BTN_LEFT		0x110
#define BTN_RIGHT		0x111
#define BTN_MIDDLE		0x112

#define REL_X			0x00
#define REL_Y			0x01
#define REL_WHEEL		0x08
#define REL_MAX			0x0f
#define REL_CNT			(REL_MAX + 1)

#define MSC_SCAN		0x04
#define MSC_MAX			0x07
#define MSC_CNT			(MSC_MAX + 1)

#define LED_NUML		0x00
#define LED_CAPSL		0x01
#define LED_SCROLLL		0x02
#define LED_MAX			0x0f
#define LED_CNT			(LED_MAX + 1)

#define REP_DELAY		0x00
#define REP_PERIOD		0x01
#define REP_MAX			0x01
#define REP_CNT			(REP_MAX + 1)

#define INPUT_PROP_POINTER	0x00
#define INPUT_PROP_MAX		0x1f
#define INPUT_PROP_CNT		(INPUT_PROP_MAX + 1)

#define BUS_I8042		0x11

struct input_id {
	uint16_t bustype;
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
};

/*
 * Linux kernel struct input_event on 64-bit: two unsigned longs then
 * type/code/value. Userspace timeval is the same 16 bytes.
 */
struct input_event {
	uint64_t input_event_sec;
	uint64_t input_event_usec;
	uint16_t type;
	uint16_t code;
	int32_t value;
};

_Static_assert(sizeof(struct input_event) == 24, "linux input_event ABI");

/* ioctl type 'E' — linux/input.h EVIOC* */
#define EVIOCGVERSION		0x80044501u
#define EVIOCGID		0x80084502u
#define EVIOCGREP		0x80084503u
#define EVIOCSREP		0x40084503u
#define EVIOCGRAB		0x40044590u
#define EVIOCREVOKE		0x40044591u
#define EVIOCSCLOCKID		0x400445a0u
