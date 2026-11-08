#include <mouse.h>

#include <devfs.h>
#include <debug.h>
#include <idt.h>
#include <pic.h>
#include <stdio.h>
#include <serial.h>
#include <spinlock.h>
#include <sysfs.h>
#include <thread.h>
#include <input_evdev.h>
#include <keyboard.h>

#define PS2_CMD_PORT 0x64
#define PS2_DATA_PORT 0x60

/* Byte ring exposed via /dev/input/mice */
static uint8_t g_mouse_rb[4096];
static int g_mouse_head = 0;
static int g_mouse_tail = 0;
static int g_mouse_count = 0;
static spinlock_t g_mouse_lock = { 0 };

/* Packet assembler for IRQ stream */
static uint8_t g_pkt[3];
static int g_pkt_idx = 0;

static int g_mouse_sysfs_registered = 0;
static int g_ps2_aux_live = 0;
static unsigned int g_mouse_init_state = 0; /* 0 pending, 1 ready, 2 failed */
static unsigned int g_mouse_irq_count = 0;
static unsigned int g_mouse_aux_bytes = 0;

int ps2_aux_is_live(void) {
    return g_ps2_aux_live;
}

static int ps2_wait_input_empty(void) {
    for (int i = 0; i < 100000; i++) {
        if ((inb(PS2_CMD_PORT) & 0x02) == 0) return 1;
        if ((i & 15) == 0)
            outb(0x80, 0);
        asm volatile("pause" ::: "memory");
    }
    return 0;
}

static int ps2_wait_output_full(void) {
    for (int i = 0; i < 100000; i++) {
        if (inb(PS2_CMD_PORT) & 0x01) return 1;
        if ((i & 15) == 0)
            outb(0x80, 0);
        asm volatile("pause" ::: "memory");
    }
    return 0;
}

static void ps2_flush_output(void) {
    for (int i = 0; i < 64; i++) {
        if ((inb(PS2_CMD_PORT) & 0x01u) == 0) break;
        (void)inb(PS2_DATA_PORT);
    }
}

static int ps2_mouse_write(uint8_t v) {
    if (!ps2_wait_input_empty()) return -1;
    outb(PS2_CMD_PORT, 0xD4);
    if (!ps2_wait_input_empty()) return -1;
    outb(PS2_DATA_PORT, v);
    return 0;
}

static int ps2_mouse_send_ack(uint8_t byte) {
    for (int attempt = 0; attempt < 3; attempt++) {
        if (ps2_mouse_write(byte) != 0) return -1;
        /* Keyboard data may precede the AUX response in the shared buffer. */
        for (int i = 0; i < 64; i++) {
            if (!ps2_wait_output_full()) return -1;
            uint8_t status = inb(PS2_CMD_PORT);
            uint8_t data = inb(PS2_DATA_PORT);
            if (!(status & 0x20u)) {
                keyboard_process_scancode(data);
                continue;
            }
            if (data == 0xFA) return 0;
            if (data == 0xFE) break;
            return -1;
        }
    }
    return -1;
}

static void mouse_stream_push(uint8_t b) {
    unsigned long irqf;
    acquire_irqsave(&g_mouse_lock, &irqf);
    if (g_mouse_count < (int)sizeof(g_mouse_rb)) {
        g_mouse_rb[g_mouse_tail] = b;
        g_mouse_tail = (g_mouse_tail + 1) % (int)sizeof(g_mouse_rb);
        g_mouse_count++;
    }
    release_irqrestore(&g_mouse_lock, irqf);
}

void mouse_process_byte(uint8_t b) {
    __atomic_fetch_add(&g_mouse_aux_bytes, 1, __ATOMIC_RELAXED);
    if (g_pkt_idx == 0 && (b & 0x08u) == 0) {
        /* Out-of-sync: first byte always has bit3=1 for PS/2 packet. */
        return;
    }
    g_pkt[g_pkt_idx++] = b;
    if (g_pkt_idx >= 3) {
        mouse_stream_push(g_pkt[0]);
        mouse_stream_push(g_pkt[1]);
        mouse_stream_push(g_pkt[2]);
        evdev_ps2_mouse_packet(g_pkt);
        g_pkt_idx = 0;
    }
}

static void mouse_irq_handler(cpu_registers_t *regs) {
    /* Both IRQs share one controller output buffer, including its status.
     * Use the same lock and status-based routing as IRQ1 and the paint poll. */
    __atomic_fetch_add(&g_mouse_irq_count, 1, __ATOMIC_RELAXED);
    keyboard_handler(regs);
}

int mouse_stream_available(void) {
    int n;
    unsigned long irqf;
    acquire_irqsave(&g_mouse_lock, &irqf);
    n = g_mouse_count;
    release_irqrestore(&g_mouse_lock, irqf);
    return n;
}

ssize_t mouse_read_stream(void *buf, size_t size) {
    if (!buf) return -1;
    if (size == 0) return 0;
    uint8_t *out = (uint8_t*)buf;
    size_t got = 0;

    /* Block until at least one byte, then drain available bytes. */
    while (got == 0) {
        unsigned long irqf;
        acquire_irqsave(&g_mouse_lock, &irqf);
        while (got < size && g_mouse_count > 0) {
            out[got++] = g_mouse_rb[g_mouse_head];
            g_mouse_head = (g_mouse_head + 1) % (int)sizeof(g_mouse_rb);
            g_mouse_count--;
        }
        release_irqrestore(&g_mouse_lock, irqf);
        if (got > 0) break;
        thread_sleep(1);
    }
    return (ssize_t)got;
}

static ssize_t mouse_sysfs_show_text(char *buf, size_t size, void *priv) {
    const char *s = (const char*)priv;
    if (!buf || size == 0) return 0;
    if (!s) s = "";
    size_t n = 0;
    while (s[n] && n < size) { buf[n] = s[n]; n++; }
    if (n < size) buf[n++] = '\n';
    return (ssize_t)n;
}

static ssize_t mouse_sysfs_show_pending(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    return (ssize_t)snprintf(buf, size, "%d\n", mouse_stream_available());
}

static ssize_t mouse_sysfs_show_counter(char *buf, size_t size, void *priv) {
    if (!buf || size == 0) return 0;
    return (ssize_t)snprintf(buf, size, "%u\n",
        __atomic_load_n((unsigned int *)priv, __ATOMIC_RELAXED));
}

static void mouse_register_sysfs(void) {
    if (g_mouse_sysfs_registered) return;
    if (sysfs_mkdir("/sys/class") != 0) return;
    if (sysfs_mkdir("/sys/class/input") != 0) return;
    if (sysfs_mkdir("/sys/class/input/mouse0") != 0) return;
    struct sysfs_attr attr_name = { mouse_sysfs_show_text, NULL, (void*)"PS/2 mouse" };
    struct sysfs_attr attr_driver = { mouse_sysfs_show_text, NULL, (void*)"ps2-mouse" };
    struct sysfs_attr attr_pending = { mouse_sysfs_show_pending, NULL, NULL };
    struct sysfs_attr attr_init = { mouse_sysfs_show_counter, NULL, &g_mouse_init_state };
    struct sysfs_attr attr_irq = { mouse_sysfs_show_counter, NULL, &g_mouse_irq_count };
    struct sysfs_attr attr_aux = { mouse_sysfs_show_counter, NULL, &g_mouse_aux_bytes };
    if (sysfs_create_file("/sys/class/input/mouse0/name", &attr_name) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/driver", &attr_driver) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/pending_bytes", &attr_pending) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/init_state", &attr_init) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/irq12_count", &attr_irq) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/aux_bytes", &attr_aux) != 0) return;
    g_mouse_sysfs_registered = 1;
}

void mouse_publish_sysfs(void) {
    mouse_register_sysfs();
}

void ps2_mouse_init(void) {
    uint8_t test = 0xFF;

    idt_set_handler(44, mouse_irq_handler); /* IRQ12 */

    /* Probe AUX with bounded waits. Blind 0xA8+0xD4 on a laptop without a
     * second port wedges i8042 (hang after "List of block devices"). */
    pic_mask_irq(1);
    pic_mask_irq(12);
    ps2_flush_output();
    if (!ps2_wait_input_empty()) {
        goto failed;
    }
    outb(PS2_CMD_PORT, 0xA8); /* enable aux so 0xA9 is meaningful */
    if (!ps2_wait_input_empty()) {
        goto failed;
    }
    outb(PS2_CMD_PORT, 0xA9); /* test second port */
    if (!ps2_wait_output_full()) {
        goto failed;
    }
    test = inb(PS2_DATA_PORT);
    if (test != 0x00) {
        goto failed;
    }

    ps2_flush_output();
    if (!ps2_wait_input_empty()) goto failed;
    outb(PS2_CMD_PORT, 0xA8); /* enable aux port */
    if (!ps2_wait_input_empty()) goto failed;
    outb(PS2_CMD_PORT, 0x20); /* read command byte */
    if (!ps2_wait_output_full()) goto failed;
    uint8_t cmd = inb(PS2_DATA_PORT);
    cmd |= 0x03u;              /* force IRQ1 + IRQ12 enabled */
    cmd &= (uint8_t)~0x30u;    /* clear disable keyboard/mouse clocks */
    cmd |= 0x40u;              /* keep translation on for set1 keyboard path */
    if (!ps2_wait_input_empty()) goto failed;
    outb(PS2_CMD_PORT, 0x60);
    if (!ps2_wait_input_empty()) goto failed;
    outb(PS2_DATA_PORT, cmd);
    ps2_flush_output();

    if (ps2_mouse_send_ack(0xF6) != 0 || ps2_mouse_send_ack(0xF4) != 0)
        goto failed;

    g_ps2_aux_live = 1;
    __atomic_store_n(&g_mouse_init_state, 1, __ATOMIC_RELAXED);
    pic_unmask_irq(1);
    pic_unmask_irq(12);

    goto publish;
failed:
    __atomic_store_n(&g_mouse_init_state, 2, __ATOMIC_RELAXED);
    qemu_debug_printf("ps2_mouse_init: AUX setup failed\n");
    pic_unmask_irq(1);
publish:
    (void)devfs_create_char_node("/dev/input/mice", NULL);
    mouse_register_sysfs();
}
