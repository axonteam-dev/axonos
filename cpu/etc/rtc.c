/*
 * RTC driver
 * Author: kotazz
*/

#include <rtc.h>
#include <serial.h>
#include <pic.h>
#include <klog.h>
#include <debug.h>
#include <spinlock.h>

// Глобальный счетчик тиков RTC
volatile uint64_t rtc_ticks = 0;
static spinlock_t rtc_cmos_lock;

/* Index port bit7 disables NMI for the access (Linux CMOS). */
static uint8_t rtc_read_register(uint8_t reg) {
    outb(RTC_COMMAND_PORT, (uint8_t)(reg | 0x80u));
    return inb(RTC_DATA_PORT);
}

static void rtc_write_register(uint8_t reg, uint8_t value) {
    outb(RTC_COMMAND_PORT, (uint8_t)(reg | 0x80u));
    outb(RTC_DATA_PORT, value);
}

static int is_update_in_progress(void) {
    return (rtc_read_register(RTC_REG_STATUS_A) & 0x80) != 0;
}

// Конвертация из BCD в бинарный формат
static uint8_t bcd_to_binary(uint8_t bcd) {
    return (bcd & 0x0F) + ((bcd >> 4) * 10);
}

void rtc_read_datetime(rtc_datetime_t* dt) {
    unsigned long irqf;
    int i;
    uint8_t reg_b;

    if (!dt)
        return;
    /* Linux rtc_cmos: never spin forever on UIP (0xFF CMOS looks like UIP). */
    acquire_irqsave(&rtc_cmos_lock, &irqf);
    for (i = 0; i < 10000; i++) {
        if (!is_update_in_progress())
            break;
        asm volatile("pause" ::: "memory");
    }

    dt->second = rtc_read_register(RTC_REG_SECONDS);
    dt->minute = rtc_read_register(RTC_REG_MINUTES);
    dt->hour = rtc_read_register(RTC_REG_HOURS);
    dt->day = rtc_read_register(RTC_REG_DAY);
    dt->month = rtc_read_register(RTC_REG_MONTH);
    dt->year = rtc_read_register(RTC_REG_YEAR);
    reg_b = rtc_read_register(RTC_REG_STATUS_B);

    if (!(reg_b & 0x04)) {
        dt->second = bcd_to_binary(dt->second);
        dt->minute = bcd_to_binary(dt->minute);
        dt->hour = bcd_to_binary(dt->hour);
        dt->day = bcd_to_binary(dt->day);
        dt->month = bcd_to_binary(dt->month);
        dt->year = bcd_to_binary(dt->year);
    }
    if (!(reg_b & 0x02) && (dt->hour & 0x80))
        dt->hour = (uint8_t)(((dt->hour & 0x7Fu) + 12u) % 24u);

    dt->year = (uint16_t)(dt->year + 2000);
    if (dt->month < 1 || dt->month > 12 || dt->day < 1 || dt->day > 31 ||
        dt->hour > 23 || dt->minute > 59 || dt->second > 59) {
        dt->second = 0;
        dt->minute = 0;
        dt->hour = 0;
        dt->day = 1;
        dt->month = 1;
        dt->year = 2026;
    }
    release_irqrestore(&rtc_cmos_lock, irqf);
}

// Обработчик прерывания от RTC (IRQ 8)
void rtc_handler(cpu_registers_t* regs) {
    (void)regs; // Неиспользуемый параметр

    rtc_ticks++;

    // ВАЖНО: Прочитать регистр C, чтобы разрешить следующее прерывание
    outb(RTC_COMMAND_PORT, RTC_REG_STATUS_C);
    inb(RTC_DATA_PORT);

    // Отправляем EOI (End of Interrupt) контроллеру прерываний
    // IRQ 8 находится на ведомом (slave) PIC
    pic_send_eoi(8);
}

// Инициализация RTC
void rtc_init() {
    klogprintf("RTC driver for AxonOS by kotazz\n");
    // Отключаем прерывания на время настройки
    asm volatile("cli");

    // Выбираем регистр B и отключаем NMI
    outb(RTC_COMMAND_PORT, 0x8B);
    uint8_t prev = inb(RTC_DATA_PORT); // Читаем текущее значение

    // Устанавливаем бит 6 (PIE - Periodic Interrupt Enable)
    outb(RTC_COMMAND_PORT, 0x8B);
    outb(RTC_DATA_PORT, prev | 0x40);

    // Устанавливаем частоту прерываний
    // Частота = 32768 >> (rate - 1)
    // rate 15 -> 2 Hz
    // rate 6 -> 1024 Hz
    uint8_t rate = 15; // 2 Гц, хорошая частота для начала
    rate &= 0x0F;

    outb(RTC_COMMAND_PORT, 0x8A);
    prev = inb(RTC_DATA_PORT);
    outb(RTC_COMMAND_PORT, 0x8A);
    outb(RTC_DATA_PORT, (prev & 0xF0) | rate);

    // Размаскируем IRQ 8 на PIC
    pic_unmask_irq(8);

    // Разрешаем прерывания
    asm volatile("sti");

    klogprintf("RTC: initialized with 2 Hz periodic interrupt.\n");
}
