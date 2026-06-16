#include <stdarg.h>
#include <stdint.h>
#include <serial.h>
#include <debug.h>

#define QEMU_DEBUG_PORT 0x3f8

static uint8_t is_transmit_empty(void)
{
    return inb(QEMU_DEBUG_PORT + 5) & 0x20;
}

static void write_serial(char a)
{
    while (!is_transmit_empty())
        ;
    outb(QEMU_DEBUG_PORT, a);
}

static void print_num(int num)
{
    char buffer[12];
    int i = 0;
    int is_negative = 0;

    if (num == 0) {
        write_serial('0');
        return;
    }
    if (num < 0) {
        is_negative = 1;
        num = -num;
    }
    while (num != 0) {
        buffer[i++] = (num % 10) + '0';
        num /= 10;
    }
    if (is_negative)
        buffer[i++] = '-';
    while (i > 0)
        write_serial(buffer[--i]);
}

static void print_hex64(unsigned long long num, int uppercase)
{
    const char *hex = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    char buffer[32];
    int i = 0;

    if (num == 0) {
        write_serial('0');
        return;
    }
    while (num != 0) {
        buffer[i++] = hex[num & 0xF];
        num >>= 4;
    }
    while (i > 0)
        write_serial(buffer[--i]);
}

void qemu_debug_printf(const char *format, ...)
{
#ifdef QEMU_LOG_ENABLE
    va_list args;

    va_start(args, format);
    const char *p = format;

    while (*p) {
        if (*p != '%') {
            write_serial(*p++);
            continue;
        }
        p++;
        int left = 0, zero_pad = 0, alt = 0;

        while (*p == '-' || *p == '0' || *p == '#') {
            if (*p == '-')
                left = 1;
            if (*p == '0')
                zero_pad = 1;
            if (*p == '#')
                alt = 1;
            p++;
        }

        int width = 0;
        while (*p >= '0' && *p <= '9') {
            width = width * 10 + (*p - '0');
            p++;
        }

        int lmod = 0;
        while (*p == 'l') {
            lmod++;
            p++;
        }
        char spec = *p ? *p++ : 0;
        char buf[64];
        int len = 0;
        char pad_char = (zero_pad && !left) ? '0' : ' ';

        if (spec == 's') {
            char *str = va_arg(args, char *);
            int slen = 0;
            while (str[slen])
                slen++;
            int pad = width > slen ? width - slen : 0;
            if (!left)
                for (int i = 0; i < pad; i++)
                    write_serial(pad_char);
            for (int i = 0; i < slen; i++)
                write_serial(str[i]);
            if (left)
                for (int i = 0; i < pad; i++)
                    write_serial(' ');
        } else if (spec == 'p') {
            void *vp = va_arg(args, void *);
            unsigned long long v = (unsigned long long)(uintptr_t)vp;
            write_serial('0');
            write_serial('x');
            print_hex64(v, 0);
        } else if (spec == 'u' || spec == 'd' || spec == 'i' || spec == 'x' || spec == 'X') {
            int neg = 0;
            int uppercase = (spec == 'X');

            if (spec == 'd' || spec == 'i') {
                if (lmod >= 2) {
                    long long val = va_arg(args, long long);
                    unsigned long long uval;
                    if (val < 0) {
                        neg = 1;
                        uval = (unsigned long long)(-val);
                    } else {
                        uval = (unsigned long long)val;
                    }
                    if (uval == 0)
                        buf[len++] = '0';
                    else
                        for (unsigned long long tmp = uval; tmp; tmp /= 10)
                            buf[len++] = '0' + (tmp % 10);
                } else {
                    int val = va_arg(args, int);
                    unsigned int uval;
                    if (val < 0) {
                        neg = 1;
                        uval = (unsigned int)(-val);
                    } else {
                        uval = (unsigned int)val;
                    }
                    if (uval == 0)
                        buf[len++] = '0';
                    else
                        for (unsigned int tmp = uval; tmp; tmp /= 10)
                            buf[len++] = '0' + (tmp % 10);
                }
            } else if (spec == 'u') {
                if (lmod >= 2) {
                    unsigned long long val = va_arg(args, unsigned long long);
                    if (val == 0)
                        buf[len++] = '0';
                    else
                        for (unsigned long long tmp = val; tmp; tmp /= 10)
                            buf[len++] = '0' + (tmp % 10);
                } else {
                    unsigned int val = va_arg(args, unsigned int);
                    if (val == 0)
                        buf[len++] = '0';
                    else
                        for (unsigned int tmp = val; tmp; tmp /= 10)
                            buf[len++] = '0' + (tmp % 10);
                }
            } else {
                unsigned long long val = (lmod >= 2) ? va_arg(args, unsigned long long)
                                                     : va_arg(args, unsigned int);
                const char *hex = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
                if (val == 0)
                    buf[len++] = '0';
                else
                    for (unsigned long long tmp = val; tmp; tmp >>= 4)
                        buf[len++] = hex[tmp & 0xF];
            }

            int prefix = (spec == 'x' || spec == 'X') && alt ? 2 : 0;
            int total_len = len + prefix + neg;
            int pad = width > total_len ? width - total_len : 0;
            if (!left)
                for (int i = 0; i < pad; i++)
                    write_serial(pad_char);
            if (neg)
                write_serial('-');
            if (prefix) {
                write_serial('0');
                write_serial(uppercase ? 'X' : 'x');
            }
            for (int i = len - 1; i >= 0; i--)
                write_serial(buf[i]);
            if (left)
                for (int i = 0; i < pad; i++)
                    write_serial(' ');
        } else if (spec == 'c') {
            write_serial((char)va_arg(args, int));
        } else if (spec == '%') {
            write_serial('%');
        } else if (spec) {
            write_serial(spec);
        }
    }
    va_end(args);
#endif
}

void oom_serial_notify(unsigned long long syscall_num, const char *name)
{
    const char msg[] = "\r\n[OOM] syscall=";
    char buf[24];
    int n = 0;
    unsigned long long v = syscall_num;

    for (int i = 0; msg[i]; i++)
        write_serial(msg[i]);
    if (v == 0)
        buf[n++] = '0';
    else
        while (v) {
            buf[n++] = '0' + (v % 10);
            v /= 10;
        }
    while (n > 0)
        write_serial(buf[--n]);
    write_serial(' ');
    if (name) {
        for (int k = 0; name[k] && k < 32; k++)
            write_serial(name[k]);
    }
    write_serial('\r');
    write_serial('\n');
}
