#include <apic_timer.h>
#include <vga.h>
#include <debug.h>
#include <vbe.h>
#include <klog.h>
#include <cirrusfb.h>
#include <apic.h>
#include <pit.h>
#include <thread.h>
#include <smp.h>
#include <power.h>
#include <loadavg.h>
#include <sysinfo.h>
#include <paging.h>
#include <syscall.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
/* common ticks */
extern volatile uint64_t timer_ticks;
extern volatile uint32_t timer_frequency;
extern int syscall_pipe_watch_active;

volatile uint64_t apic_timer_ticks = 0;
apic_timer_state_t apic_timer_state = {0};

// Timer divider values (encoded for APIC timer divider register)
static const uint8_t apic_dividers[] = {0x3, 0x0, 0x1, 0x2, 0x8, 0x9, 0xA, 0xB};
static const uint32_t divider_values[] = {16, 2, 4, 8, 32, 64, 128, 1};

/* Last programmed period (for refine rescale). */
static uint8_t g_timer_div_reg = 0x3;
static uint32_t g_timer_div_val = 16;
static uint32_t g_timer_init_count = 0;
static int g_tsc_deadline_mode;
static uint64_t g_tsc_deadline_interval;
static uint64_t g_tsc_deadline_next;

#define MSR_IA32_TSC_DEADLINE 0x6E0u

static uint64_t apic_rdtsc(void);

static void apic_wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);
    asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static int apic_has_tsc_deadline(void) {
    uint32_t a, b, c, d;
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1u), "c"(0u));
    (void)a; (void)b; (void)d;
    return (c & (1u << 24)) != 0;
}

static uint64_t apic_tsc_frequency_hz(void) {
    if (klog_tsc_hz >= 1000000ull)
        return klog_tsc_hz;
    uint64_t hint = sysinfo_tsc_hz_hint();
    if (hint >= 1000000ull)
        return hint;

    uint32_t max_leaf, b, c, d;
    asm volatile("cpuid" : "=a"(max_leaf), "=b"(b), "=c"(c), "=d"(d)
                 : "a"(0u), "c"(0u));
    if (max_leaf >= 0x15u) {
        uint32_t denom, numer, crystal;
        asm volatile("cpuid" : "=a"(denom), "=b"(numer), "=c"(crystal), "=d"(d)
                     : "a"(0x15u), "c"(0u));
        if (denom && numer && crystal)
            return ((uint64_t)crystal * (uint64_t)numer) / (uint64_t)denom;
    }
    if (max_leaf >= 0x16u) {
        uint32_t base_mhz;
        asm volatile("cpuid" : "=a"(base_mhz), "=b"(b), "=c"(c), "=d"(d)
                     : "a"(0x16u), "c"(0u));
        if (base_mhz)
            return (uint64_t)base_mhz * 1000000ull;
    }
    return 0;
}

static void apic_tsc_deadline_rearm(void) {
    if (!g_tsc_deadline_mode || !g_tsc_deadline_interval)
        return;
    uint64_t now = apic_rdtsc();
    uint64_t next = g_tsc_deadline_next + g_tsc_deadline_interval;
    if (next <= now)
        next = now + g_tsc_deadline_interval;
    g_tsc_deadline_next = next;
    apic_wrmsr(MSR_IA32_TSC_DEADLINE, next);
}

// Find best divider for target frequency
static uint8_t find_best_divider(uint32_t target_freq, uint32_t base_freq, uint32_t* out_count) {
    if (!target_freq || !base_freq || !out_count)
        return 0x3;
    /* Prefer divider 16 — same as calibration — then fall back. */
    static const int order[] = { 0, 1, 2, 3, 4, 5, 6, 7 }; /* indices into divider_values */
    for (unsigned oi = 0; oi < sizeof(order) / sizeof(order[0]); oi++) {
        int i = order[oi];
        uint32_t div = divider_values[i];
        uint64_t count = (uint64_t)base_freq / ((uint64_t)div * (uint64_t)target_freq);
        if (count >= 10ull && count <= 0xFFFFFull) {
            *out_count = (uint32_t)count;
            return apic_dividers[i];
        }
    }

    /* Fallback to divider 16 */
    uint64_t c = (uint64_t)base_freq / (16ull * (uint64_t)target_freq);
    if (c < 10ull) c = 10ull;
    if (c > 0xFFFFFull) c = 0xFFFFFull;
    *out_count = (uint32_t)c;
    return 0x3;
}

static uint32_t divider_val_for_reg(uint8_t reg) {
    for (int i = 0; i < 8; i++) {
        if (apic_dividers[i] == (reg & 0x0Fu))
            return divider_values[i];
    }
    return 16;
}

static uint64_t apic_rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* A missing PIT IRQ must degrade to PIT mode, never hang kernel bring-up. */
static int wait_pit_ticks_bounded(uint64_t start, uint64_t need, uint32_t sample_ms,
                                  uint64_t *delta_out) {
    uint64_t tsc_hz = sysinfo_tsc_hz_hint();
    uint64_t tsc_start = apic_rdtsc();
    uint64_t max_ms = (uint64_t)sample_ms * 4ull + 100ull;
    uint64_t max_cycles = tsc_hz ? (tsc_hz / 1000ull) * max_ms : 0;
    uint32_t spins = 0;
    const uint32_t max_spins = 10000000u;

    while ((pit_get_ticks() - start) < need) {
        if (max_cycles && apic_rdtsc() - tsc_start >= max_cycles)
            break;
        if (++spins >= max_spins)
            break;
        asm volatile("pause" ::: "memory");
    }
    uint64_t delta = pit_get_ticks() - start;
    if (delta_out) *delta_out = delta;
    return delta >= need ? 0 : -1;
}

/* Calibrate APIC timer base frequency against PIT ticks.
   This is far more stable across machines than CPUID/busy-loop heuristics. */
static uint32_t quick_calibrate(void) {
    const uint32_t divider = 16;
    const uint32_t sample_ms = sysinfo_is_hypervisor() ? 250u : 100u;
    uint32_t pit_hz = pit_frequency ? pit_frequency : 250u;
    /* Convert wall sample to PIT ticks — never treat ticks as milliseconds.
     * Old code waited N ticks but divided as if N were ms; at HZ=250 that
     * made base_hz ~4× too high and the periodic timer ~4× too slow. */
    uint64_t sample_ticks = ((uint64_t)pit_hz * (uint64_t)sample_ms + 999ull) / 1000ull;
    if (sample_ticks < 5ull)
        sample_ticks = 5ull;
    uint64_t pit_start = pit_get_ticks();

    /* One-shot, masked: we only read CURRENT counter and don't need interrupts. */
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, true);
    apic_write(LAPIC_TIMER_DIV_REG, 0x3); /* divider=16 */
    apic_write(LAPIC_TIMER_INIT_REG, 0xFFFFFFFFu);

    uint64_t rflags = 0;
    asm volatile("pushfq; popq %0" : "=r"(rflags));
    uint64_t pit_delta = 0;
    if (rflags & (1ull << 9))
        (void)wait_pit_ticks_bounded(pit_start, sample_ticks, sample_ms, &pit_delta);

    uint32_t remaining = apic_read(LAPIC_TIMER_CURRENT_REG);
    uint32_t elapsed = 0xFFFFFFFF - remaining;
    apic_write(LAPIC_TIMER_INIT_REG, 0);
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, true);

    if (pit_delta >= 5 && elapsed > 0) {
        /* base_hz = bus_counts * divider / seconds = counts * div * pit_hz / ticks */
        uint64_t base_hz = ((uint64_t)elapsed * (uint64_t)divider * (uint64_t)pit_hz) / pit_delta;
        if (base_hz >= 1000000ULL && base_hz <= 2000000000ULL) {
            kprintf("APIC: calibrated against PIT: elapsed=%u pit_delta=%llu (%ums) -> base=%u Hz\n",
                    elapsed, (unsigned long long)pit_delta, sample_ms, (unsigned)base_hz);
            return (uint32_t)base_hz;
        }
    }

    /* If PIT ticks are not advancing yet (e.g. before STI), use bounded busy-loop estimate. */
    if (pit_delta == 0) {
        apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, true);
        apic_write(LAPIC_TIMER_DIV_REG, 0x3);
        apic_write(LAPIC_TIMER_INIT_REG, 0xFFFFFFFFu);
        for (volatile uint32_t i = 0; i < 300000; i++) {
            asm volatile("pause");
        }
        uint32_t rem2 = apic_read(LAPIC_TIMER_CURRENT_REG);
        uint32_t el2 = 0xFFFFFFFFu - rem2;
        apic_write(LAPIC_TIMER_INIT_REG, 0);
        if (el2 > 0) {
            uint64_t base_hz = (uint64_t)el2 * (uint64_t)divider * 200ULL; /* ~5ms sample */
            if (base_hz >= 1000000ULL && base_hz <= 2000000000ULL) {
                kprintf("APIC: pre-STI calibration fallback: elapsed=%u -> base=%u Hz\n",
                        el2, (unsigned)base_hz);
                return (uint32_t)base_hz;
            }
        }
    }

    /* Last resort fallback: conservative default to avoid hangs/wild rates. */
    kprintf("APIC: calibration fallback (pit_delta=%llu elapsed=%u), using 100000000 Hz\n",
            (unsigned long long)pit_delta, elapsed);
    return 100000000u;
}

// Simple integer to string conversion
static void uint_to_str(uint64_t value, char* buffer) {
    if (value == 0) {
        buffer[0] = '0';
        buffer[1] = '\0';
        return;
    }

    char temp[20];
    int i = 0;

    while (value > 0) {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }

    for (int j = 0; j < i; j++) {
        buffer[j] = temp[i - j - 1];
    }
    buffer[i] = '\0';
}

// Simple string copy
static void str_copy(char* dest, const char* src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

// Format uptime into human readable string
void apic_timer_format_uptime(char* buffer, size_t buffer_size) {
    uint64_t seconds = apic_timer_get_uptime_seconds();

    if (seconds == 0) {
        str_copy(buffer, "00:00:00");
        return;
    }

    uint64_t days = seconds / (24 * 3600);
    uint64_t hours = (seconds % (24 * 3600)) / 3600;
    uint64_t minutes = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;

    char days_str[10];
    char hours_str[3];
    char minutes_str[3];
    char secs_str[3];

    // Format hours, minutes, seconds with leading zeros
    uint_to_str(hours, hours_str);
    uint_to_str(minutes, minutes_str);
    uint_to_str(secs, secs_str);

    // Ensure two digits
    if (hours < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = hours_str[0];
        temp[2] = '\0';
        str_copy(hours_str, temp);
    }

    if (minutes < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = minutes_str[0];
        temp[2] = '\0';
        str_copy(minutes_str, temp);
    }

    if (secs < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = secs_str[0];
        temp[2] = '\0';
        str_copy(secs_str, temp);
    }

    if (days > 0) {
        uint_to_str(days, days_str);
        // Format: Xd HH:MM:SS
        char* ptr = buffer;
        str_copy(ptr, days_str);
        ptr += strlen(days_str);
        *ptr++ = 'd';
        *ptr++ = ' ';
        str_copy(ptr, hours_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, minutes_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, secs_str);
    } else {
        // Format: HH:MM:SS
        char* ptr = buffer;
        str_copy(ptr, hours_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, minutes_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, secs_str);
    }
}

uint64_t apic_timer_get_uptime_seconds(void) {
    return apic_timer_get_time_ms() / 1000;
}

void apic_timer_handler(cpu_registers_t* regs) {
    apic_tsc_deadline_rearm();
    apic_timer_ticks++;
    apic_timer_state.ticks = apic_timer_ticks;
    if (!pit_is_enabled())
        timer_ticks++;
    /*
     * Early clockevent mode: calibration starts before thread_init(). Linux
     * likewise keeps the early timer handler to accounting + EOI; scheduler,
     * process timers and framebuffer work become legal only after init=1.
     */
    if (!init) {
        apic_eoi();
        return;
    }
    /* Charge CPU time before any schedule/publish side effects. */
    thread_account_timer_tick(regs && ((regs->cs & 3) == 3));
    process_itimer_tick(pit_get_time_ms());
    if (smp_sched_cpu_id() == 0)
        syscall_net_l2_irq_poll();
    /* Safety net for rare deferred CLONE_THREAD wakes; normal fork wakes earlier. */
    int published_fork_child = 0;
    if (regs && ((regs->cs & 3) == 3))
        published_fork_child = syscall_publish_deferred_fork_child();
    /* Wall-second loadavg update (modulo ticks skips seconds when IRQs coalesce). */
    if (init && smp_sched_cpu_id() == 0) {
        static uint64_t loadavg_last_ms;
        uint64_t now_ms = pit_get_time_ms();
        if (now_ms - loadavg_last_ms >= 1000ull) {
            loadavg_last_ms = now_ms;
            loadavg_second_tick();
        }
    }

    /* Ensure ACPI/power requests progress even when system is otherwise idle at a prompt. */
    if (power_is_pending() && (!regs || ((regs->cs & 3) == 0))) {
        power_poll();
    }

    thread_wake_expired_timeouts();
    if (apic_timer_state.frequency > 0) {
        uint32_t resched_quantum = apic_timer_state.frequency / 100u;
        if (resched_quantum < 1u)
            resched_quantum = 1u;
        if ((apic_timer_ticks % resched_quantum) == 0)
            thread_request_resched();
    }

    /*
     * Bounded post-pipe sampler. Keep this deliberately tiny: it is diagnostic
     * evidence, not part of scheduling, and must not recreate the old IRQ-log
     * livelock. It can be removed once pipeline bring-up is complete.
     */
    if (regs && ((regs->cs & 3) == 3) && syscall_pipe_watch_active &&
        apic_timer_state.frequency > 0) {
        uint32_t sample_every = apic_timer_state.frequency / 16u;
        if (sample_every < 1u)
            sample_every = 1u;
        if ((apic_timer_ticks % sample_every) == 0) {
            static int samples_left = 16;
            if (samples_left-- > 0) {
                thread_t *cur = thread_current();
                devel_printf("pipe-sample: tid=%d rip=0x%llx rsp=0x%llx "
                        "rax=0x%llx rdx=0x%llx state=%d cr3=0x%llx\n",
                        cur ? (int)(cur->tid ? cur->tid : 1) : -1,
                        (unsigned long long)regs->rip,
                        (unsigned long long)regs->rsp,
                        (unsigned long long)regs->rax,
                        (unsigned long long)regs->rdx,
                        cur ? (int)cur->state : -1,
                        (unsigned long long)paging_read_cr3());
            }
        }
    }

    /*
     * UP needs timer preemption for a ring-3 CPU spinner.  PIT already uses
     * this path; omitting it after PIT is disabled lets a post-fork child
     * starve its parent forever (the shell cannot regain the tty or handle
     * Ctrl-C).  Acknowledge the local APIC before a possible context switch,
     * because this handler may resume only when this task is scheduled again.
     * SMP remains cooperative until syscall entry/scheduler state is per-CPU.
     */
    /*
     * All ring-3 tasks are intentionally pinned to the BSP until syscall
     * entry is per-CPU.  A VM may still expose several vCPUs; using the total
     * CPU count here disabled preemption on cpu0 and let one shell freeze all
     * user terminals.  Preempt the BSP's ring-3 task regardless of AP count.
     */
    /* Cursor and deferred framebuffer damage must progress while ring 3 runs. */
    if (smp_sched_cpu_id() == 0) {
        if (cirrusfb_is_ready()) {
            cirrusfb_update_cursor();
        } else if (vbe_is_available()) {
            vbefb_update_cursor();
        } else {
            vga_update_cursor();
        }
    }

    if (regs && ((regs->cs & 3) == 3) && smp_sched_cpu_id() == 0) {
        apic_eoi();
        /*
         * After wake_up_new_task from this IRQ, run the child on this tick.
         * Skipping preempt here used to leave the child READY until the next
         * quantum — with slow console SYNC that looked like a 1s post-fork stall.
         */
        if (published_fork_child) {
            thread_ring3_preempt_if_waiters();
            return;
        }
        /*
         * Linux-style scheduling granularity: account every timer tick, but
         * do not context-switch on every IRQ. Under VMware a switch can take
         * longer than a 1 kHz period; the next LAPIC interrupt is then already
         * pending at iretq and two runnable tasks livelock in IRQ frames
         * without retiring a single user instruction.
         *
         * Keep timer accounting at 250 Hz, but force scheduling around 100 Hz
         * (~10 ms). /64 (~4 Hz) felt multi-second under load with console I/O.
         * Still far below 1 kHz to avoid the VMware IRQ livelock.
         */
        uint32_t quantum = apic_timer_state.frequency / 100u;
        if (quantum < 1u)
            quantum = 1u;
        if ((apic_timer_ticks % quantum) == 0)
            thread_ring3_preempt_if_waiters();
        return;
    }

    /* Kernel-mode/AP timer ticks do not schedule from IRQ context. */
    apic_eoi();
}

void apic_timer_init(void) {
    // Initialize state
    apic_timer_ticks = 0;
    apic_timer_state.ticks = 0;
    apic_timer_state.frequency = 0;
    apic_timer_state.running = false;
    apic_timer_state.calibrated = false;
    apic_timer_state.mode = APIC_TIMER_PERIODIC;

    // Perform quick calibration
    apic_timer_state.base_frequency = quick_calibrate();
    apic_timer_state.calibration_value = apic_timer_state.base_frequency / 100;
    apic_timer_state.calibrated = true;

    // Stop timer initially
    apic_timer_stop();

    klogprintf("APIC: Ready (base freq: %u Hz)\n", apic_timer_state.base_frequency);
}

void apic_timer_start(uint32_t freq_hz) {
    if (!apic_timer_state.calibrated) {
        klogprintf("APIC: Not calibrated, cannot start\n");
        return;
    }

    if (apic_timer_state.running) {
        apic_timer_stop();
    }

    if (freq_hz == 0)
        freq_hz = 250u;

    uint32_t count = 0;
    uint8_t divider = find_best_divider(freq_hz, apic_timer_state.base_frequency, &count);

    uint64_t deadline_tsc_hz = apic_tsc_frequency_hz();
    if (apic_has_tsc_deadline() && deadline_tsc_hz >= 1000000ull) {
        uint64_t interval = deadline_tsc_hz / (uint64_t)freq_hz;
        if (interval > 0) {
            g_tsc_deadline_mode = 1;
            g_tsc_deadline_interval = interval;
            g_tsc_deadline_next = apic_rdtsc() + interval;
            g_timer_init_count = 1;
            apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_TSC_DEADLINE, false);
            apic_wrmsr(MSR_IA32_TSC_DEADLINE, g_tsc_deadline_next);
            apic_timer_state.frequency = freq_hz;
            apic_timer_state.running = true;
            apic_timer_state.mode = APIC_TIMER_TSC_DEADLINE;
            apic_timer_ticks = 0;
            kprintf("APIC: TSC-deadline clockevent at %u Hz (TSC=%llu Hz)\n",
                    freq_hz, (unsigned long long)deadline_tsc_hz);
            return;
        }
    }

    if (count < 10) count = 10;
    if (count > 0xFFFFF) count = 0xFFFFF;

    kprintf("APIC: Starting at %u Hz (div=%u count=%u base=%u)\n",
            freq_hz, divider_val_for_reg(divider), count,
            apic_timer_state.base_frequency);

    apic_write(LAPIC_TIMER_DIV_REG, divider);
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_PERIODIC, false);
    apic_write(LAPIC_TIMER_INIT_REG, count);

    g_timer_div_reg = divider;
    g_timer_div_val = divider_val_for_reg(divider);
    g_timer_init_count = count;

    apic_timer_state.frequency = freq_hz;
    if (!pit_is_enabled())
        timer_frequency = freq_hz;
    apic_timer_state.running = true;
    apic_timer_state.mode = APIC_TIMER_PERIODIC;
    apic_timer_ticks = 0;
}

/*
 * Measure IRQ rate over ~sample_ms and rescale initial-count toward target_hz.
 * Uses PIT while enabled (elapsed from actual PIT ticks — not the nominal ms),
 * else TSC. Returns measured Hz *before* rescale.
 */
uint32_t apic_timer_refine(uint32_t target_hz, uint32_t sample_ms) {
    if (!apic_timer_state.running || !g_timer_init_count || target_hz == 0)
        return apic_timer_state.frequency;
    if (sample_ms < 50u)
        sample_ms = 50u;
    if (sample_ms > 1000u)
        sample_ms = 1000u;

    uint64_t t0 = apic_timer_ticks;
    uint64_t elapsed_us = 0;

    if (pit_is_enabled()) {
        uint32_t pit_hz = pit_frequency ? pit_frequency : 250u;
        uint64_t need = ((uint64_t)pit_hz * (uint64_t)sample_ms + 999ull) / 1000ull;
        if (need < 5ull)
            need = 5ull;
        uint64_t p0 = pit_get_ticks();
        uint64_t got = 0;
        if (wait_pit_ticks_bounded(p0, need, sample_ms, &got) != 0) {
            kprintf("APIC: PIT reference timeout during refine\n");
            return 0;
        }
        /* Exact wall time from ticks we actually waited (avoids ceil bias → slow timer). */
        elapsed_us = (got * 1000000ull) / (uint64_t)pit_hz;
    } else if (klog_tsc_per_us) {
        uint64_t wall0 = time_monotonic_us();
        uint64_t deadline = wall0 + (uint64_t)sample_ms * 1000ull;
        while (time_monotonic_us() < deadline)
            asm volatile("pause" ::: "memory");
        elapsed_us = time_monotonic_us() - wall0;
    } else {
        return 0;
    }

    uint64_t irq_delta = apic_timer_ticks - t0;
    if (irq_delta < 2ull || elapsed_us < 1000ull)
        return 0;

    uint64_t measured_hz = (irq_delta * 1000000ull) / elapsed_us;
    if (measured_hz < 10ull || measured_hz > 10000ull) {
        kprintf("APIC: refine rejected measured=%llu Hz\n",
                (unsigned long long)measured_hz);
        return apic_timer_state.frequency;
    }
    /* TSC-deadline is derived directly from the calibrated clocksource. */
    if (g_tsc_deadline_mode)
        return (uint32_t)measured_hz;

    /*
     * count_new = count_old * measured / target
     * Slow timer (measured < target) → smaller count → faster IRQs.
     */
    uint64_t new_count = ((uint64_t)g_timer_init_count * measured_hz + (target_hz / 2u)) /
                         (uint64_t)target_hz;
    if (new_count < 10ull)
        new_count = 10ull;
    if (new_count > 0xFFFFFull)
        new_count = 0xFFFFFull;

    kprintf("APIC: refine target=%u measured=%llu Hz count %u -> %u\n",
            target_hz, (unsigned long long)measured_hz,
            g_timer_init_count, (unsigned)new_count);

    if ((uint32_t)new_count != g_timer_init_count) {
        g_timer_init_count = (uint32_t)new_count;
        apic_write(LAPIC_TIMER_DIV_REG, g_timer_div_reg);
        apic_write(LAPIC_TIMER_INIT_REG, g_timer_init_count);
        apic_timer_ticks = 0;
    }

    if (g_timer_div_val)
        apic_timer_state.base_frequency =
            (uint32_t)(((uint64_t)g_timer_init_count * (uint64_t)g_timer_div_val) *
                       (uint64_t)target_hz);

    return (uint32_t)measured_hz;
}

/* Measure only — publish the real IRQ rate as the time base. */
uint32_t apic_timer_commit_measured(uint32_t sample_ms) {
    if (!apic_timer_state.running)
        return apic_timer_state.frequency;
    if (sample_ms < 50u)
        sample_ms = 50u;

    uint64_t t0 = apic_timer_ticks;
    uint64_t elapsed_us = 0;

    if (pit_is_enabled()) {
        uint32_t pit_hz = pit_frequency ? pit_frequency : 250u;
        uint64_t need = ((uint64_t)pit_hz * (uint64_t)sample_ms + 999ull) / 1000ull;
        if (need < 5ull)
            need = 5ull;
        uint64_t p0 = pit_get_ticks();
        uint64_t got = 0;
        if (wait_pit_ticks_bounded(p0, need, sample_ms, &got) != 0) {
            kprintf("APIC: PIT reference timeout during commit\n");
            return 0;
        }
        elapsed_us = (got * 1000000ull) / (uint64_t)pit_hz;
    } else if (klog_tsc_per_us) {
        uint64_t wall0 = time_monotonic_us();
        uint64_t deadline = wall0 + (uint64_t)sample_ms * 1000ull;
        while (time_monotonic_us() < deadline)
            asm volatile("pause" ::: "memory");
        elapsed_us = time_monotonic_us() - wall0;
    } else {
        return 0;
    }

    uint64_t irq_delta = apic_timer_ticks - t0;
    if (irq_delta < 2ull || elapsed_us < 1000ull)
        return 0;

    uint64_t measured_hz = (irq_delta * 1000000ull) / elapsed_us;
    if (measured_hz < 10ull || measured_hz > 10000ull)
        return apic_timer_state.frequency;
    if (g_tsc_deadline_mode)
        return (uint32_t)measured_hz;

    apic_timer_state.frequency = (uint32_t)measured_hz;
    if (!pit_is_enabled())
        timer_frequency = (uint32_t)measured_hz;

    kprintf("APIC: committed time base %u Hz (measured)\n",
            (unsigned)measured_hz);
    return (uint32_t)measured_hz;
}

void apic_timer_start_oneshot(uint32_t microseconds) {
    if (!apic_timer_state.calibrated) return;

    if (g_tsc_deadline_mode) {
        apic_wrmsr(MSR_IA32_TSC_DEADLINE, 0);
        g_tsc_deadline_mode = 0;
    }

    uint32_t count = (apic_timer_state.base_frequency * microseconds) / 1000000;
    if (count < 10) count = 10;

    apic_write(LAPIC_TIMER_DIV_REG, 0x3); // Divider 16
    apic_write(LAPIC_TIMER_INIT_REG, count);
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, false);

    apic_timer_state.running = true;
    apic_timer_state.mode = APIC_TIMER_ONESHOT;
}

void apic_timer_stop(void) {
    if (g_tsc_deadline_mode)
        apic_wrmsr(MSR_IA32_TSC_DEADLINE, 0);
    g_tsc_deadline_mode = 0;
    g_tsc_deadline_interval = 0;
    g_tsc_deadline_next = 0;
    apic_set_lvt_timer(0, 0, true); // Mask timer
    apic_write(LAPIC_TIMER_INIT_REG, 0); // Stop counter
    apic_timer_state.running = false;
    apic_timer_state.frequency = 0; /* no time base while stopped (avoids stale Hz after PIT fallback) */
}

void apic_timer_set_frequency(uint32_t freq_hz) {
    if (apic_timer_state.running) {
        apic_timer_start(freq_hz);
    } else {
        apic_timer_state.frequency = freq_hz;
    }
}

uint64_t apic_timer_get_ticks(void) {
    return apic_timer_ticks;
}

uint64_t apic_timer_get_time_ms(void) {
    if (apic_timer_state.frequency == 0) return 0;
    return (apic_timer_ticks * 1000) / apic_timer_state.frequency;
}

uint64_t apic_timer_get_time_us(void) {
    if (apic_timer_state.frequency == 0) return 0;
    return (apic_timer_ticks * 1000000) / apic_timer_state.frequency;
}

uint32_t apic_timer_get_frequency(void) {
    return apic_timer_state.frequency;
}

bool apic_timer_is_running(void) {
    return apic_timer_state.running;
}

bool apic_timer_is_calibrated(void) {
    return apic_timer_state.calibrated;
}

bool apic_timer_uses_tsc_deadline(void) {
    return g_tsc_deadline_mode != 0;
}

void apic_timer_sleep_ms(uint32_t ms) {
    if (!apic_timer_state.running) {
        pit_sleep_ms(ms);
        return;
    }

    uint64_t target_ticks = apic_timer_ticks + (ms * apic_timer_state.frequency) / 1000;
    while (apic_timer_ticks < target_ticks) {
        asm volatile("pause");
    }
}

void apic_timer_sleep_us(uint32_t us) {
    if (!apic_timer_state.running) {
        // Busy wait fallback
        for (volatile uint32_t i = 0; i < us; i++) {
            asm volatile("pause");
        }
        return;
    }

    uint64_t target_ticks = apic_timer_ticks + (us * apic_timer_state.frequency) / 1000000;
    while (apic_timer_ticks < target_ticks) {
        asm volatile("pause");
    }
}

void apic_timer_calibrate(void) {
    apic_timer_state.base_frequency = quick_calibrate();
    apic_timer_state.calibration_value = apic_timer_state.base_frequency / 100;
    apic_timer_state.calibrated = true;
}