/*
 * Kernel PRNG for x.509 key generation.
 *
 * Not an audited CSPRNG. It mixes coarse kernel entropy (TSC, PIT, RTC,
 * object addresses, stack pointer) through SHA-256 and runs a counter-mode
 * generator, which is adequate for key/cert generation in a hobby OS.
 */

#include <crypto_rand.h>
#include <sha256.h>
#include <pit.h>
#include <rtc.h>
#include <string.h>

static int g_rand_seeded = 0;
static uint8_t g_rand_state[SHA256_DIGEST_SIZE];
static uint64_t g_rand_counter = 0;

static uint64_t rand_rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void rand_seed_once(void) {
    if (g_rand_seeded)
        return;

    sha256_ctx_t c;
    uint8_t pool[256];
    size_t n = 0;

    for (int i = 0; i < 16; i++)
        pool[n++] = (uint8_t)rand_rdtsc();
    uint64_t t = rand_rdtsc();
    memcpy(pool + n, &t, sizeof(t)); n += sizeof(t);

    uint64_t ms = pit_get_time_ms();
    memcpy(pool + n, &ms, sizeof(ms)); n += sizeof(ms);

    rtc_datetime_t dt;
    rtc_read_datetime(&dt);
    memcpy(pool + n, &dt, sizeof(dt)); n += sizeof(dt);

    {
        static int local_dummy;
        uintptr_t a1 = (uintptr_t)&local_dummy;
        uintptr_t a2 = (uintptr_t)&g_rand_seeded;
        uintptr_t a3 = (uintptr_t)&rand_seed_once;
        uintptr_t sp;
        asm volatile("mov %%rsp, %0" : "=r"(sp));
        memcpy(pool + n, &a1, sizeof(a1)); n += sizeof(a1);
        memcpy(pool + n, &a2, sizeof(a2)); n += sizeof(a2);
        memcpy(pool + n, &a3, sizeof(a3)); n += sizeof(a3);
        memcpy(pool + n, &sp, sizeof(sp)); n += sizeof(sp);
    }

    sha256_init(&c);
    sha256_update(&c, pool, n);
    sha256_final(&c, g_rand_state);
    g_rand_counter = ms ^ t ^ rand_rdtsc();
    g_rand_seeded = 1;
}

void crypto_rand_bytes(void *buf, size_t len) {
    uint8_t *out = (uint8_t *)buf;
    size_t done = 0;

    rand_seed_once();

    while (done < len) {
        uint8_t block[SHA256_DIGEST_SIZE];
        sha256_ctx_t c;
        uint8_t ctr[8];
        for (int i = 0; i < 8; i++)
            ctr[i] = (uint8_t)(g_rand_counter >> (56 - i * 8));
        g_rand_counter++;

        sha256_init(&c);
        sha256_update(&c, g_rand_state, sizeof(g_rand_state));
        sha256_update(&c, ctr, sizeof(ctr));
        sha256_final(&c, block);

        size_t take = SHA256_DIGEST_SIZE;
        if (take > len - done) take = len - done;
        memcpy(out + done, block, take);
        done += take;

        /* Mix output back into state for forward secrecy between calls. */
        sha256_init(&c);
        sha256_update(&c, g_rand_state, sizeof(g_rand_state));
        sha256_update(&c, block, sizeof(block));
        sha256_final(&c, g_rand_state);
    }
}
