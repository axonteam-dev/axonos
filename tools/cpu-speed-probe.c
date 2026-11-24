/* Identical fixed-work pthread benchmark for a Linux host and AxonOS guest.
 * Usage: cpu-speed-probe [workers [iterations-per-worker]]
 * Reports observations, not a proof of SMP correctness or CPU coverage. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define MAX_WORKERS 256
#define DEFAULT_ITERATIONS 30000000ULL

struct worker {
    uint64_t iterations, result;
    int cpu_start, cpu_end;
};

static atomic_int gate;

static uint64_t compute(uint64_t n)
{
    uint64_t x = UINT64_C(0x123456789abcdef0);
    for (uint64_t i = 0; i < n; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x *= UINT64_C(0x2545f4914f6cdd1d);
    }
    return x;
}

static void *run_worker(void *arg)
{
    struct worker *w = arg;
    while (atomic_load_explicit(&gate, memory_order_acquire) == 0)
        sched_yield();
    if (atomic_load_explicit(&gate, memory_order_relaxed) < 0)
        return NULL;
    w->cpu_start = sched_getcpu();
    w->result = compute(w->iterations);
    w->cpu_end = sched_getcpu();
    return NULL;
}

static int now(double *t)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    *t = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
    return 0;
}

static int run(unsigned count, uint64_t iterations, uint64_t expected, double *seconds)
{
    pthread_t threads[MAX_WORKERS];
    struct worker workers[MAX_WORKERS];
    unsigned created = 0;
    double start, end;
    atomic_store(&gate, 0);
    for (; created < count; created++) {
        workers[created] = (struct worker){ .iterations = iterations,
                                            .cpu_start = -1, .cpu_end = -1 };
        int rc = pthread_create(&threads[created], NULL, run_worker, &workers[created]);
        if (rc) {
            fprintf(stderr, "pthread_create worker %u failed: %d\n", created, rc);
            atomic_store_explicit(&gate, -1, memory_order_release);
            for (unsigned j = 0; j < created; j++) pthread_join(threads[j], NULL);
            return -1;
        }
    }
    if (now(&start) != 0) {
        perror("clock_gettime");
        atomic_store_explicit(&gate, -1, memory_order_release);
        for (unsigned j = 0; j < created; j++) pthread_join(threads[j], NULL);
        return -1;
    }
    atomic_store_explicit(&gate, 1, memory_order_release);
    for (unsigned i = 0; i < count; i++) {
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            fprintf(stderr, "pthread_join worker %u failed: %d\n", i, rc);
            return -1;
        }
    }
    if (now(&end) != 0 || end <= start) {
        fprintf(stderr, "CLOCK_MONOTONIC failed or did not advance\n");
        return -1;
    }
    *seconds = end - start;
    for (unsigned i = 0; i < count; i++) {
        if (workers[i].result != expected) {
            fprintf(stderr, "checksum mismatch on worker %u\n", i);
            return -1;
        }
        printf("worker=%u cpu_start=%d cpu_end=%d\n",
               i, workers[i].cpu_start, workers[i].cpu_end);
    }
    printf("workers=%u seconds=%.6f Miter_per_second=%.3f checksum=%016" PRIx64 "\n",
           count, *seconds, ((double)count * (double)iterations) / *seconds / 1e6, expected);
    return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    errno = 0;
    if (!s || !*s || *s == '-') return -1;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || *end || !n) return -1;
    *out = (uint64_t)n;
    return 0;
}

int main(int argc, char **argv)
{
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t count = online > 0 ? (uint64_t)online : 1;
    uint64_t iterations = DEFAULT_ITERATIONS;
    if (argc > 3 || (argc > 1 && parse_u64(argv[1], &count)) ||
        (argc > 2 && parse_u64(argv[2], &iterations)) || count > MAX_WORKERS) {
        fprintf(stderr, "usage: %s [workers 1..%u [iterations-per-worker]]\n", argv[0], MAX_WORKERS);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("online_reported=%ld workers=%" PRIu64 " iterations_per_worker=%" PRIu64 "\n",
           online, count, iterations);
    puts("Calculating reference checksum...");
    uint64_t expected = compute(iterations);
    double single, parallel;
    puts("Single-worker run:");
    if (run(1, iterations, expected, &single)) return 1;
    puts("Parallel run:");
    if (run((unsigned)count, iterations, expected, &parallel)) return 1;
    printf("relative_throughput=%.3fx (parallel vs one worker)\n",
           ((double)count * single) / parallel);
    puts("CPU IDs are snapshots; -1 means unavailable. They do not prove full CPU coverage.");
    return 0;
}
