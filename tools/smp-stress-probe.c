/* Run in an isolated guest: parallel task execution, migration and fork. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { WORKERS = 4, ITERATIONS = 10000, FORKS = 8 };
static atomic_uint cpu_mask;
static atomic_uint worker_cpu_masks[WORKERS];
static atomic_uint completed;
static atomic_int bad;
static atomic_int release_workers;
static int no_syscalls;
static int serial_exit;
static int raw_exit;

static void *worker(void *arg)
{
    uintptr_t id = (uintptr_t)arg;
    volatile uint64_t canary[16];
    for (int i = 0; i < 16; i++) canary[i] = 0xabc0123400000000ULL | (id << 8) | (unsigned)i;
    int iterations = no_syscalls ? ITERATIONS * 100 : ITERATIONS;
    for (int i = 0; i < iterations; i++) {
        unsigned cpu = 99;
        if (!no_syscalls && syscall(SYS_getcpu, &cpu, NULL, NULL) == 0 && cpu < 32) {
            atomic_fetch_or(&cpu_mask, 1u << cpu);
            atomic_fetch_or(&worker_cpu_masks[id], 1u << cpu);
        }
        for (int j = 0; j < 16; j++)
            if (canary[j] != (0xabc0123400000000ULL | (id << 8) | (unsigned)j))
                atomic_store(&bad, 1);
        if (!no_syscalls && (i & 127) == 0) sched_yield();
    }
    atomic_fetch_add(&completed, 1);
    if (no_syscalls) {
        int release_value = serial_exit ? (int)id + 1 : 1;
        while (atomic_load(&release_workers) < release_value)
            __asm__ volatile("pause");
    }
    if (raw_exit) {
        syscall(SYS_exit, 0);
        __builtin_unreachable();
    }
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t threads[WORKERS];
    unsigned expected_mask = 0;
    if (argc > 3) return 6;
    if (argc >= 2) {
        char *end;
        unsigned long value = strtoul(argv[1], &end, 0);
        if (!argv[1][0] || *end || value > UINT32_MAX) return 6;
        expected_mask = (unsigned)value;
    }
    if (argc == 3) {
        if ((argv[2][0] != 'n' && argv[2][0] != 's' && argv[2][0] != 'x') ||
            argv[2][1] != '\0' || expected_mask)
            return 6;
        no_syscalls = 1;
        serial_exit = argv[2][0] == 's';
        raw_exit = argv[2][0] == 'x';
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("SMP_PROBE_START");
    for (uintptr_t i = 0; i < WORKERS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, (void *)i);
        if (rc) { printf("THREAD_CREATE_FAILED=%d\n", rc); return 1; }
    }
    if (no_syscalls) {
        while (atomic_load(&completed) != WORKERS)
            __asm__ volatile("pause");
        puts("SMP_WORKERS_COMPUTED_BEFORE_EXIT");
        atomic_store(&release_workers, 1);
    }
    for (int i = 0; i < WORKERS; i++) {
        if (pthread_join(threads[i], NULL)) return 2;
        if (serial_exit)
            atomic_store(&release_workers, i + 2);
    }
    printf("SMP_THREADS_DONE=%u CPUS=0x%x BAD=%d\n",
           atomic_load(&completed), atomic_load(&cpu_mask), atomic_load(&bad));
    for (int i = 0; i < WORKERS; i++)
        printf("SMP_WORKER=%d CPUS=0x%x\n", i, atomic_load(&worker_cpu_masks[i]));
    if (atomic_load(&completed) != WORKERS || atomic_load(&bad)) return 3;
    if ((atomic_load(&cpu_mask) & expected_mask) != expected_mask) {
        printf("SMP_EXPECTED_CPUS_MISSING=0x%x\n",
               expected_mask & ~atomic_load(&cpu_mask));
        return 7;
    }
    for (int i = 0; i < FORKS; i++) {
        pid_t pid = fork();
        if (pid < 0) return 4;
        if (!pid) _exit((i + 31) & 255);
        int status = 0;
        if (waitpid(pid, &status, 0) != pid ||
            !WIFEXITED(status) || WEXITSTATUS(status) != ((i + 31) & 255)) {
            printf("SMP_FORK_FAILED=%d status=%x\n", i, status);
            return 5;
        }
    }
    puts("SMP_FORKS_DONE");
    return 0;
}
