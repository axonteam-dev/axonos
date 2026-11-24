/* Isolated guest: create/join threads after exhausting the low frame pool. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

enum { BLOCKS = 12, BLOCK_MIB = 64, THREADS = 2 };
static _Thread_local unsigned tls_marker;

static void *worker(void *arg)
{
    uintptr_t id = (uintptr_t)arg;
    volatile uint64_t stack_words[64];
    tls_marker = (unsigned)id + 0x123400u;
    for (unsigned i = 0; i < 64; i++)
        stack_words[i] = 0x9876000000000000ULL | (id << 8) | i;
    for (unsigned iteration = 0; iteration < 2000; iteration++) {
        if (tls_marker != (unsigned)id + 0x123400u)
            return (void *)1;
        for (unsigned i = 0; i < 64; i++)
            if (stack_words[i] != (0x9876000000000000ULL | (id << 8) | i))
                return (void *)1;
        if ((iteration & 127u) == 0)
            (void)getpid();
    }
    return NULL;
}

int main(int argc, char **argv)
{
    unsigned char *blocks[BLOCKS];
    int block_count = BLOCKS;
    if (argc == 2) {
        char *end;
        errno = 0;
        long requested = strtol(argv[1], &end, 10);
        if (errno || !argv[1][0] || *end || requested < 1 || requested > BLOCKS)
            return 2;
        block_count = (int)requested;
    } else if (argc != 1) {
        return 2;
    }
    size_t length = (size_t)BLOCK_MIB * 1024 * 1024;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (size_t)page_size > length)
        return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("HIGH_THREAD_START");
    for (int i = 0; i < block_count; i++) {
        blocks[i] = mmap(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (blocks[i] == MAP_FAILED) {
            printf("HIGH_THREAD_MMAP_FAILED block=%d errno=%d\n", i, errno);
            return 2;
        }
        for (size_t j = 0; j < length; j += (size_t)page_size)
            blocks[i][j] = (unsigned char)(i + j / (size_t)page_size + 1);
    }
    puts("HIGH_THREAD_POPULATED");
    pthread_t threads[THREADS];
    for (uintptr_t i = 0; i < THREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, worker, (void *)i);
        if (rc) {
            printf("HIGH_THREAD_CREATE_FAILED id=%lu rc=%d\n", (unsigned long)i, rc);
            return 1;
        }
    }
    for (int i = 0; i < THREADS; i++) {
        void *result = NULL;
        int rc = pthread_join(threads[i], &result);
        if (rc || result) {
            printf("HIGH_THREAD_JOIN_FAILED id=%d rc=%d result=%p\n", i, rc, result);
            return 1;
        }
    }
    for (int i = 0; i < block_count; i++) {
        for (size_t j = 0; j < length; j += (size_t)page_size) {
            if (blocks[i][j] != (unsigned char)(i + j / (size_t)page_size + 1)) {
                printf("HIGH_THREAD_DATA_CORRUPT block=%d offset=%zu\n", i, j);
                return 1;
            }
        }
        if (munmap(blocks[i], length) != 0)
            return 1;
    }
    puts("HIGH_THREAD_PASS");
    return 0;
}
