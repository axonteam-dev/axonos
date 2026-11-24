/* Isolated guest test: allocate, touch and verify memory in bounded mappings. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

enum { MAX_BLOCKS = 128, BLOCK_MIB = 64 };

int main(int argc, char **argv)
{
    char *end;
    if ((argc != 2 && argc != 3) || !argv[1][0] || argv[1][0] == '-')
        return 2;
    errno = 0;
    unsigned long mb = strtoul(argv[1], &end, 0);
    if (errno || *end || !mb || mb > MAX_BLOCKS * BLOCK_MIB || mb % BLOCK_MIB)
        return 2;
    unsigned long rounds = 1;
    if (argc == 3) {
        if (!argv[2][0] || argv[2][0] == '-')
            return 2;
        errno = 0;
        rounds = strtoul(argv[2], &end, 0);
        if (errno || *end || !rounds || rounds > 4)
            return 2;
    }
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0 || (uint64_t)ps > (uint64_t)BLOCK_MIB * 1024 * 1024)
        return 2;

    unsigned char *blocks[MAX_BLOCKS] = {0};
    size_t block_size = (size_t)BLOCK_MIB * 1024 * 1024;
    size_t count = mb / BLOCK_MIB;
    int result = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("HIGH_PROBE_START target_mib=%lu block_mib=%d\n", mb, BLOCK_MIB);
    for (unsigned long round = 0; round < rounds; round++) {
        size_t mapped = 0;
        printf("HIGH_PROBE_ROUND=%lu\n", round + 1);
        for (; mapped < count; mapped++) {
            void *p = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) {
                printf("HIGH_PROBE_MMAP_FAILED mapped_mib=%zu errno=%d\n",
                       mapped * BLOCK_MIB, errno);
                result = 1;
                break;
            }
            blocks[mapped] = p;
            for (size_t offset = 0; offset < block_size; offset += (size_t)ps) {
                if (blocks[mapped][offset] != 0) {
                    printf("HIGH_PROBE_NOT_ZERO block=%zu offset=%zu\n", mapped, offset);
                    mapped++;
                    result = 1;
                    goto done;
                }
                blocks[mapped][offset] = (unsigned char)(1 + round + mapped + (offset / (size_t)ps));
            }
            printf("HIGH_PROBE_TOUCHED_MIB=%zu\n", (mapped + 1) * BLOCK_MIB);
        }
        for (size_t i = 0; i < mapped; i++) {
            for (size_t offset = 0; offset < block_size; offset += (size_t)ps) {
                unsigned char expected = (unsigned char)(1 + round + i + (offset / (size_t)ps));
                if (blocks[i][offset] != expected) {
                    printf("HIGH_PROBE_MISMATCH block=%zu offset=%zu\n", i, offset);
                    result = 1;
                    goto done;
                }
            }
        }
done:
        for (size_t i = 0; i < mapped; i++)
            if (munmap(blocks[i], block_size) != 0)
                result = 1;
        if (result)
            return result;
    }
    puts("HIGH_PROBE_PASS");
    return result;
}
