/* Compile against the guest's libc and run as root in an AxonOS guest booted
 * with the experimental high-RAM pool. A host static libc may require CPU
 * instructions that the guest has not enabled.
 * This test creates and deletes only /tmp/axonos-highmem-test-<pid>. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#undef BLOCK_SIZE
#define BLOCK_SIZE 65536
#define BLOCKS 256

static unsigned char buffer[BLOCK_SIZE];

static void fill(unsigned block)
{
    for (unsigned i = 0; i < BLOCK_SIZE; ++i)
        buffer[i] = (unsigned char)((block * 73u + i * 17u + (i >> 8)) & 255u);
}

static int transfer(int fd, void *buffer, size_t n, int writing)
{
    size_t done = 0;
    while (done < n) {
        ssize_t result = writing ? write(fd, (char *)buffer + done, n - done)
                                 : read(fd, (char *)buffer + done, n - done);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return -1;
        done += (size_t)result;
    }
    return 0;
}

static int meminfo(unsigned long long *free_kb, unsigned long long *available_kb)
{
    char line[256];
    int found = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemFree: %llu kB", free_kb) == 1) found |= 1;
        if (sscanf(line, "MemAvailable: %llu kB", available_kb) == 1) found |= 2;
    }
    fclose(f);
    return found == 3 ? 0 : -1;
}

int main(void)
{
    char path[96];
    unsigned long long before, before_avail, written, written_avail, after, after_avail;
    int fd = -1, result = 1;
    if (mount("proc", "/proc", "proc", 0, NULL) < 0 && errno != EBUSY)
        perror("mount proc");
    if (meminfo(&before, &before_avail) != 0) {
        fprintf(stderr, "FAIL: cannot read /proc/meminfo\n");
        return 1;
    }
    snprintf(path, sizeof(path), "/tmp/axonos-highmem-test-%ld", (long)getpid());
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) { perror("open"); return 1; }
    for (unsigned block = 0; block < BLOCKS; ++block) {
        fill(block);
        if (transfer(fd, buffer, sizeof(buffer), 1) != 0) {
            perror("write"); goto out;
        }
    }
    if (meminfo(&written, &written_avail) != 0) goto out;
    if (lseek(fd, 0, SEEK_SET) != 0) { perror("lseek"); goto out; }
    for (unsigned block = 0; block < BLOCKS; ++block) {
        if (transfer(fd, buffer, sizeof(buffer), 0) != 0) {
            fprintf(stderr, "FAIL: short read at block %u\n", block); goto out;
        }
        for (unsigned i = 0; i < BLOCK_SIZE; ++i) {
            unsigned char expected = (unsigned char)((block * 73u + i * 17u + (i >> 8)) & 255u);
            if (buffer[i] != expected) {
                fprintf(stderr, "FAIL: data mismatch at block %u offset %u\n", block, i);
                goto out;
            }
        }
    }
    if (close(fd) != 0) { fd = -1; perror("close"); goto out; }
    fd = -1;
    if (unlink(path) != 0) { perror("unlink"); return 1; }
    path[0] = '\0';
    if (meminfo(&after, &after_avail) != 0) return 1;
    printf("MemFree kB: before=%llu written=%llu after=%llu\n", before, written, after);
    printf("MemAvailable kB: before=%llu written=%llu after=%llu\n",
           before_avail, written_avail, after_avail);
    if (before < written || before - written < 12 * 1024 ||
        after < written || after - written < 12 * 1024) {
        fprintf(stderr, "FAIL: RAMFS page accounting did not drop and recover\n");
        return 1;
    }
    if (before_avail > written_avail && before_avail - written_avail > 4 * 1024) {
        fprintf(stderr, "FAIL: write consumed low process memory, not the high pool\n");
        return 1;
    }
    puts("PASS: high RAMFS pages, 16 MiB nonzero write/read/unlink");
    result = 0;
out:
    if (fd >= 0) close(fd);
    if (path[0]) unlink(path);
    return result;
}
