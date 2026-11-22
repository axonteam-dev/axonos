/* Repeated loader and fork/COW workload. Build with: cc -O2 -o repro-wrapper-memory tools/repro-wrapper-memory.c -ldl
 * Run on AxonOS: ./repro-wrapper-memory /path/to/library.so [iterations]
 * MemFree is only an AxonOS estimate, not PMM availability. Check kernel OOM
 * messages too; warm caches can retain pages. This does not execute a wrapper.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void meminfo(int iteration)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    printf("iteration %d", iteration);
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (!strncmp(line, "MemFree:", 8) || !strncmp(line, "MemAvailable:", 13)) {
                line[strcspn(line, "\n")] = 0;
                printf("  %s", line);
            }
        fclose(f);
    }
    putchar('\n');
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const size_t size = 4 * 1024 * 1024;
    int iterations = argc > 2 ? atoi(argv[2]) : 500;
    if (argc < 2 || iterations <= 0) {
        fprintf(stderr, "usage: %s library.so [iterations]\n", argv[0]);
        return 2;
    }
    char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    for (size_t i = 0; i < size; i += 4096) p[i] = 1;
    meminfo(0);
    for (int n = 1; n <= iterations; n++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (!pid) {
            for (size_t i = 0; i < size; i += 4096) p[i]++;
            void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
            if (!h) { fprintf(stderr, "iteration %d: dlopen: %s\n", n, dlerror()); _exit(1); }
            dlclose(h);
            _exit(0);
        }
        int status;
        while (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) continue;
            perror("waitpid"); return 1;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            fprintf(stderr, "iteration %d: child status %#x\n", n, status);
            meminfo(n);
            return 1;
        }
        if (n % 10 == 0 || n == iterations) meminfo(n);
    }
    munmap(p, size);
    return 0;
}
