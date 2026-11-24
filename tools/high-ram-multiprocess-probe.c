/* Isolated guest: two independently faulted address spaces stay live together. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

enum { CHILDREN = 2, BLOCK_MIB = 64, MAX_BLOCKS = 20 };

static void worker(int id, int blocks, int ready, int gate)
{
    unsigned char *pages[MAX_BLOCKS];
    size_t length = (size_t)BLOCK_MIB * 1024 * 1024;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (size_t)page_size > length)
        _exit(2);
    for (int i = 0; i < blocks; i++) {
        pages[i] = mmap(NULL, length, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages[i] == MAP_FAILED) {
            if (write(ready, "E", 1) != 1) _exit(4);
            _exit(2);
        }
        for (size_t j = 0; j < length; j += (size_t)page_size) {
            if (pages[i][j] != 0) {
                if (write(ready, "E", 1) != 1) _exit(4);
                _exit(3);
            }
            pages[i][j] = (unsigned char)(1 + id * 17 + i + j / (size_t)page_size);
        }
    }
    if (write(ready, "R", 1) != 1)
        _exit(4);
    char token;
    if (read(gate, &token, 1) != 1)
        _exit(4);
    for (int i = 0; i < blocks; i++) {
        for (size_t j = 0; j < length; j += (size_t)page_size) {
            unsigned char expected = (unsigned char)(1 + id * 17 + i + j / (size_t)page_size);
            if (pages[i][j] != expected)
                _exit(5);
        }
        if (munmap(pages[i], length) != 0)
            _exit(6);
    }
    _exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 2 || !argv[1][0] || argv[1][0] == '-')
        return 2;
    char *end;
    errno = 0;
    unsigned long mb = strtoul(argv[1], &end, 0);
    if (errno || *end || !mb || mb % BLOCK_MIB || mb > MAX_BLOCKS * BLOCK_MIB)
        return 2;
    int ready[2], gate[CHILDREN][2];
    if (pipe(ready) != 0)
        return 2;
    for (int i = 0; i < CHILDREN; i++)
        if (pipe(gate[i]) != 0)
            return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    printf("HIGH_MP_START children=%d mib_each=%lu\n", CHILDREN, mb);
    pid_t children[CHILDREN];
    for (int i = 0; i < CHILDREN; i++) {
        children[i] = fork();
        if (children[i] < 0)
            return 2;
        if (children[i] == 0) {
            close(ready[0]);
            for (int j = 0; j < CHILDREN; j++) {
                close(gate[j][1]);
                if (j != i) close(gate[j][0]);
            }
            worker(i, (int)(mb / BLOCK_MIB), ready[1], gate[i][0]);
        }
    }
    close(ready[1]);
    for (int i = 0; i < CHILDREN; i++)
        close(gate[i][0]);
    int ok = 1;
    for (int i = 0; i < CHILDREN; i++) {
        char message = 0;
        if (read(ready[0], &message, 1) != 1 || message != 'R')
            ok = 0;
    }
    if (ok)
        printf("HIGH_MP_SIMULTANEOUS_MIB=%lu\n", mb * CHILDREN);
    for (int i = 0; i < CHILDREN; i++) {
        if (write(gate[i][1], "G", 1) != 1)
            ok = 0;
        close(gate[i][1]);
    }
    close(ready[0]);
    for (int i = 0; i < CHILDREN; i++) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("HIGH_MP_CHILD_FAILED id=%d status=%x\n", i, status);
            ok = 0;
        }
    }
    puts(ok ? "HIGH_MP_PASS" : "HIGH_MP_FAIL");
    return ok ? 0 : 1;
}
