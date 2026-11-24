/* Isolated guest test: fork after crossing the low physical-page pool. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

enum { BLOCKS = 12, BLOCK_MIB = 64 };

int main(int argc, char **argv)
{
    int exec_child = argc == 2 && strcmp(argv[1], "exec") == 0;
    if (argc > 2 || (argc == 2 && !exec_child))
        return 2;
    unsigned char *blocks[BLOCKS];
    size_t length = (size_t)BLOCK_MIB * 1024 * 1024;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (size_t)page_size > length)
        return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("HIGH_FORK_START");
    for (int i = 0; i < BLOCKS; i++) {
        blocks[i] = mmap(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (blocks[i] == MAP_FAILED) {
            printf("HIGH_FORK_MMAP_FAILED block=%d errno=%d\n", i, errno);
            return 2;
        }
        for (size_t j = 0; j < length; j += (size_t)page_size)
            blocks[i][j] = (unsigned char)(i + j / (size_t)page_size + 1);
    }
    puts("HIGH_FORK_POPULATED");
    pid_t child = fork();
    int fork_errno = errno;
    if (child == 0) {
        if (exec_child) {
            execl("/bin/true", "true", (char *)NULL);
            _exit(127);
        }
        for (int i = 0; i < BLOCKS; i++) {
            for (size_t j = 0; j < length; j += (size_t)page_size) {
                unsigned char expected = (unsigned char)(i + j / (size_t)page_size + 1);
                if (blocks[i][j] != expected)
                    _exit(3);
                blocks[i][j] ^= 0xff;
            }
        }
        _exit(0);
    }
    int status = 0;
    if (child > 0 && (waitpid(child, &status, 0) != child ||
                      !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        printf("HIGH_FORK_CHILD_FAILED status=%x\n", status);
        return 1;
    }
    for (int i = 0; i < BLOCKS; i++) {
        for (size_t j = 0; j < length; j += (size_t)page_size) {
            unsigned char expected = (unsigned char)(i + j / (size_t)page_size + 1);
            if (blocks[i][j] != expected) {
                printf("HIGH_FORK_PARENT_CORRUPT block=%d offset=%zu\n", i, j);
                return 1;
            }
        }
        if (munmap(blocks[i], length) != 0)
            return 1;
    }
    if (child < 0) {
        printf("HIGH_FORK_FAILED errno=%d parent_data_intact=1\n", fork_errno);
        return 1;
    }
    puts(exec_child ? "HIGH_FORK_EXEC_PASS" : "HIGH_FORK_PASS");
    return 0;
}
