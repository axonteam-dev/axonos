/* Compile with the guest libc; exercise real memfd semantics in the guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#define F_ADD_SEALS 1033
#define F_SEAL_SEAL 1
#endif

int main(void)
{
    static const char text[] = "axon-memfd";
    char actual[sizeof(text)] = {0};
    int fd = (int)syscall(SYS_memfd_create, "axon-test", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); return 1; }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || !(flags & FD_CLOEXEC)) {
        fprintf(stderr, "FAIL: missing FD_CLOEXEC\n");
        close(fd);
        return 1;
    }
    if (fcntl(fd, F_GET_SEALS) != F_SEAL_SEAL) {
        fprintf(stderr, "FAIL: default memfd must prevent further sealing\n");
        close(fd);
        return 1;
    }
    if (ftruncate(fd, 4096) || pwrite(fd, text, sizeof(text), 0) != sizeof(text) ||
        pread(fd, actual, sizeof(actual), 0) != sizeof(actual) ||
        memcmp(text, actual, sizeof(text))) {
        perror("memfd read/write/truncate");
        close(fd);
        return 1;
    }
    void *mapping = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        perror("memfd mmap");
        close(fd);
        return 1;
    }
    if (memcmp(mapping, text, sizeof(text))) {
        fprintf(stderr, "FAIL: mapped bytes differ\n");
        munmap(mapping, 4096);
        close(fd);
        return 1;
    }
    munmap(mapping, 4096);
    close(fd);
    errno = 0;
    if (syscall(SYS_memfd_create, "axon-test", 0x80000000U) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: invalid flags were accepted\n");
        return 1;
    }
    puts("PASS: memfd_create CLOEXEC, resize, I/O and shared read-only mapping");
    return 0;
}
