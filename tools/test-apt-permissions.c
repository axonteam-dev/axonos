/* Run as root inside AxonOS (and Linux for comparison), not on a live APT dir. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)
int main(void)
{
    const uid_t sandbox = 12345;
    char dir[] = "/tmp/axon-apt-perms-XXXXXX", file[128], secret[128];
    gid_t group = 12345;
    CHECK(getuid() == 0 && geteuid() == 0);
    CHECK(mkdtemp(dir) != NULL);
    CHECK(snprintf(file, sizeof(file), "%s/probe-XXXXXX", dir) > 0);
    CHECK(snprintf(secret, sizeof(secret), "%s/secret", dir) > 0);
    CHECK(chown(dir, sandbox, group) == 0);
    CHECK(chmod(dir, 0700) == 0);
    int fd = open(secret, O_CREAT | O_WRONLY | O_EXCL, 0600);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(setgroups(1, &group) == 0);
    CHECK(setegid(group) == 0);
    CHECK(seteuid(sandbox) == 0);
    CHECK(getuid() == 0 && geteuid() == sandbox);
    /* access uses real root; open uses effective _apt. */
    CHECK(access(secret, R_OK) == 0);
    errno = 0;
    CHECK(open(secret, O_RDONLY) == -1 && errno == EACCES);
    fd = mkstemp(file);
    CHECK(fd >= 0);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_uid == sandbox);
    CHECK(close(fd) == 0);
    CHECK(unlink(file) == 0);
    CHECK(seteuid(0) == 0);
    CHECK(setegid(0) == 0);
    CHECK(unlink(secret) == 0);
    CHECK(rmdir(dir) == 0);
    puts("PASS: APT temporary effective-ID switch and mkstemp");
    return 0;
}
