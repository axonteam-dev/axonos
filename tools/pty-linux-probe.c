/* Run in a guest to identify the failing Unix98 PTY operation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static void result(const char *name, int rc)
{
    int e = errno;
    printf("%s: rc=%d errno=%d (%s)\n", name, rc, e, strerror(e));
    fflush(stdout);
}

int main(void)
{
    struct termios term;
    struct winsize ws;
    struct stat st;
    unsigned int index = 0;
    int master, slave, peer;
    char *name;

    setvbuf(stdout, NULL, _IONBF, 0);
    errno = 0;
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    result("posix_openpt", master);
    if (master < 0) return 1;
    errno = 0; result("TIOCGPTN", ioctl(master, TIOCGPTN, &index));
    printf("pty index=%u\n", index);
    errno = 0; result("grantpt", grantpt(master));
    errno = 0; result("unlockpt", unlockpt(master));
    int packet = 1;
    errno = 0; result("TIOCPKT enable", ioctl(master, TIOCPKT, &packet));
#ifdef TIOCGPKT
    int packet_state = -1;
    errno = 0; result("TIOCGPKT", ioctl(master, TIOCGPKT, &packet_state));
    printf("packet mode=%d\n", packet_state);
#endif
    errno = 0; name = ptsname(master);
    printf("ptsname: %s errno=%d\n", name ? name : "(null)", errno);
    if (!name) return 1;
    errno = 0; result("stat slave", stat(name, &st));
    errno = 0; slave = open(name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    result("open slave", slave);
    errno = 0; result("TCGETS master", tcgetattr(master, &term));
    if (slave >= 0) {
        errno = 0; result("TCGETS slave", tcgetattr(slave, &term));
        errno = 0; result("TIOCGWINSZ slave", ioctl(slave, TIOCGWINSZ, &ws));
        char bytes[8] = {0};
        ssize_t written = write(slave, "ABC", 3);
        errno = 0;
        ssize_t read_count = read(master, bytes, sizeof(bytes));
        printf("packet write=%ld read=%ld header=%u data=%.*s errno=%d\n",
               (long)written, (long)read_count, (unsigned char)bytes[0],
               read_count > 1 ? (int)(read_count - 1) : 0, bytes + 1, errno);
        errno = 0; result("tcflush slave input", tcflush(slave, TCIFLUSH));
        int flags = fcntl(master, F_GETFL);
        if (flags >= 0) (void)fcntl(master, F_SETFL, flags | O_NONBLOCK);
        errno = 0; read_count = read(master, bytes, sizeof(bytes));
        printf("packet flush read=%ld header=%u errno=%d\n",
               (long)read_count, (unsigned char)bytes[0], errno);
    }
#ifdef TIOCGPTPEER
    errno = 0; peer = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    result("TIOCGPTPEER", peer);
    if (peer >= 0) close(peer);
#else
    peer = -1;
    (void)peer;
#endif
    if (slave >= 0) close(slave);
    close(master);
    return 0;
}
