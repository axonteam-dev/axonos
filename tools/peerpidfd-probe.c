/* Run in a guest: SO_PEERPIDFD must not fabricate ownership of stdin. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

int main(void) {
    int sockets[2], pidfd = -1;
    socklen_t size = sizeof(pidfd);
    if (fcntl(0, F_GETFD) < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        return 1;
    int rc = getsockopt(sockets[0], SOL_SOCKET, SO_PEERPIDFD, &pidfd, &size);
    if (rc == 0) {
        if (size != sizeof(pidfd) || pidfd < 3 || fcntl(pidfd, F_GETFD) < 0)
            return 2;
        close(pidfd);
    } else if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
        return 3;
    }
    close(sockets[0]);
    close(sockets[1]);
    if (fcntl(0, F_GETFD) < 0) return 4;
    puts("PEERPIDFD_PROBE_OK");
    return 0;
}
