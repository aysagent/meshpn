/*
 * TUN helper for Linux
 * Creates and manages TUN interface, communicates via stdin/stdout
 * 
 * Protocol:
 * - Sends interface name to stderr on startup
 * - Reads packets from stdin: 4-byte length (BE) + packet data
 * - Writes packets to stdout: 4-byte length (BE) + packet data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <signal.h>

#define MTU 1500
#define BUFFER_SIZE (MTU + 100)

static int tun_fd = -1;
static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char *argv[]) {
    char tun_name[IFNAMSIZ] = "tun0";
    unsigned char buffer[BUFFER_SIZE];
    unsigned char stdin_buffer[BUFFER_SIZE * 2];
    int stdin_buffer_len = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (argc > 1) {
        strncpy(tun_name, argv[1], IFNAMSIZ - 1);
    }

    tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "ERROR: Failed to create TUN interface: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "%s\n", tun_name);
    fflush(stderr);

    set_nonblocking(tun_fd);
    set_nonblocking(STDIN_FILENO);

    fd_set read_fds;
    int max_fd = (tun_fd > STDIN_FILENO) ? tun_fd : STDIN_FILENO;

    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(tun_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(tun_fd, &read_fds)) {
            int nread = read(tun_fd, buffer + 4, BUFFER_SIZE - 4);
            if (nread > 0) {
                buffer[0] = (nread >> 24) & 0xFF;
                buffer[1] = (nread >> 16) & 0xFF;
                buffer[2] = (nread >> 8) & 0xFF;
                buffer[3] = nread & 0xFF;
                
                int total = nread + 4;
                int written = 0;
                while (written < total) {
                    int w = write(STDOUT_FILENO, buffer + written, total - written);
                    if (w < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                        running = 0;
                        break;
                    }
                    written += w;
                }
            }
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            int nread = read(STDIN_FILENO, stdin_buffer + stdin_buffer_len, 
                           sizeof(stdin_buffer) - stdin_buffer_len);
            if (nread <= 0) {
                if (nread == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    running = 0;
                }
                continue;
            }
            stdin_buffer_len += nread;

            while (stdin_buffer_len >= 4) {
                int packet_len = (stdin_buffer[0] << 24) | (stdin_buffer[1] << 16) |
                                (stdin_buffer[2] << 8) | stdin_buffer[3];
                
                if (packet_len > MTU + 100 || packet_len < 0) {
                    stdin_buffer_len = 0;
                    break;
                }

                if (stdin_buffer_len < 4 + packet_len) {
                    break;
                }

                if (write(tun_fd, stdin_buffer + 4, packet_len) < 0) {
                    // Ignore write errors
                }

                int remaining = stdin_buffer_len - 4 - packet_len;
                if (remaining > 0) {
                    memmove(stdin_buffer, stdin_buffer + 4 + packet_len, remaining);
                }
                stdin_buffer_len = remaining;
            }
        }
    }

    if (tun_fd >= 0) {
        close(tun_fd);
    }

    return 0;
}
