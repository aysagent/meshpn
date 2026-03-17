/*
 * utun-helper.c - macOS utun interface helper
 * 
 * Creates a utun interface and acts as a bidirectional pipe:
 * - stdin -> utun (packets from Node.js to network)
 * - utun -> stdout (packets from network to Node.js)
 * 
 * Protocol:
 * - Each packet is prefixed with 4-byte length (big-endian)
 * - Interface name is written to stderr on startup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <arpa/inet.h>

#define MTU 1500
#define BUFFER_SIZE (MTU + 100)

static int create_utun(char *ifname, size_t ifname_len) {
    int fd;
    struct sockaddr_ctl addr;
    struct ctl_info info;
    socklen_t ifname_size = ifname_len;
    
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("socket(PF_SYSTEM)");
        return -1;
    }
    
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        perror("ioctl(CTLIOCGINFO)");
        close(fd);
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;  /* Let kernel assign unit number */
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_size) < 0) {
        perror("getsockopt(UTUN_OPT_IFNAME)");
        close(fd);
        return -1;
    }
    
    return fd;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static ssize_t read_exact(int fd, void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, (char *)buf + total, count - total);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return total > 0 ? (ssize_t)total : -1;
            }
            return -1;
        }
        if (n == 0) return total;
        total += n;
    }
    return total;
}

static ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = write(fd, (const char *)buf + total, count - total);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        total += n;
    }
    return total;
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    char ifname[64];
    int utun_fd;
    unsigned char utun_buf[BUFFER_SIZE];
    unsigned char stdin_buf[BUFFER_SIZE];
    fd_set read_fds;
    int max_fd;
    
    utun_fd = create_utun(ifname, sizeof(ifname));
    if (utun_fd < 0) {
        fprintf(stderr, "ERROR: Failed to create utun interface\n");
        return 1;
    }
    
    /* Output interface name to stderr for Node.js to read */
    fprintf(stderr, "%s\n", ifname);
    fflush(stderr);
    
    set_nonblocking(STDIN_FILENO);
    set_nonblocking(utun_fd);
    
    max_fd = (utun_fd > STDIN_FILENO) ? utun_fd : STDIN_FILENO;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(utun_fd, &read_fds);
        
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        
        /* Read from utun, write to stdout */
        if (FD_ISSET(utun_fd, &read_fds)) {
            ssize_t n = read(utun_fd, utun_buf, sizeof(utun_buf));
            if (n > 0) {
                /* utun packets have 4-byte AF header, skip it for the IP packet */
                if (n > 4) {
                    uint32_t len = htonl(n - 4);
                    if (write_all(STDOUT_FILENO, &len, 4) < 0) {
                        perror("write length to stdout");
                        break;
                    }
                    if (write_all(STDOUT_FILENO, utun_buf + 4, n - 4) < 0) {
                        perror("write packet to stdout");
                        break;
                    }
                }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read from utun");
                break;
            }
        }
        
        /* Read from stdin, write to utun */
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            uint32_t len_be;
            ssize_t n = read_exact(STDIN_FILENO, &len_be, 4);
            if (n == 0) {
                /* EOF on stdin - parent process closed pipe */
                break;
            }
            if (n == 4) {
                uint32_t len = ntohl(len_be);
                if (len > 0 && len <= MTU) {
                    /* Prepare AF header (AF_INET = 2) */
                    stdin_buf[0] = 0;
                    stdin_buf[1] = 0;
                    stdin_buf[2] = 0;
                    stdin_buf[3] = 2;  /* AF_INET */
                    
                    n = read_exact(STDIN_FILENO, stdin_buf + 4, len);
                    if (n == (ssize_t)len) {
                        /* Check if IPv6 (version field in first nibble) */
                        if ((stdin_buf[4] >> 4) == 6) {
                            stdin_buf[3] = 30;  /* AF_INET6 */
                        }
                        
                    ssize_t written = write(utun_fd, stdin_buf, len + 4);
                    if (written < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("write to utun");
                        }
                    } else {
                        fprintf(stderr, "UTUN: wrote %zd bytes to interface\n", written);
                    }
                    }
                } else if (len > MTU) {
                    fprintf(stderr, "ERROR: Packet too large: %u\n", len);
                    /* Drain the oversized packet */
                    while (len > 0) {
                        size_t chunk = (len > sizeof(stdin_buf)) ? sizeof(stdin_buf) : len;
                        if (read_exact(STDIN_FILENO, stdin_buf, chunk) <= 0) break;
                        len -= chunk;
                    }
                }
            }
        }
    }
    
    close(utun_fd);
    return 0;
}
