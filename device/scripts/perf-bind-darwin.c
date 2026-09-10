/* Process-local iperf3 IPv4 socket binding. No routes, privileges or packet
 * proxying: set the native interface option at socket creation, before any
 * bind/connect/send. Loaded only in runner-owned iperf3 client processes. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int meshpn_socket(int domain, int type, int protocol)
{
    const char *iface = getenv("MESHPN_IPERF_IFACE");
    if (!iface || !*iface) { errno = EINVAL; return -1; }
    /* This runner is IPv4-only. Never leave IPv6 traffic unbound. */
    if (domain == AF_INET6) { errno = EAFNOSUPPORT; return -1; }
    int fd = socket(domain, type, protocol);
    if (fd < 0 || domain != AF_INET) return fd;
    unsigned index = if_nametoindex(iface), actual = 0;
    socklen_t len = sizeof(actual);
    if (!index) { close(fd); errno = ENXIO; return -1; }
    if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) < 0 ||
        getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &actual, &len) < 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    if (len != sizeof(actual) || actual != index) {
        close(fd); errno = ENXIO; return -1;
    }
    /* Runner rejects measurements without this proof that interposition ran.
     * One line per socket, never per packet. No performance data is copied. */
    fprintf(stderr, "MESHPN_BOUND_IF=%s\n", iface);
    return fd;
}

#ifndef MESHPN_BIND_TEST
#if !defined(__APPLE__)
#error This helper requires macOS
#endif
__attribute__((used)) static const struct {
    const void *replacement;
    const void *original;
} interpose_socket __attribute__((section("__DATA,__interpose"))) = {
    (const void *)meshpn_socket, (const void *)socket
};
#endif
