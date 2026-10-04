/* Lab-only Linux UDP/PMTU probe; no raw sockets, firewall or system changes.
 * server ADDRESS | probe ADDRESS LOCAL TX_BYTES RX_BYTES DF REPLY_DF ID
 * DF: 0=DONT, 2=DO, 3=PROBE. Packet bytes are deterministic, not user data. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned char data[65536], expected[65536];
static void die(const char *s) { perror(s); exit(2); }
static long number(const char *s, long max) {
  char *end; errno = 0; long n = strtol(s, &end, 10);
  if (errno || !*s || *end || n < 0 || n > max) { fprintf(stderr, "bad integer\n"); exit(2); }
  return n;
}
static int mode(long n) { if (n != 0 && n != 2 && n != 3) exit(2); return (int)n; }
static struct sockaddr_in addr(const char *s, int port) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
  if (inet_pton(AF_INET, s, &a.sin_addr) != 1) exit(2);
  return a;
}
static void option(int fd, int name, int value) {
  if (setsockopt(fd, IPPROTO_IP, name, &value, sizeof(value))) die("setsockopt");
}
static void packet(unsigned char *p, int n, uint32_t id, int reply, int df) {
  for (int i = 0; i < n; i++) p[i] = (unsigned char)(i * 31 + id);
  uint32_t h[] = {htonl(id), htonl((uint32_t)reply), htonl((uint32_t)df)};
  memcpy(p, h, sizeof(h));
}
static uint32_t digest(unsigned char *p, int n) {
  uint32_t h = 2166136261u; for (int i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u; return h;
}
static int error_queue(int fd, const char *side) {
  char control[512]; unsigned char quoted[65536]; struct sockaddr_in offender;
  struct iovec io = {.iov_base = quoted, .iov_len = sizeof(quoted)};
  struct msghdr msg = {.msg_name = &offender, .msg_namelen = sizeof(offender),
    .msg_iov = &io, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
  ssize_t n = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT); if (n < 0) return 0;
  uint32_t id = 0; if (n >= 4) { memcpy(&id, quoted, 4); id = ntohl(id); }
  for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVERR || c->cmsg_len < CMSG_LEN(sizeof(struct sock_extended_err))) continue;
    struct sock_extended_err *e = (void *)CMSG_DATA(c);
    printf("{\"event\":\"error\",\"side\":\"%s\",\"id\":%u,\"errno\":%u,\"origin\":%u,\"type\":%u,\"code\":%u,\"mtu\":%u}\n",
      side, id, e->ee_errno, e->ee_origin, e->ee_type, e->ee_code, e->ee_info);
  }
  return 1;
}
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000.0 + t.tv_nsec / 1e6; }
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  int server = argc == 3 && !strcmp(argv[1], "server");
  if (!server && (argc != 9 || strcmp(argv[1], "probe"))) return 2;
  int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) die("socket");
  option(fd, IP_RECVERR, 1);
  struct sockaddr_in a = addr(argv[2], 38474);
  if (server) {
    if (bind(fd, (void *)&a, sizeof(a))) die("bind");
    printf("{\"event\":\"ready\"}\n");
    for (;;) {
      struct pollfd p = {.fd = fd, .events = POLLIN}; if (poll(&p, 1, 1000) < 0) die("poll");
      while (error_queue(fd, "server")) {}
      struct sockaddr_in peer; socklen_t len = sizeof(peer);
      ssize_t n = recvfrom(fd, data, sizeof(data), MSG_DONTWAIT, (void *)&peer, &len);
      if (n < 16) continue;
      uint32_t h[3]; memcpy(h, data, sizeof(h));
      uint32_t id = ntohl(h[0]); int reply = (int)ntohl(h[1]), df = (int)ntohl(h[2]);
      if (reply < 16 || reply > 60000 || (df != 0 && df != 2 && df != 3)) continue;
      packet(expected, (int)n, id, reply, df); int valid = !memcmp(data, expected, (size_t)n);
      char source[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &peer.sin_addr, source, sizeof(source));
      uint32_t received_hash = digest(data, (int)n);
      option(fd, IP_MTU_DISCOVER, df); packet(data, reply, id, reply, df);
      ssize_t sent = valid ? sendto(fd, data, (size_t)reply, 0, (void *)&peer, len) : -1;
      int err = sent < 0 ? errno : 0;
      printf("{\"event\":\"received\",\"id\":%u,\"peer\":\"%s\",\"bytes\":%zd,\"hash\":%u,\"valid\":%s,\"sent\":%zd,\"sendErrno\":%d}\n", id, source, n, received_hash, valid ? "true" : "false", sent, err);
    }
  }
  struct sockaddr_in local = addr(argv[3], 0); if (bind(fd, (void *)&local, sizeof(local))) die("bind client");
  int tx = (int)number(argv[4], 60000), rx = (int)number(argv[5], 60000);
  if (tx < 16 || rx < 16) return 2;
  int df = mode(number(argv[6], 3)), rdf = mode(number(argv[7], 3));
  uint32_t id = (uint32_t)number(argv[8], 10000000);
  option(fd, IP_MTU_DISCOVER, df); if (connect(fd, (void *)&a, sizeof(a))) die("connect");
  packet(data, tx, id, rx, rdf);
  printf("{\"event\":\"request\",\"id\":%u,\"bytes\":%d,\"hash\":%u}\n", id, tx, digest(data, tx));
  int senderr = send(fd, data, (size_t)tx, 0) < 0 ? errno : 0;
  int ok = 0, bytes = 0; double end = now() + 5000;
  do {
    struct pollfd p = {.fd = fd, .events = POLLIN}; if (poll(&p, 1, 100) < 0) die("poll");
    while (error_queue(fd, "client")) {}
    ssize_t n = recv(fd, data, sizeof(data), MSG_DONTWAIT);
    if (n >= 0) { bytes = (int)n; packet(expected, rx, id, rx, rdf); ok = n == rx && !memcmp(data, expected, (size_t)rx); break; }
    if (senderr) break;
  } while (now() < end);
  int mtu = 0; socklen_t len = sizeof(mtu); if (getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len)) die("get mtu");
  printf("{\"event\":\"result\",\"id\":%u,\"ok\":%s,\"bytes\":%d,\"hash\":%u,\"expectedHash\":%u,\"sendErrno\":%d,\"pathMtu\":%d}\n", id, ok ? "true" : "false", bytes, digest(data, bytes), (packet(expected, rx, id, rx, rdf), digest(expected, rx)), senderr, mtu);
  close(fd); return 0;
}
