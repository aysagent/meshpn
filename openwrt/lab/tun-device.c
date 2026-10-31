/* Lab-only replacement for absent BusyBox `ip tuntap`; never installed in APK. */
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "create") && strcmp(argv[1], "delete")) ||
      (strcmp(argv[2], "cvctun0") && strcmp(argv[2], "cvetun0"))) return 2;
  int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (fd < 0) { perror("tun_open"); return 1; }
  struct ifreq req;
  memset(&req, 0, sizeof(req));
  req.ifr_flags = IFF_TUN | IFF_NO_PI;
  memcpy(req.ifr_name, argv[2], strlen(argv[2]) + 1);
  int rc = ioctl(fd, TUNSETIFF, &req);
  if (!rc) rc = ioctl(fd, TUNSETPERSIST, !strcmp(argv[1], "create"));
  if (rc) perror("tun_ioctl");
  if (close(fd)) { perror("tun_close"); return 1; }
  return rc ? 1 : 0;
}
