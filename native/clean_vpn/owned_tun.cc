// Short-lived privileged control helper. No packet processing or shell.
// TUN remains ephemeral until its durable owner alias and address are installed.
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

static void require(bool value) { if (!value) throw std::runtime_error("owned_tun_refused"); }
static void ip(std::vector<std::string> args) {
  args.insert(args.begin(), "ip");
  std::vector<char*> argv;
  for (auto& a : args) argv.push_back(a.data());
  argv.push_back(nullptr);
  const pid_t pid = fork(); require(pid >= 0);
  if (!pid) { execv("/usr/sbin/ip", argv.data()); execv("/sbin/ip", argv.data()); _exit(127); }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  int status = 0;
  for (;;) {
    const auto result = waitpid(pid, &status, WNOHANG);
    if (result == pid) { require(WIFEXITED(status) && WEXITSTATUS(status) == 0); return; }
    if (result < 0 || std::chrono::steady_clock::now() >= deadline) {
      kill(pid, SIGKILL); while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
      require(false);
    }
    usleep(10000);
  }
}
int main(int argc, char** argv) {
  int fd = -1;
  try {
    require((argc == 3 || argc == 4) && geteuid() == 0);
    const std::string name = argv[1], owner = argv[2];
    const bool client = name == "tun0" && std::regex_match(owner, std::regex("cvpn-native-host-[a-f0-9]{24}"));
    const bool exit = std::regex_match(name, std::regex("cvexit[a-z0-9]{0,8}")) &&
      std::regex_match(owner, std::regex("cvpn-native-exit-host-[a-f0-9]{24}"));
    require(client || exit);
    std::string peer = argc == 4 ? argv[3] : "10.99.0.2";
    in_addr address{}; require(inet_pton(AF_INET, peer.c_str(), &address) == 1);
    const auto v = ntohl(address.s_addr);
    require((argc != 4 || client) && (v >> 8) == 0x0a6300 && (v & 255) >= 2 && (v & 255) <= 254);
    fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC); require(fd >= 0);
    ifreq request{}; std::memcpy(request.ifr_name, name.c_str(), name.size() + 1);
    request.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    require(ioctl(fd, TUNSETIFF, &request) == 0);
    ip({"link", "set", "dev", name, "alias", owner});
    ip({"address", "add", client ? peer + "/32" : "10.99.0.1/24", "dev", name});
    ip({"link", "set", "dev", name, "mtu", "1400", "up"});
    require(ioctl(fd, TUNSETPERSIST, 1) == 0);
    close(fd); return 0;
  } catch (...) {
    if (fd >= 0) close(fd);
    std::cerr << "owned_tun_refused\n"; return 1;
  }
}
