#pragma once
#include "transparent_hello.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <memory>

namespace cvpn::transparent {
struct Destination {
  std::array<uint8_t, 4> ipv4{};
  uint16_t port = 0;
  bool operator==(const Destination& other) const { return ipv4 == other.ipv4 && port == other.port; }
};
inline uint32_t ipv4_number(const std::array<uint8_t, 4>& a) {
  return (uint32_t(a[0]) << 24) | (uint32_t(a[1]) << 16) | (uint32_t(a[2]) << 8) | a[3];
}
struct IPv4Prefix {
  uint32_t network, mask;
  bool contains(uint32_t address) const { return (address & mask) == network; }
  static IPv4Prefix parse(const std::string& text) {
    const auto slash = text.find('/');
    require(slash != std::string::npos && text.find('\0') == std::string::npos, "relay_policy_prefix");
    const auto ip = text.substr(0, slash), width = text.substr(slash + 1);
    require(!width.empty() && width.size() <= 2 && (width.size() == 1 || width[0] != '0'), "relay_policy_prefix");
    unsigned bits = 0;
    for (char c : width) { require(c >= '0' && c <= '9', "relay_policy_prefix"); bits = bits * 10 + c - '0'; }
    in_addr address{};
    require(bits <= 32 && inet_pton(AF_INET, ip.c_str(), &address) == 1, "relay_policy_prefix");
    const uint32_t value = ntohl(address.s_addr), mask = bits ? uint32_t(0xffffffff) << (32 - bits) : 0;
    require((value & mask) == value, "relay_policy_prefix"); return {value, mask};
  }
};

class DestinationPolicy {
  bool public_https_ = false;
  std::vector<Destination> allowed_;
  std::vector<IPv4Prefix> denied_;
  explicit DestinationPolicy(bool internet) : public_https_(internet) {}
  static void exclude_local(uint32_t target) {
    ifaddrs* raw = nullptr;
    require(getifaddrs(&raw) == 0, "relay_policy_interfaces");
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> addresses(raw, freeifaddrs);
    size_t seen = 0;
    for (auto* a = raw; a; a = a->ifa_next) {
      require(++seen <= 4096, "relay_policy_interfaces");
      if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
      const auto local = ntohl(reinterpret_cast<sockaddr_in*>(a->ifa_addr)->sin_addr.s_addr);
      require(target != local, "relay_destination_local");
      require(a->ifa_netmask && a->ifa_netmask->sa_family == AF_INET, "relay_policy_interfaces");
      const auto mask = ntohl(reinterpret_cast<sockaddr_in*>(a->ifa_netmask)->sin_addr.s_addr);
      // Reject malformed masks rather than interpreting a partial snapshot.
      const auto inverse = ~mask;
      require((inverse & (inverse + 1)) == 0, "relay_policy_interfaces");
      require((target & mask) != (local & mask), "relay_destination_local");
      if ((a->ifa_flags & IFF_POINTOPOINT) && a->ifa_dstaddr && a->ifa_dstaddr->sa_family == AF_INET)
        require(target != ntohl(reinterpret_cast<sockaddr_in*>(a->ifa_dstaddr)->sin_addr.s_addr), "relay_destination_local");
    }
  }
public:
  explicit DestinationPolicy(std::vector<Destination> allowed) : allowed_(std::move(allowed)) {
    require(!allowed_.empty() && allowed_.size() <= 64, "relay_policy_config");
    for (const auto& a : allowed_) require(a.port && a.ipv4[0] && a.ipv4[0] < 224, "relay_policy_config");
  }
  static DestinationPolicy public_https(const std::vector<std::string>& deny,
                                       const std::vector<std::array<uint8_t, 4>>& protected_ips = {}) {
    require(deny.size() <= 64 && protected_ips.size() <= 8, "relay_policy_config");
    DestinationPolicy out(true);
    // Conservative union of ALL IANA IPv4 Special-Purpose registry blocks
    // (snapshot checked 2026-10-07, registry revision 2025-10-09), including its
    // globally reachable exceptions. Additionally exclude multicast 224/4.
    // https://www.iana.org/assignments/iana-ipv4-special-registry/
    for (const char* prefix : {"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
         "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24",
         "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
         "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"})
      out.denied_.push_back(IPv4Prefix::parse(prefix));
    std::vector<IPv4Prefix> configured;
    for (const auto& text : deny) {
      auto p = IPv4Prefix::parse(text);
      for (const auto& previous : configured) require(previous.network != p.network || previous.mask != p.mask,
                                                      "relay_duplicate_prefix");
      configured.push_back(p); out.denied_.push_back(p);
    }
    for (const auto& ip : protected_ips) out.denied_.push_back({ipv4_number(ip), 0xffffffff});
    return out;
  }
  bool is_public_https() const { return public_https_; }
  void check(const Destination& dst) const {
    if (!public_https_) {
      require(std::find(allowed_.begin(), allowed_.end(), dst) != allowed_.end(), "relay_destination_denied"); return;
    }
    require(dst.port == 443, "relay_destination_port");
    const auto address = ipv4_number(dst.ipv4);
    for (const auto& p : denied_) require(!p.contains(address), "relay_destination_denied");
    // Fresh kernel interface snapshot on every admission, not only at startup.
    // Numeric destinations only: there is no DNS resolution/rebinding step.
    exclude_local(address);
  }
};
} // namespace cvpn::transparent
