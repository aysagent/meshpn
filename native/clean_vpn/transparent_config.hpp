#pragma once
#include "transparent_socket.hpp"
#include <nlohmann/json.hpp>
#include <set>

namespace cvpn::transparent {
// Deliberately separate schema: the boring-tls TUN/certificate configuration
// cannot silently become a transparent proxy. Policy selection is explicit.
struct TransparentConfig {
  bool client;
  Destination listen, exit{};
  std::string public_name, secret_path, replay_directory;
  std::vector<Destination> destinations;
  bool public_https = false;
  std::vector<std::string> deny_ipv4;
  DestinationPolicy policy() const {
    if (!public_https) return DestinationPolicy(destinations);
    std::vector<std::array<uint8_t, 4>> protected_ips;
    if (ipv4_number(listen.ipv4)) protected_ips.push_back(listen.ipv4);
    if (client) protected_ips.push_back(exit.ipv4);
    return DestinationPolicy::public_https(deny_ipv4, protected_ips);
  }
  static Destination endpoint(const nlohmann::json& j) {
    require(j.is_object() && j.size() == 2 && j.contains("ipv4") && j.contains("port") &&
            j.at("ipv4").is_string() && j.at("port").is_number_integer(), "relay_endpoint_config");
    Destination d; in_addr addr{};
    const auto text = j.at("ipv4").get<std::string>(); const auto port = j.at("port").get<int64_t>();
    require(text.find('\0') == std::string::npos && inet_pton(AF_INET, text.c_str(), &addr) == 1 &&
            port > 0 && port <= 65535, "relay_endpoint_config");
    std::copy_n(reinterpret_cast<const uint8_t*>(&addr), 4, d.ipv4.begin()); d.port = port; return d;
  }
  explicit TransparentConfig(const nlohmann::json& j) {
    require(j.is_object() && j.at("version").is_number_integer() && j.at("version") == 1 &&
            j.at("transport") == "transparent-tls", "relay_config");
    const auto role = j.at("role").get<std::string>(); require(role == "client" || role == "exit", "relay_role");
    client = role == "client";
    require(j.contains("destinations") != j.contains("destination_policy"), "relay_policy_conflict");
    std::set<std::string> fields{"version","transport","role","listen","public_name","secret_path"};
    fields.insert(j.contains("destinations") ? "destinations" : "destination_policy");
    fields.insert(client ? "exit" : "replay_directory");
    require(j.size() == fields.size(), "relay_config_fields");
    for (const auto& field : fields) require(j.contains(field), "relay_config_fields");
    listen = endpoint(j.at("listen"));
    require(listen.ipv4[0] < 224, "relay_listen_address");
    public_name = j.at("public_name").get<std::string>(); require(hostname(public_name), "relay_public_name");
    secret_path = j.at("secret_path").get<std::string>();
    require(!secret_path.empty() && secret_path.front() == '/' && secret_path.find('\0') == std::string::npos, "relay_secret_path");
    if (j.contains("destinations")) {
      const auto& allowed = j.at("destinations"); require(allowed.is_array() && !allowed.empty() && allowed.size() <= 64, "relay_policy_config");
      for (const auto& a : allowed) {
        const auto dst = endpoint(a);
        require(std::find(destinations.begin(), destinations.end(), dst) == destinations.end(), "relay_duplicate_destination");
        require(!(dst == listen), "relay_self_destination"); destinations.push_back(dst);
      }
    } else {
      const auto& p = j.at("destination_policy");
      require(p.is_object() && p.size() == 2 && p.at("mode") == "public-https" &&
              p.at("deny_ipv4").is_array() && p.at("deny_ipv4").size() <= 64, "relay_policy_config");
      public_https = true;
      for (const auto& prefix : p.at("deny_ipv4")) deny_ipv4.push_back(prefix.get<std::string>());
    }
    if (client) {
      exit = endpoint(j.at("exit")); DestinationPolicy exit_policy({exit});
      require(!(exit == listen) && std::find(destinations.begin(), destinations.end(), exit) == destinations.end(), "relay_self_destination");
    } else {
      replay_directory = j.at("replay_directory").get<std::string>();
      require(replay_directory.size() > 1 && replay_directory.front() == '/' &&
              replay_directory.find('\0') == std::string::npos, "relay_replay_path");
    }
    (void)policy();
  }
};
} // namespace cvpn::transparent
