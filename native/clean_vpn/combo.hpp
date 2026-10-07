#pragma once
#include "transparent_config.hpp"
#include <deque>

namespace cvpn::combo {
namespace tr = cvpn::transparent;
enum class Branch { boring, transparent };
// Routing is deliberately not authentication. Reserved relay names NEVER
// fall back to TLS termination on malformed/expired/replayed authorization.
inline Branch classify(const tr::Hello& hello, const std::string& public_name) {
  const auto name = tr::lowercase(hello.sni), base = tr::lowercase(public_name);
  tr::require(tr::hostname(base), "combo_public_name");
  if (name == base) return Branch::boring;
  const auto suffix = "." + base;
  tr::require(name.size() > suffix.size() &&
    name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0, "combo_unknown_name");
  return Branch::transparent;
}

struct Config {
  nlohmann::json boring, transparent;
  tr::TransparentConfig relay;
  explicit Config(const nlohmann::json& j)
    : boring(j.at("boring")), transparent(j.at("transparent")), relay(transparent) {
    tr::require(j.is_object() && j.size() == 5 && j.at("version").is_number_integer() &&
      j.at("version") == 1 && j.at("transport") == "combo-tls", "combo_config");
    const auto role = j.at("role").get<std::string>();
    tr::require((role == "client" || role == "exit") && boring.at("role") == role &&
      transparent.at("role") == role, "combo_role");
    const auto endpoint = tr::TransparentConfig::endpoint({{"ipv4",boring.at("address")},{"port",boring.at("port")}});
    tr::require(endpoint == (relay.client ? relay.exit : relay.listen), "combo_endpoint");
    if (relay.client) tr::require(tr::lowercase(boring.value("sni",boring.at("server_name").get<std::string>())) ==
      tr::lowercase(relay.public_name), "combo_sni");
  }
};

// Leave ALL bytes in the socket. BoringSSL and the relay's admission gate must
// see the original stream, including coalesced records following ClientHello.
inline Branch peek(int fd, const std::string& name, uint64_t deadline, const std::atomic<bool>& stop) {
  tr::HelloReader reader; Bytes buffer(tr::hello_limit); size_t seen = 0;
  while (!stop.load()) {
    tr::require(tr::monotonic_ms() < deadline, "combo_hello_timeout");
    const auto n = recv(fd, buffer.data(), buffer.size(), MSG_PEEK | MSG_DONTWAIT);
    if (n < 0) tr::require(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR, "combo_peek");
    else {
      tr::require(n > 0 && size_t(n) >= seen, "combo_hello_eof");
      if (size_t(n) > seen) {
        const auto used = reader.feed(buffer.data() + seen, size_t(n) - seen); seen += used;
        if (reader.done()) return classify(reader.take(), name);
      }
      tr::require(seen < buffer.size(), "combo_hello_limit");
    }
    // A partial MSG_PEEK remains readable: polling POLLIN here would busy-spin.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("combo_cancelled");
}

// One external listener; descriptors move inside this C++ process only.
// Boring sessions stay in the existing multi-peer reactor. Relay workers use
// the existing durable admission + bounded queues, never an internal TCP proxy.
class Exit {
  struct Job { std::atomic<bool> done{false}; std::thread thread;
    ~Job() { if (thread.joinable()) thread.join(); } };
  tr::RelaySocket listener_;
  const tr::SniAuthorization& auth_;
  std::string name_;
  tr::DestinationPolicy policy_;
  std::shared_ptr<tr::ReplayWindow> replay_;
  tr::RelayLimits limits_;
  std::atomic<bool> stop_{false};
  std::atomic<size_t> peeking_{0}, relaying_{0};
  std::mutex mutex_;
  std::deque<std::unique_ptr<tr::RelaySocket>> boring_;
  std::vector<std::unique_ptr<Job>> jobs_;
  std::thread thread_;
  void run() {
    auto window = tr::monotonic_ms(); unsigned admissions = 0;
    while (!stop_) {
      for (auto it = jobs_.begin(); it != jobs_.end();) {
        if ((*it)->done) it = jobs_.erase(it); else ++it;
      }
      pollfd p{listener_.fd,POLLIN,0}; const int rc = poll(&p,1,25);
      tr::require(rc >= 0 || errno == EINTR, "combo_poll"); if (rc <= 0) continue;
      tr::require(!(p.revents & (POLLERR | POLLHUP | POLLNVAL)), "combo_listener");
      tr::RelaySocket accepted(accept4(listener_.fd,nullptr,nullptr,SOCK_NONBLOCK | SOCK_CLOEXEC));
      if (accepted.fd < 0) { tr::require(errno == EAGAIN || errno == EINTR, "combo_accept"); continue; }
      const auto now = tr::monotonic_ms();
      if (now - window >= 1000) { window = now; admissions = 0; }
      if (admissions >= 32 || peeking_ >= 16 || jobs_.size() >= 32) { ++dropped; continue; }
      ++admissions; ++peeking_;
      auto job = std::make_unique<Job>(); auto* done = &job->done; const int fd = accepted.fd;
      job->thread = std::thread([this, fd, done, now] {
        tr::RelaySocket socket(fd); bool pending = true, relay = false;
        try {
          const auto branch = peek(socket.fd,name_,now + limits_.hello_ms,stop_);
          --peeking_; pending = false;
          if (branch == Branch::boring) {
            std::lock_guard<std::mutex> lock(mutex_);
            tr::require(boring_.size() < 16, "combo_boring_queue");
            auto owned = std::make_unique<tr::RelaySocket>(socket.fd); socket.fd = -1;
            boring_.push_back(std::move(owned));
            ++boring_selected;
          } else {
            const auto previous = relaying_.fetch_add(1); relay = true;
            tr::require(previous < limits_.sessions, "combo_relay_limit");
            ++relay_selected;
            const int owned = socket.fd; socket.fd = -1;
            tr::relay_session(owned,false,auth_,{},{},policy_,*replay_,stop_,limits_);
          }
        } catch (...) { ++rejected; }
        if (pending) --peeking_;
        if (relay) --relaying_;
        *done = true;
      });
      accepted.fd = -1; jobs_.push_back(std::move(job));
    }
    jobs_.clear();
  }
public:
  std::atomic<bool> broken{false};
  std::atomic<uint64_t> boring_selected{0}, relay_selected{0}, rejected{0}, dropped{0};
  size_t pending() const { return peeking_.load(); }
  Exit(int fd, const tr::SniAuthorization& auth, std::string name, tr::DestinationPolicy policy,
       std::shared_ptr<tr::ReplayWindow> replay, tr::RelayLimits limits = {})
    : listener_(fd), auth_(auth), name_(std::move(name)), policy_(std::move(policy)),
      replay_(std::move(replay)), limits_(limits) {
    tr::require(bool(replay_), "combo_replay_required"); replay_->check_scope(auth_.replay_scope()); limits_.check();
    tr::require(tr::hostname(name_), "combo_public_name");
    const int flags = fcntl(fd,F_GETFL); tr::require(flags >= 0 && (flags & O_NONBLOCK), "combo_nonblocking");
    jobs_.reserve(32);
    thread_ = std::thread([this] { try { run(); } catch (...) { broken = true; stop_ = true; jobs_.clear(); } });
  }
  // Ownership transfers to reactor; empty is the same as nonblocking accept.
  int take_boring() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (boring_.empty()) { errno = EAGAIN; return -1; }
    auto socket = std::move(boring_.front()); boring_.pop_front();
    const int fd = socket->fd; socket->fd = -1; return fd;
  }
  ~Exit() { stop_ = true; if (thread_.joinable()) thread_.join(); }
};
} // namespace cvpn::combo
