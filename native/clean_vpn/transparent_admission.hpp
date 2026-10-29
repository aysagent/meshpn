#pragma once
#include "transparent_auth.hpp"
#include <functional>

namespace cvpn::transparent {
// One independently provisioned key = one identity, even behind a shared NAT.
// Duplicate keys are forbidden. RAII releases quotas on every error/EOF path.
class ExitAdmission {
  struct Counts { std::mutex mutex; size_t total = 0; std::vector<size_t> peers; };
  struct Lease {
    std::shared_ptr<Counts> counts; size_t peer;
    Lease(std::shared_ptr<Counts> c, size_t p) : counts(std::move(c)), peer(p) {}
    ~Lease() { std::lock_guard<std::mutex> lock(counts->mutex); --counts->total; --counts->peers[peer]; }
  };
  struct Peer { std::shared_ptr<SniAuthorization> auth; std::shared_ptr<ReplayWindow> replay; };
  std::vector<Peer> peers_;
  std::shared_ptr<Counts> counts_ = std::make_shared<Counts>();
  size_t total_limit_, peer_limit_;
public:
  struct Session { AuthorizedHello hello; std::shared_ptr<void> lease; };
  ExitAdmission(size_t total, size_t per_peer) : total_limit_(total), peer_limit_(per_peer) {
    require(total && total <= 256 && per_peer && per_peer < total, "relay_quota_config");
  }
  // Only before listener startup; no concurrent mutation or live key reload.
  void add(std::shared_ptr<SniAuthorization> auth, std::shared_ptr<ReplayWindow> replay) {
    require(auth && replay && peers_.size() < 32, "relay_peer_config");
    for (const auto& p : peers_) require(p.auth->replay_scope() != auth->replay_scope(), "relay_duplicate_key");
    replay->check_scope(auth->replay_scope());
    peers_.push_back({std::move(auth),std::move(replay)}); counts_->peers.push_back(0);
  }
  template<class Clock> Session accept(const Hello& hello, const DestinationPolicy& policy, Clock clock) const {
    for (size_t i = 0; i < peers_.size(); ++i) {
      const auto& p = peers_[i];
      if (!p.auth->authenticates(hello)) continue;
      std::shared_ptr<Lease> lease;
      {
        std::lock_guard<std::mutex> lock(counts_->mutex);
        require(counts_->peers[i] < peer_limit_, "relay_peer_limit");
        require(counts_->total < total_limit_, "relay_global_limit");
        lease = std::make_shared<Lease>(counts_,i);
        ++counts_->total; ++counts_->peers[i];
      }
      // A full quota is rejected before disk I/O or origin connect. Authentication
      // alone never authorizes connect: binding, destination and durable replay
      // must all pass. An exception releases the temporary quota reservation.
      return {p.auth->accept(hello,policy,*p.replay,clock),std::move(lease)};
    }
    throw std::runtime_error("relay_token_auth");
  }
  size_t active() const { std::lock_guard<std::mutex> lock(counts_->mutex); return counts_->total; }
};
} // namespace cvpn::transparent
