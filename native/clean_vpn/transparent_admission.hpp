#pragma once
#include "transparent_auth.hpp"
#include <functional>
#include <atomic>

namespace cvpn::transparent {
// One independently provisioned key = one identity, even behind a shared NAT.
// Counts outlive revoked entries until their workers release their leases.
class ExitAdmission {
public:
  struct Peer {
    std::shared_ptr<SniAuthorization> auth;
    std::shared_ptr<ReplayWindow> replay;
    std::string tag;
    size_t active = 0;
    std::atomic<bool> revoked{false};
    Peer(std::shared_ptr<SniAuthorization> a, std::shared_ptr<ReplayWindow> r, std::string t)
      : auth(std::move(a)), replay(std::move(r)), tag(std::move(t)) {}
  };
  using Peers = std::vector<std::shared_ptr<Peer>>;
private:
  struct Counts { std::mutex mutex; size_t total = 0; };
  struct Lease {
    std::shared_ptr<Counts> counts; std::shared_ptr<Peer> peer;
    Lease(std::shared_ptr<Counts> c, std::shared_ptr<Peer> p) : counts(std::move(c)), peer(std::move(p)) {}
    ~Lease() { std::lock_guard<std::mutex> lock(counts->mutex); --counts->total; --peer->active; }
  };
  Peers peers_;
  std::shared_ptr<Counts> counts_ = std::make_shared<Counts>();
  size_t total_limit_, peer_limit_;
public:
  struct Session {
    AuthorizedHello hello;
    std::shared_ptr<void> lease;
    std::shared_ptr<const Peer> identity;
  };
  ExitAdmission(size_t total, size_t per_peer) : total_limit_(total), peer_limit_(per_peer) {
    require(total && total <= 256 && per_peer && per_peer < total, "relay_quota_config");
  }
  // Startup only. Live reload prepares a full candidate before replace().
  void add(std::shared_ptr<SniAuthorization> auth, std::shared_ptr<ReplayWindow> replay, std::string tag = {}) {
    require(auth && replay && peers_.size() < 32, "relay_peer_config");
    for (const auto& p : peers_) require(p->auth->replay_scope() != auth->replay_scope(), "relay_duplicate_key");
    replay->check_scope(auth->replay_scope());
    peers_.push_back(std::make_shared<Peer>(std::move(auth),std::move(replay),std::move(tag)));
  }
  std::shared_ptr<Peer> retained(const SniAuthorization& auth, const std::string& tag) const {
    std::lock_guard<std::mutex> lock(counts_->mutex);
    for (const auto& p : peers_) if (p->auth->replay_scope() == auth.replay_scope()) {
      require(p->tag == tag, "relay_reload_replay_path_changed"); return p;
    }
    return {};
  }
  // The callback MUST be noexcept, allocation-free and nonblocking. Packet
  // peers switch under this same admission lock for one combo transaction.
  template<class Commit> void replace(Peers next, Commit commit) {
    static_assert(noexcept(commit()), "reload_commit_must_be_noexcept");
    std::lock_guard<std::mutex> lock(counts_->mutex);
    commit();
    for (const auto& old : peers_)
      if (std::find(next.begin(),next.end(),old)==next.end()) old->revoked=true;
    peers_.swap(next);
  }
  void replace(Peers next) { replace(std::move(next),[]() noexcept {}); }
  template<class Clock> Session accept(const Hello& hello, const DestinationPolicy& policy, Clock clock) const {
    std::shared_ptr<Lease> lease;
    std::shared_ptr<Peer> matched;
    {
      std::lock_guard<std::mutex> lock(counts_->mutex);
      for (const auto& p : peers_) {
        if (!p->auth->authenticates(hello)) continue;
        require(p->active < peer_limit_, "relay_peer_limit");
        require(counts_->total < total_limit_, "relay_global_limit");
        lease=std::make_shared<Lease>(counts_,p); matched=p;
        ++counts_->total; ++p->active; break;
      }
    }
    require(bool(matched),"relay_token_auth");
    auto authorized=matched->auth->accept(hello,policy,*matched->replay,clock);
    require(!matched->revoked.load(),"relay_peer_revoked");
    return {std::move(authorized),std::move(lease),std::move(matched)};
  }
  size_t active() const { std::lock_guard<std::mutex> lock(counts_->mutex); return counts_->total; }
};
} // namespace cvpn::transparent
