#pragma once
#include "transparent_config.hpp"

namespace cvpn::transparent {
class RelayCredentials {
  const TransparentConfig& config_;
  std::vector<std::shared_ptr<SniAuthorization>> keys_;
  SniAuthorization inactive_;
  std::string directory(size_t i) const {
    return config_.replay_directory + (!config_.secret_path.empty() ? "" : "/" + config_.peers[i].id);
  }
public:
  template<class Read> RelayCredentials(const TransparentConfig& c, Read read) : config_(c), inactive_(Digest{},c.public_name) {
    const size_t count = !c.secret_path.empty() ? 1 : c.peers.size();
    for (size_t i=0; i<count; ++i) {
      auto bytes = read(!c.secret_path.empty() ? c.secret_path : c.peers[i].secret_path);
      struct Clean { std::string& b; ~Clean(){ OPENSSL_cleanse(b.data(),b.size()); } } clean{bytes};
      require(bytes.size()==32,"secret_length");
      Digest key{}; std::copy(bytes.begin(),bytes.end(),key.begin());
      struct CleanKey { Digest& b; ~CleanKey(){ OPENSSL_cleanse(b.data(),b.size()); } } clean_key{key};
      auto auth=std::make_shared<SniAuthorization>(key,c.public_name);
      for (const auto& previous:keys_) require(previous->replay_scope()!=auth->replay_scope(),"relay_duplicate_key");
      keys_.push_back(std::move(auth));
    }
  }
  const SniAuthorization& primary() const { return keys_.empty() ? inactive_ : *keys_.front(); }
  void initialize() const {
    require(!config_.client,"relay_init_exit_only");
    if (!config_.peers.empty()) {
      ReplayFd root(ReplayJournal::open_directory(config_.replay_directory));
      for (const auto& p:config_.peers) {
        require(mkdirat(root.get(),p.id.c_str(),0700)==0,"relay_peer_replay_exists_or_create_failed");
        require(fsync(root.get())==0,"relay_replay_commit");
      }
    }
    for (size_t i=0;i<keys_.size();++i) ReplayWindow state(directory(i),keys_[i]->replay_scope(),true);
  }
  ExitAdmission::Peers prepare(const ExitAdmission& active) const {
    require(!config_.client,"relay_exit_required");
    ExitAdmission::Peers next; next.reserve(keys_.size());
    for (size_t i=0;i<keys_.size();++i) {
      auto kept=active.retained(*keys_[i],directory(i));
      if (kept) next.push_back(std::move(kept));
      else next.push_back(std::make_shared<ExitAdmission::Peer>(keys_[i],
        std::make_shared<ReplayWindow>(directory(i),keys_[i]->replay_scope()),directory(i)));
    }
    return next;
  }
  std::shared_ptr<ExitAdmission> open() const {
    require(!config_.client,"relay_exit_required");
    auto admission=std::make_shared<ExitAdmission>(config_.limits.sessions,config_.limits.per_client);
    for (size_t i=0;i<keys_.size();++i)
      admission->add(keys_[i],std::make_shared<ReplayWindow>(directory(i),keys_[i]->replay_scope()),directory(i));
    return admission;
  }
};
} // namespace cvpn::transparent
