#pragma once
// Fixed-size, process-local counters. No destinations, ClientHello, keys or payload.
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <initializer_list>
namespace cvpn::transparent {
enum class RelayPhase : size_t { redirect, hello, authorization, connect, tls_prefix, stream, dispatch, internal, count };
inline constexpr std::array<const char*, size_t(RelayPhase::count)> relay_phase_names{
  "redirect", "client_hello", "authorization", "upstream_connect", "tls_prefix", "encrypted_stream", "dispatch", "internal"};
struct RelayFailureSnapshot {
  std::array<uint64_t, size_t(RelayPhase::count)> phases{};
  std::string last_code;
  RelayPhase last_phase=RelayPhase::internal;
  uint64_t last_monotonic_ms=0;
};
class RelayDiagnostics {
  std::array<std::atomic<uint64_t>, size_t(RelayPhase::count)> phases_{};
  mutable std::mutex mutex_;
  std::string last_code_;
  RelayPhase last_phase_=RelayPhase::internal;
  uint64_t last_monotonic_ms_=0;
public:
  void failure(RelayPhase phase, const char* reason) {
    const std::string code=reason?reason:"";
    bool safe=false;
    // An unknown exception, even one with a plausible prefix, cannot publish
    // arbitrary text. New reason codes require an explicit vocabulary update.
    for(const char* known : {
      "combo_accept", "combo_boring_queue", "combo_cancelled", "combo_config", "combo_endpoint",
      "combo_hello_eof", "combo_hello_limit", "combo_hello_timeout", "combo_listener", "combo_nonblocking",
      "combo_peek", "combo_poll", "combo_public_name", "combo_relay_limit", "combo_replay_required",
      "combo_role", "combo_sni", "combo_unknown_name", "hello_ciphers", "hello_compression",
      "hello_extension", "hello_extensions", "hello_incomplete", "hello_length", "hello_limit",
      "hello_reader_state", "hello_record", "hello_record_boundary", "hello_record_count", "hello_record_resize",
      "hello_replacement", "hello_session_id", "hello_sni", "hello_sni_missing", "hello_structure",
      "hello_type", "hello_versions", "queue_limit", "relay_accept", "relay_alert",
      "relay_cancelled", "relay_ccs", "relay_clock_rollback", "relay_config", "relay_config_fields",
      "relay_connect", "relay_crypto", "relay_destination", "relay_destination_denied", "relay_destination_local",
      "relay_destination_port", "relay_drain_timeout", "relay_duplicate_destination", "relay_duplicate_key", "relay_duplicate_prefix",
      "relay_endpoint_config", "relay_exit_required", "relay_failed", "relay_global_limit", "relay_handshake_eof",
      "relay_handshake_timeout", "relay_hello_binding", "relay_hello_eof", "relay_hello_limit", "relay_hello_state",
      "relay_idle_timeout", "relay_init_exit_only", "relay_interleaved_handshake", "relay_internal", "relay_lifetime_timeout",
      "relay_limits", "relay_listen_address", "relay_listener", "relay_listener_nonblocking", "relay_not_redirected",
      "relay_original_destination", "relay_peer_config", "relay_peer_id", "relay_peer_limit", "relay_peer_replay_exists_or_create_failed",
      "relay_peer_revoked", "relay_policy_config", "relay_policy_conflict", "relay_policy_interfaces", "relay_policy_prefix",
      "relay_poll", "relay_public_name", "relay_queue_limit", "relay_quota_config", "relay_record",
      "relay_record_count", "relay_record_type", "relay_recv", "relay_reload_replay_path_changed", "relay_replay_commit",
      "relay_replay_config", "relay_replay_corrupt", "relay_replay_directory", "relay_replay_exists", "relay_replay_failed",
      "relay_replay_file", "relay_replay_full", "relay_replay_locked", "relay_replay_path", "relay_replay_pending",
      "relay_replay_read", "relay_replay_scope_or_format", "relay_replay_sync", "relay_replay_write", "relay_replayed",
      "relay_retry_boundary", "relay_retry_identity", "relay_retry_sequence", "relay_retry_version", "relay_role",
      "relay_secret_path", "relay_self_destination", "relay_send", "relay_sequence", "relay_server_boundary",
      "relay_server_hello", "relay_server_version", "relay_shutdown", "relay_socket", "relay_socket_error",
      "relay_socket_option", "relay_socket_timeout", "relay_token_auth", "relay_token_encoding", "relay_token_expired",
      "relay_token_format", "relay_token_hostname", "relay_token_hostname_limit", "relay_token_suffix"
    })if(code==known){safe=true;break;}
    const size_t index=size_t(phase)<phases_.size()?size_t(phase):size_t(RelayPhase::internal);
    ++phases_[index];
    std::lock_guard<std::mutex> lock(mutex_);
    last_code_=safe?code:"relay_internal";last_phase_=RelayPhase(index);
    last_monotonic_ms_=uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
  }
  RelayFailureSnapshot snapshot() const {
    RelayFailureSnapshot s;
    for(size_t i=0;i<phases_.size();i++)s.phases[i]=phases_[i].load();
    std::lock_guard<std::mutex> lock(mutex_);
    s.last_code=last_code_;s.last_phase=last_phase_;s.last_monotonic_ms=last_monotonic_ms_;
    return s;
  }
};
} // namespace cvpn::transparent
