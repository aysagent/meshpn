#pragma once
#include "transparent_hello.hpp"
#include <openssl/sha.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <map>
#include <memory>
#include <mutex>

namespace cvpn::transparent {
using Digest = std::array<uint8_t, 32>;
inline Digest digest(const Bytes& b) {
  Digest out{}; require(SHA256(b.data(), b.size(), out.data()) != nullptr, "relay_crypto"); return out;
}
constexpr uint64_t token_window_seconds = 30;
struct ReplayRecord { Digest id; uint64_t issued; };
struct ReplaySnapshot { uint64_t wall = 0; bool poisoned = false; std::vector<ReplayRecord> records; };

class ReplayFd {
  int fd_;
public:
  explicit ReplayFd(int fd) : fd_(fd) {}
  ~ReplayFd() { if (fd_ >= 0) close(fd_); }
  ReplayFd(const ReplayFd&) = delete;
  ReplayFd& operator=(const ReplayFd&) = delete;
  int get() const { return fd_; }
};

// A dedicated, caller-provisioned 0700 directory. A separate stable lock inode
// spans atomic snapshot replacements. Persist + fsync BEFORE authorizing connect.
// No reset/recovery of damaged or missing committed state. Root/owner rollback of
// the entire directory, hostile storage and dishonest fsync are outside scope.
class ReplayJournal {
  static constexpr size_t maximum_bytes = 89 + 4096 * 40;
  ReplayFd dir_, lock_;
  Digest scope_;
  static int directory(const std::string& path) {
    require(path.size() > 1 && path.front() == '/' && path.back() != '/', "relay_replay_path");
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0, "relay_replay_directory");
    try {
      // The system owner can be an unmapped uid inside an isolated user
      // namespace. Trust the namespace's root-directory owner, not literal 0.
      struct stat root{}; require(fstat(fd, &root) == 0, "relay_replay_directory");
      for (size_t at = 1; at < path.size();) {
        const auto end = path.find('/', at);
        const auto name = path.substr(at, end == std::string::npos ? end : end - at);
        require(!name.empty() && name != "." && name != "..", "relay_replay_path");
        const int next = openat(fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        require(next >= 0, "relay_replay_directory"); close(fd); fd = next;
        struct stat st{};
        require(fstat(fd, &st) == 0 && (st.st_uid == geteuid() || st.st_uid == root.st_uid), "relay_replay_directory");
        const bool leaf = end == std::string::npos;
        require(leaf ? st.st_uid == geteuid() && (st.st_mode & 07777) == 0700 :
                !(st.st_mode & 0022) || (st.st_uid == root.st_uid && (st.st_mode & S_ISVTX)), "relay_replay_directory");
        if (leaf) return fd;
        at = end + 1;
      }
    } catch (...) { close(fd); throw; }
    close(fd); throw std::runtime_error("relay_replay_path");
  }
  static void regular(int fd) {
    struct stat st{};
    require(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
            (st.st_mode & 07777) == 0600 && st.st_nlink == 1 && st.st_size >= 0 &&
            uint64_t(st.st_size) <= maximum_bytes, "relay_replay_file");
  }
  static void put_number(Bytes& b, uint64_t n) { for (int i = 7; i >= 0; --i) b.push_back(n >> (8 * i)); }
  static uint64_t get_number(const Bytes& b, size_t at) {
    require(at <= b.size() && b.size() - at >= 8, "relay_replay_corrupt");
    uint64_t n = 0; for (size_t i = 0; i < 8; ++i) n = (n << 8) | b[at + i]; return n;
  }
  int lock_file(bool initialize) {
    const int fd = openat(dir_.get(), "lock", O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC |
                        (initialize ? O_CREAT | O_EXCL : 0), 0600);
    try {
      regular(fd); require(flock(fd, LOCK_EX | LOCK_NB) == 0, "relay_replay_locked");
      struct stat st{}; require(fstat(fd, &st) == 0 && st.st_size == 0, "relay_replay_file");
    } catch (...) { if (fd >= 0) close(fd); throw; }
    return fd;
  }
  void discard_pending() {
    const int fd = openat(dir_.get(), "pending", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { require(errno == ENOENT, "relay_replay_pending"); return; }
    ReplayFd pending(fd); regular(fd);
    require(unlinkat(dir_.get(), "pending", 0) == 0, "relay_replay_pending");
  }
public:
#ifdef CVPN_TEST_REPLAY_JOURNAL
  inline static void (*fault_hook)(const char*) = nullptr;
#endif
  const Digest& scope() const { return scope_; }
  ReplayJournal(const std::string& path, const Digest& scope, bool initialize = false)
      : dir_(directory(path)), lock_(lock_file(initialize)), scope_(scope) {
    if (initialize) {
      struct stat st{};
      require(fstatat(dir_.get(), "state", &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT,
              "relay_replay_exists");
      require(fstatat(dir_.get(), "pending", &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT,
              "relay_replay_pending");
      save({});
    }
  }
  ReplaySnapshot load() {
    ReplayFd fd(openat(dir_.get(), "state", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    regular(fd.get()); Bytes b; std::array<uint8_t, 4096> chunk{};
    for (;;) {
      const auto n = read(fd.get(), chunk.data(), chunk.size());
      if (n < 0 && errno == EINTR) continue;
      require(n >= 0, "relay_replay_read"); if (!n) break;
      require(b.size() + size_t(n) <= maximum_bytes, "relay_replay_corrupt");
      b.insert(b.end(), chunk.begin(), chunk.begin() + n);
    }
    const Bytes magic{'C','V','R','P','L','Y','0','1'};
    require(b.size() >= 89 && std::equal(magic.begin(), magic.end(), b.begin()) &&
            std::equal(scope_.begin(), scope_.end(), b.begin() + 8), "relay_replay_scope_or_format");
    const auto hash = digest(Bytes(b.begin(), b.end() - 32));
    require(std::equal(hash.begin(), hash.end(), b.end() - 32), "relay_replay_corrupt");
    ReplaySnapshot out; out.wall = get_number(b, 40); const auto count = get_number(b, 48);
    require(count <= 4096 && b[56] <= 1 && b.size() == 89 + count * 40, "relay_replay_corrupt");
    out.poisoned = b[56];
    for (size_t i = 0; i < count; ++i) {
      ReplayRecord r{}; std::copy_n(b.begin() + 57 + i * 40, 32, r.id.begin());
      r.issued = get_number(b, 89 + i * 40); out.records.push_back(r);
    }
    // A killed writer may leave only an uncommitted temporary. The committed
    // state must validate first; never promote a temporary or recreate state.
    discard_pending(); return out;
  }
  void save(const ReplaySnapshot& snapshot) {
    require(snapshot.records.size() <= 4096, "relay_replay_full");
    Bytes b{'C','V','R','P','L','Y','0','1'}; b.insert(b.end(), scope_.begin(), scope_.end());
    put_number(b, snapshot.wall); put_number(b, snapshot.records.size()); b.push_back(snapshot.poisoned);
    for (const auto& r : snapshot.records) { b.insert(b.end(), r.id.begin(), r.id.end()); put_number(b, r.issued); }
    auto hash = digest(b); b.insert(b.end(), hash.begin(), hash.end());
    ReplayFd fd(openat(dir_.get(), "pending", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    regular(fd.get());
#ifdef CVPN_TEST_REPLAY_JOURNAL
    if (fault_hook) fault_hook("opened");
#endif
    for (size_t at = 0; at < b.size();) {
      const auto n = write(fd.get(), b.data() + at, b.size() - at);
      if (n < 0 && errno == EINTR) continue;
      require(n > 0, "relay_replay_write"); at += n;
    }
#ifdef CVPN_TEST_REPLAY_JOURNAL
    if (fault_hook) fault_hook("written");
#endif
    require(fsync(fd.get()) == 0, "relay_replay_sync");
#ifdef CVPN_TEST_REPLAY_JOURNAL
    if (fault_hook) fault_hook("synced");
#endif
    require(renameat(dir_.get(), "pending", dir_.get(), "state") == 0, "relay_replay_commit");
#ifdef CVPN_TEST_REPLAY_JOURNAL
    if (fault_hook) fault_hook("renamed");
#endif
    require(fsync(dir_.get()) == 0, "relay_replay_commit");
#ifdef CVPN_TEST_REPLAY_JOURNAL
    if (fault_hook) fault_hook("committed");
#endif
  }
};

// Shared by all sessions of one exit/key. Memory mode is for isolated fixtures;
// a durable exit must supply a journal scoped to its key and public name.
class ReplayWindow {
  struct Entry { uint64_t issued, monotonic; };
  std::map<Digest, Entry> used_;
  size_t capacity_;
  uint64_t last_wall_ = 0, last_mono_ = 0;
  bool failed_ = false, reloaded_ = false;
  std::unique_ptr<ReplayJournal> journal_;
  std::mutex mutex_;
  void checkpoint() {
    if (!journal_) return;
    ReplaySnapshot s; s.wall = last_wall_; s.poisoned = failed_;
    for (const auto& [id, e] : used_) s.records.push_back({id, e.issued});
    try { journal_->save(s); } catch (...) { failed_ = true; throw; }
  }
public:
  bool durable() const { return bool(journal_); }
  void check_scope(const Digest& scope) const {
    require(!journal_ || journal_->scope() == scope, "relay_replay_scope_or_format");
  }
  explicit ReplayWindow(size_t capacity = 4096) : capacity_(capacity) {
    require(capacity && capacity <= 4096, "relay_replay_config");
  }
  ReplayWindow(const std::string& directory, const Digest& scope, bool initialize = false, size_t capacity = 4096)
      : ReplayWindow(capacity) {
    journal_ = std::make_unique<ReplayJournal>(directory, scope, initialize);
    const auto s = journal_->load(); last_wall_ = s.wall; failed_ = s.poisoned; reloaded_ = true;
    require(!failed_, "relay_clock_rollback");
    for (const auto& r : s.records) require(used_.emplace(r.id, Entry{r.issued, 0}).second, "relay_replay_corrupt");
    require(used_.size() <= capacity_, "relay_replay_full");
  }
  template<class Clock> void consume(const Digest& id, uint64_t issued, Clock clock) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto [wall, mono] = clock();
    require(!failed_, "relay_replay_failed");
    if (wall < last_wall_ || mono < last_mono_) {
      failed_ = true; checkpoint(); throw std::runtime_error("relay_clock_rollback");
    }
    last_wall_ = wall; last_mono_ = mono;
    if (reloaded_) {
      // Restart/reboot never trusts a previous boot's monotonic epoch. Keep
      // every loaded record for another 61 s, even if its wall validity ended.
      for (auto& item : used_) item.second.monotonic = mono;
      reloaded_ = false;
    }
    require(issued <= wall ? wall - issued <= token_window_seconds : issued - wall <= token_window_seconds,
            "relay_token_expired");
    for (auto it = used_.begin(); it != used_.end();) {
      const auto e = it->second;
      if (wall > e.issued && wall - e.issued > token_window_seconds &&
          mono >= e.monotonic && mono - e.monotonic > 61000) it = used_.erase(it);
      else ++it;
    }
    require(!used_.count(id), "relay_replayed");
    require(used_.size() < capacity_, "relay_replay_full"); used_.emplace(id, Entry{issued, mono});
    checkpoint();
  }
};
} // namespace cvpn::transparent
