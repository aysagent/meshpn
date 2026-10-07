#include "transparent_auth.hpp"
#include <sys/wait.h>
#include <signal.h>
#include <filesystem>
#include <iostream>
#include <thread>
#include <atomic>

using namespace cvpn;
using namespace cvpn::transparent;
static void need(bool ok, int line = __builtin_LINE()) {
  if (!ok) throw std::runtime_error("replay_test_line_" + std::to_string(line));
}
template<class F> static void reject(F f, const std::string& code = {}) {
  bool failed = false;
  try { f(); } catch (const std::runtime_error& e) { failed = true; if (!code.empty()) need(code == e.what()); }
  need(failed);
}
struct Temp {
  std::string path;
  Temp() { char p[] = "/tmp/cvpn-replay-XXXXXX"; const char* result = mkdtemp(p); need(result); path = result; }
  ~Temp() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
};
static Digest id(uint8_t n) { Digest d{}; d[0] = n; return d; }
static auto clock_at(uint64_t wall, uint64_t mono) { return [=] { return std::make_pair(wall, mono); }; }
static void fixture_file(const std::string& path, const Bytes& b) {
  ReplayFd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)); need(fd.get() >= 0);
  need(write(fd.get(), b.data(), b.size()) == ssize_t(b.size()));
}
static const char* crash_stage = nullptr;
static void crash_at(const char* stage) { if (std::string(stage) == crash_stage) kill(getpid(), SIGKILL); }
static void crash_tests(const Digest& scope) {
  for (const char* stage : {"opened", "written", "synced", "renamed", "committed", "returned"}) {
    Temp dir;
    { ReplayWindow replay(dir.path, scope, true); replay.consume(id(1), 1000, clock_at(1000, 100)); }
    const auto child = fork(); need(child >= 0);
    if (!child) {
      try {
        ReplayWindow replay(dir.path, scope);
        crash_stage = stage; ReplayJournal::fault_hook = crash_at;
        replay.consume(id(2), 1000, clock_at(1000, 200));
        crash_at("returned");
      } catch (...) { _exit(3); }
      _exit(4);
    }
    int status = 0; need(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    ReplayWindow replay(dir.path, scope);
    reject([&] { replay.consume(id(1), 1000, clock_at(1000, 1)); }, "relay_replayed");
    if (std::string(stage) == "renamed" || std::string(stage) == "committed" || std::string(stage) == "returned")
      reject([&] { replay.consume(id(2), 1000, clock_at(1000, 2)); }, "relay_replayed");
    else replay.consume(id(2), 1000, clock_at(1000, 2)); // never returned authorization
    need(!std::filesystem::exists(dir.path + "/pending"));
  }
}
int main() {
  try {
    Digest key{}; key.fill(0x42); SniAuthorization auth(key, "relay.example"); const auto scope = auth.replay_scope();
    const auto different = SniAuthorization(id(9), "relay.example").replay_scope();
    need(scope != different && scope != SniAuthorization(key, "other.example").replay_scope());
    Temp dir;
    reject([&] { ReplayWindow missing(dir.path, scope); });
    {
      ReplayWindow replay(dir.path, scope, true, 2); need(replay.durable());
      replay.consume(id(1), 1000, clock_at(1000, 100));
      reject([&] { ReplayWindow duplicate(dir.path, scope); }, "relay_replay_locked");
      reject([&] { ReplayWindow reset(dir.path, scope, true); });
      reject([&] { replay.check_scope(different); }, "relay_replay_scope_or_format");
      std::atomic<unsigned> admitted{0}; std::vector<std::thread> threads;
      for (int i = 0; i < 16; ++i) threads.emplace_back([&] {
        try { replay.consume(id(2), 1000, clock_at(1000, 101)); ++admitted; } catch (...) {}
      });
      for (auto& t : threads) t.join();
      need(admitted == 1);
      reject([&] { replay.consume(id(3), 1000, clock_at(1000, 102)); }, "relay_replay_full");
    }
    reject([&] { ReplayWindow wrong(dir.path, different); }, "relay_replay_scope_or_format");
    {
      ReplayWindow replay(dir.path, scope, false, 2);
      reject([&] { replay.consume(id(1), 1000, clock_at(1000, 1)); }, "relay_replayed");
      reject([&] { replay.consume(id(3), 1100, clock_at(1100, 2)); }, "relay_replay_full");
      reject([&] { replay.consume(id(3), 1100, clock_at(1100, 61001)); }, "relay_replay_full");
      replay.consume(id(3), 1100, clock_at(1100, 61002));
    }
    {
      ReplayWindow replay(dir.path, scope);
      reject([&] { replay.consume(id(4), 1099, clock_at(1099, 1)); }, "relay_clock_rollback");
    }
    reject([&] { ReplayWindow poisoned(dir.path, scope); }, "relay_clock_rollback");
    crash_tests(scope);
    // Filesystem failures must not return admission; the live instance remains
    // failed even when storage is repaired. Only validated restart can resume.
    {
      Temp d;
      {
        ReplayWindow replay(d.path, scope, true); fixture_file(d.path + "/pending", {});
        reject([&] { replay.consume(id(1), 1000, clock_at(1000, 1)); });
        need(unlink((d.path + "/pending").c_str()) == 0);
        reject([&] { replay.consume(id(2), 1000, clock_at(1000, 2)); }, "relay_replay_failed");
      }
      ReplayWindow replay(d.path, scope); replay.consume(id(1), 1000, clock_at(1000, 1));
    }
    for (const std::string fault : {"missing", "corrupt", "truncated", "symlink", "hardlink", "mode", "directory", "pending-symlink"}) {
      Temp d; { ReplayWindow replay(d.path, scope, true); replay.consume(id(1), 1000, clock_at(1000, 1)); }
      const auto state = d.path + "/state";
      if (fault == "missing" || fault == "symlink" || fault == "directory") need(unlink(state.c_str()) == 0);
      if (fault == "symlink") { fixture_file(d.path + "/other", {}); need(symlink("other", state.c_str()) == 0); }
      if (fault == "pending-symlink") need(symlink("state", (d.path + "/pending").c_str()) == 0);
      if (fault == "hardlink") need(link(state.c_str(), (d.path + "/other").c_str()) == 0);
      if (fault == "mode") need(chmod(state.c_str(), 0644) == 0);
      if (fault == "directory") need(mkdir(state.c_str(), 0700) == 0);
      if (fault == "corrupt" || fault == "truncated") {
        ReplayFd fd(open(state.c_str(), O_WRONLY)); need(fd.get() >= 0);
        if (fault == "corrupt") { uint8_t b = 7; need(pwrite(fd.get(), &b, 1, 60) == 1); }
        else need(ftruncate(fd.get(), 88) == 0);
      }
      reject([&] { ReplayWindow replay(d.path, scope); });
    }
    {
      Temp d; need(chmod(d.path.c_str(), 0755) == 0);
      reject([&] { ReplayWindow replay(d.path, scope, true); }, "relay_replay_directory");
    }
    std::cout << "native transparent durable replay PASS: restart, 6 SIGKILL boundaries, scoped key, clock poison, concurrency, bounded retention, corrupt/missing/unsafe storage\n";
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
