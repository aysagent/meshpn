#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <signal.h>
#include <pthread.h>
#include <stdexcept>

// One invocation per worker thread. JNI owns the lifetime; the engine borrows
// the TUN and duplicates it. No process signals, stdio, routes or DNS listeners.
namespace cvpn {
struct AndroidRuntime {
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> network_generation{0};
  std::atomic<bool> running{false};
  int tun_fd=-1;
  std::function<bool(int)> protect;
  std::function<void(const std::string&)> event;
};
extern thread_local AndroidRuntime* android_runtime;
// BoringSSL's socket BIO uses send(..., 0). Suppress SIGPIPE only on the
// calling worker, never change ART's process-wide signal dispositions.
class AndroidSigpipeGuard {
  sigset_t old_, pipe_;
public:
  AndroidSigpipeGuard(){
    sigemptyset(&pipe_);sigaddset(&pipe_,SIGPIPE);
    if(pthread_sigmask(SIG_BLOCK,&pipe_,&old_)!=0)throw std::runtime_error("signal_mask");
  }
  ~AndroidSigpipeGuard(){
    if(!sigismember(&old_,SIGPIPE)){timespec zero{};while(sigtimedwait(&pipe_,nullptr,&zero)>=0){}}
    pthread_sigmask(SIG_SETMASK,&old_,nullptr);
  }
};
}
int cvpn_android_main(int argc, char** argv);
