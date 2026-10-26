#pragma once
#ifndef CVPN_TEST_PACKET_FD
#error Test-only H2 budget instrumentation
#endif
#include "protocol.hpp"
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <string>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <linux/sock_diag.h>
namespace cvpn::h2_budget_fixture {
inline bool enabled(){return std::getenv("CVPN_TEST_H2_BUDGET")!=nullptr;}
inline bool browser_credit(){
  const char* value=std::getenv("CVPN_TEST_H2_BUDGET");
  if(!value)return false;
  const std::string mode(value);
  if(mode!="baseline"&&mode!="browser-credit")throw std::runtime_error("fixture_budget_mode");
  return mode=="browser-credit";
}
struct Queues;
inline std::vector<const Queues*> live;
inline uint64_t created=0,destroyed=0;
struct Queues {
  const Queue &outgoing,&network,&packets;
  SSL* ssl;
  Queues(const Queue& o,const Queue& n,const Queue& p,SSL* s):outgoing(o),network(n),packets(p),ssl(s){
    if(enabled()){live.push_back(this);created++;}
  }
  ~Queues(){if(enabled()){live.erase(std::remove(live.begin(),live.end(),this),live.end());destroyed++;}}
  Queues(const Queues&)=delete;Queues& operator=(const Queues&)=delete;
};
inline nlohmann::json status(){
  size_t outgoing=0,network=0,packets=0,largest=0;
  uint64_t tcp_receive=0,tcp_send=0,socket_samples=0;
  for(const auto* q:live){
    outgoing+=q->outgoing.size();network+=q->network.size();packets+=q->packets.size();
    largest=std::max({largest,q->outgoing.size(),q->network.size(),q->packets.size()});
    uint32_t memory[SK_MEMINFO_VARS]{};socklen_t length=sizeof(memory);
    if(getsockopt(SSL_get_fd(q->ssl),SOL_SOCKET,SO_MEMINFO,memory,&length)==0&&length==sizeof(memory)){
      tcp_receive+=memory[SK_MEMINFO_RMEM_ALLOC];tcp_send+=memory[SK_MEMINFO_WMEM_QUEUED];socket_samples++;
    }
  }
  return {{"live_sessions",live.size()},{"created",created},{"destroyed",destroyed},
    {"outgoing_bytes",outgoing},{"network_bytes",network},{"packet_bytes",packets},
    {"largest_queue_bytes",largest},{"per_queue_limit",queue_limit},
    {"tcp_receive_alloc_bytes",tcp_receive},{"tcp_send_queued_bytes",tcp_send},{"socket_memory_samples",socket_samples}};
}
}
