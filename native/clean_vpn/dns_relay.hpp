#pragma once
#include "dns_wire.hpp"
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <mutex>
#include <array>
#include <algorithm>
namespace cvpn {
// Same fixed stub/upstreams as the existing DNS plan. Payload stays entirely
// native. SO_BINDTODEVICE is an extra constraint, not a substitute for guard.
class DnsRelay {
  using Time=std::chrono::steady_clock;
  struct Socket {int fd;explicit Socket(int n):fd(n){}~Socket(){if(fd>=0)close(fd);}Socket(const Socket&)=delete;};
  struct Job {uint32_t peer=0;std::atomic<bool> done{false};std::thread thread;~Job(){if(thread.joinable())thread.join();}};
  std::atomic<bool> stop_{false};std::atomic<bool>& ready_;std::atomic<bool>& failed_;std::string tun_,local_ip_;
  std::atomic<bool>* idle_;std::atomic<bool>* demand_;
  const bool private_bridge_;
  std::mutex peers_mutex_;std::set<uint32_t> peers_;
  static inline thread_local uint32_t request_peer_=0;
  bool permitted(uint32_t peer){if(!private_bridge_)return true;std::lock_guard<std::mutex> lock(peers_mutex_);return peers_.count(peer);}
  Socket udp_{-1},tcp_{-1};std::thread loop_;std::vector<std::unique_ptr<Job>> jobs_;
  static sockaddr_in address(const char* ip,unsigned port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);dns::need(inet_pton(AF_INET,ip,&a.sin_addr)==1);return a;}
  bool alive()const{return !stop_;}
  void wait(int fd,short events,Time::time_point end,bool upstream){
    while(alive()&&permitted(request_peer_)&&(!upstream||ready_)){
      dns::need(Time::now()<end);pollfd p{fd,events,0};int rc=poll(&p,1,25);dns::need(rc>=0||errno==EINTR);
      if(rc>0){dns::need(!(p.revents&(POLLNVAL|POLLERR)));if(p.revents&(events|POLLHUP))return;}
    }
    throw std::runtime_error("dns_cancelled");
  }
  void write_all(int fd,const uint8_t* p,size_t n,Time::time_point end,bool upstream){
    while(n){wait(fd,POLLOUT,end,upstream);ssize_t k=send(fd,p,n,MSG_NOSIGNAL);if(k<0&&(errno==EAGAIN||errno==EINTR))continue;dns::need(k>0);p+=k;n-=k;}
  }
  void write_frame(int fd,const Bytes& payload,Time::time_point end,bool upstream){
    // RFC 7766 section 8: offer length and message to TCP together, avoiding
    // a small prefix waiting for a delayed ACK before Nagle releases the body.
    // write_all still handles partial writes and cancellation; TCP may fragment.
    dns::need(payload.size()<=65535);Bytes frame(payload.size()+2);
    frame[0]=uint8_t(payload.size()>>8);frame[1]=uint8_t(payload.size());
    std::copy(payload.begin(),payload.end(),frame.begin()+2);
    write_all(fd,frame.data(),frame.size(),end,upstream);
  }
  void read_all(int fd,uint8_t* p,size_t n,Time::time_point end,bool upstream){
    while(n){wait(fd,POLLIN,end,upstream);ssize_t k=recv(fd,p,n,0);if(k<0&&(errno==EAGAIN||errno==EINTR))continue;dns::need(k>0);p+=k;n-=k;}
  }
  Bytes exchange(const Bytes& query,const char* server,unsigned port,bool tcp){
    dns::need(ready_);Socket s(socket(AF_INET,(tcp?SOCK_STREAM:SOCK_DGRAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0));dns::need(s.fd>=0);
    if(!private_bridge_)dns::need(setsockopt(s.fd,SOL_SOCKET,SO_BINDTODEVICE,tun_.c_str(),tun_.size()+1)==0);
    // Distinguish the native resolver from ordinary host DNS, which can use
    // the same TUN source address. The dedicated profile exempts only this mark
    // and the two fixed upstreams from DNS redirection. Never fall back unmarked.
    const uint32_t mark=0x43564e;
    if(!private_bridge_)dns::need(setsockopt(s.fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark))==0);
    auto local=address(private_bridge_?"127.0.0.1":local_ip_.c_str(),0),remote=address(server,port);dns::need(bind(s.fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0);
    // The private resolver is one authenticated hop across the tunnel. Its
    // budget includes TCP connect: one retransmission can consume >1.2s even
    // when the authoritative loopback answer itself takes only milliseconds.
    // The exit loopback bridge and fixed public upstream budgets stay short.
    const auto budget=std::chrono::milliseconds(!private_bridge_&&port==1055?3000:1200);
    auto end=Time::now()+budget;int rc=connect(s.fd,reinterpret_cast<sockaddr*>(&remote),sizeof(remote));dns::need(rc==0||errno==EINPROGRESS);
    wait(s.fd,POLLOUT,end,true);int error=0;socklen_t len=sizeof(error);dns::need(getsockopt(s.fd,SOL_SOCKET,SO_ERROR,&error,&len)==0&&!error);
    Bytes answer;
    if(tcp){
      write_frame(s.fd,query,end,true);uint8_t prefix[2];
      read_all(s.fd,prefix,2,end,true);size_t n=(size_t(prefix[0])<<8)|prefix[1];dns::need(n>=12);answer.resize(n);read_all(s.fd,answer.data(),n,end,true);
    }else{
      wait(s.fd,POLLOUT,end,true);dns::need(send(s.fd,query.data(),query.size(),0)==ssize_t(query.size()));wait(s.fd,POLLIN,end,true);
      answer.resize(4097);ssize_t n=recv(s.fd,answer.data(),answer.size(),0);dns::need(n>=12&&n<=4096);answer.resize(n);
    }
    auto r=dns::response(answer,query);dns::need(r.rcode!=2);return answer;
  }
  Bytes resolve(const Bytes& original,bool tcp){
    auto q=dns::parse(original,true);if(q.edns_version)return dns::failure(original,16);
    bool private_name;try{private_name=dns::private_peer_name(q.question);}catch(...){return dns::failure(original,1);}
    if(private_bridge_&&!private_name)return dns::failure(original,5);
    dns::need(permitted(request_peer_));
    if(!ready_&&idle_&&*idle_){
      *demand_=true;
      const auto end=Time::now()+std::chrono::seconds(3);
      while(alive()&&!ready_&&Time::now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    Bytes wire=original;dns::need(RAND_bytes(wire.data(),2)==1);
    const std::vector<const char*> servers=private_name?std::vector<const char*>{private_bridge_?"127.0.0.1":"10.99.0.1"}:std::vector<const char*>{"1.1.1.1","8.8.8.8"};
    for(const char* server:servers)try{
      auto answer=exchange(wire,server,private_name?1055:53,tcp);answer[0]=original[0];answer[1]=original[1];
      auto r=dns::response(answer,original);
      if(!tcp&&answer.size()>q.udp_size){auto short_answer=dns::failure(original,r.rcode,true);dns::put16(short_answer,2,0x8200|(r.flags&0x019f));return short_answer;}
      return answer;
    }catch(...){if(!alive())throw;}
    return dns::failure(original);
  }
  void tcp_client(int fd){
    Socket s(fd);auto end=Time::now()+std::chrono::seconds(10);
    try{for(unsigned requests=0;alive()&&permitted(request_peer_)&&requests<32;requests++){
      uint8_t prefix[2];read_all(s.fd,prefix,2,end,false);size_t n=(size_t(prefix[0])<<8)|prefix[1];dns::need(n>=12&&(!private_bridge_||n<=4096));
      Bytes query(n);read_all(s.fd,query.data(),n,end,false);auto answer=resolve(query,true);
      write_frame(s.fd,answer,end,false);
    }}catch(...){}
  }
  void run(){
    auto window=Time::now();unsigned admissions=0;std::array<unsigned,256> per_peer{};
    auto admit=[&](uint32_t peer){if(!private_bridge_)return true;
      if(Time::now()-window>=std::chrono::seconds(1)){window=Time::now();admissions=0;per_peer.fill(0);}
      const auto host=ntohl(peer);if((host&0xffffff00)!=0x0a630000||!permitted(peer)||admissions>=256||per_peer[host&255]>=64)return false;
      if(std::count_if(jobs_.begin(),jobs_.end(),[&](const auto& job){return job->peer==peer;})>=4)return false;
      admissions++;per_peer[host&255]++;return true;};
    while(alive()){
      for(auto i=jobs_.begin();i!=jobs_.end();)if((*i)->done)i=jobs_.erase(i);else ++i;
      pollfd p[]={{udp_.fd,POLLIN,0},{tcp_.fd,POLLIN,0}};if(poll(p,2,25)<=0)continue;
      if(p[0].revents&POLLIN){
        Bytes query(4097);sockaddr_in peer{};socklen_t len=sizeof(peer);ssize_t n=recvfrom(udp_.fd,query.data(),query.size(),0,reinterpret_cast<sockaddr*>(&peer),&len);
        if(n>=12&&n<=4096&&jobs_.size()<16&&admit(peer.sin_addr.s_addr)){query.resize(n);auto job=std::make_unique<Job>();job->peer=peer.sin_addr.s_addr;auto* done=&job->done;
          job->thread=std::thread([this,query=std::move(query),peer,done]{request_peer_=peer.sin_addr.s_addr;try{auto answer=resolve(query,false);if(alive()&&permitted(request_peer_))sendto(udp_.fd,answer.data(),answer.size(),MSG_NOSIGNAL,reinterpret_cast<const sockaddr*>(&peer),sizeof(peer));}catch(...){}*done=true;});jobs_.push_back(std::move(job));
        }
      }
      if(p[1].revents&POLLIN){sockaddr_in peer{};socklen_t length=sizeof(peer);int fd=accept4(tcp_.fd,reinterpret_cast<sockaddr*>(&peer),&length,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd>=0){
        if(jobs_.size()>=16||!admit(peer.sin_addr.s_addr))close(fd);else{Socket pending(fd);auto job=std::make_unique<Job>();job->peer=peer.sin_addr.s_addr;auto* done=&job->done;job->thread=std::thread([this,fd,done,peer]{request_peer_=peer.sin_addr.s_addr;tcp_client(fd);*done=true;});pending.fd=-1;jobs_.push_back(std::move(job));}
      }}
    }
    jobs_.clear();
  }
public:
  using Peers=std::set<uint32_t>;
  void replace_peers(Peers&& peers)noexcept{std::lock_guard<std::mutex> lock(peers_mutex_);peers_.swap(peers);}
  DnsRelay(const std::string& tun,std::atomic<bool>& ready,std::atomic<bool>& failed,
      std::atomic<bool>* idle=nullptr,std::atomic<bool>* demand=nullptr,const std::string& local_ip="10.99.0.2",bool private_bridge=false,Peers peers={}):
      ready_(ready),failed_(failed),tun_(tun),local_ip_(local_ip),idle_(idle),demand_(demand),private_bridge_(private_bridge),peers_(std::move(peers)){
    dns::need((idle==nullptr)==(demand==nullptr));
    jobs_.reserve(16);
    for(auto* s:{&udp_,&tcp_}){s->fd=socket(AF_INET,(s==&udp_?SOCK_DGRAM:SOCK_STREAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0);dns::need(s->fd>=0);
      if(s==&tcp_){int one=1;dns::need(setsockopt(s->fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);}
      if(private_bridge_)dns::need(setsockopt(s->fd,SOL_SOCKET,SO_BINDTODEVICE,tun_.c_str(),tun_.size()+1)==0);
      auto a=address(local_ip_.c_str(),private_bridge_?1055:1053);dns::need(bind(s->fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
    }
    dns::need(listen(tcp_.fd,16)==0);loop_=std::thread([this]{try{run();}catch(...){failed_=true;stop_=true;jobs_.clear();}});
  }
  ~DnsRelay(){stop_=true;if(loop_.joinable())loop_.join();}
};
}
