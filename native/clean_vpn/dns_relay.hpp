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
namespace cvpn {
// Same fixed stub/upstreams as the existing DNS plan. Payload stays entirely
// native. SO_BINDTODEVICE is an extra constraint, not a substitute for guard.
class DnsRelay {
  using Time=std::chrono::steady_clock;
  struct Socket {int fd;explicit Socket(int n):fd(n){}~Socket(){if(fd>=0)close(fd);}Socket(const Socket&)=delete;};
  struct Job {std::atomic<bool> done{false};std::thread thread;~Job(){if(thread.joinable())thread.join();}};
  std::atomic<bool> stop_{false};std::atomic<bool>& ready_;std::atomic<bool>& failed_;std::string tun_,local_ip_;
  std::atomic<bool>* idle_;std::atomic<bool>* demand_;
  Socket udp_{-1},tcp_{-1};std::thread loop_;std::vector<std::unique_ptr<Job>> jobs_;
  static sockaddr_in address(const char* ip,unsigned port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);dns::need(inet_pton(AF_INET,ip,&a.sin_addr)==1);return a;}
  bool alive()const{return !stop_;}
  void wait(int fd,short events,Time::time_point end,bool upstream){
    while(alive()&&(!upstream||ready_)){
      dns::need(Time::now()<end);pollfd p{fd,events,0};int rc=poll(&p,1,25);dns::need(rc>=0||errno==EINTR);
      if(rc>0){dns::need(!(p.revents&(POLLNVAL|POLLERR)));if(p.revents&(events|POLLHUP))return;}
    }
    throw std::runtime_error("dns_cancelled");
  }
  void write_all(int fd,const uint8_t* p,size_t n,Time::time_point end,bool upstream){
    while(n){wait(fd,POLLOUT,end,upstream);ssize_t k=send(fd,p,n,MSG_NOSIGNAL);if(k<0&&(errno==EAGAIN||errno==EINTR))continue;dns::need(k>0);p+=k;n-=k;}
  }
  void read_all(int fd,uint8_t* p,size_t n,Time::time_point end,bool upstream){
    while(n){wait(fd,POLLIN,end,upstream);ssize_t k=recv(fd,p,n,0);if(k<0&&(errno==EAGAIN||errno==EINTR))continue;dns::need(k>0);p+=k;n-=k;}
  }
  Bytes exchange(const Bytes& query,const char* server,bool tcp){
    dns::need(ready_);Socket s(socket(AF_INET,(tcp?SOCK_STREAM:SOCK_DGRAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0));dns::need(s.fd>=0);
    dns::need(setsockopt(s.fd,SOL_SOCKET,SO_BINDTODEVICE,tun_.c_str(),tun_.size()+1)==0);
    auto local=address(local_ip_.c_str(),0),remote=address(server,53);dns::need(bind(s.fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0);
    auto end=Time::now()+std::chrono::milliseconds(1200);int rc=connect(s.fd,reinterpret_cast<sockaddr*>(&remote),sizeof(remote));dns::need(rc==0||errno==EINPROGRESS);
    wait(s.fd,POLLOUT,end,true);int error=0;socklen_t len=sizeof(error);dns::need(getsockopt(s.fd,SOL_SOCKET,SO_ERROR,&error,&len)==0&&!error);
    Bytes answer;
    if(tcp){
      uint8_t prefix[]={uint8_t(query.size()>>8),uint8_t(query.size())};write_all(s.fd,prefix,2,end,true);write_all(s.fd,query.data(),query.size(),end,true);
      read_all(s.fd,prefix,2,end,true);size_t n=(size_t(prefix[0])<<8)|prefix[1];dns::need(n>=12);answer.resize(n);read_all(s.fd,answer.data(),n,end,true);
    }else{
      wait(s.fd,POLLOUT,end,true);dns::need(send(s.fd,query.data(),query.size(),0)==ssize_t(query.size()));wait(s.fd,POLLIN,end,true);
      answer.resize(4097);ssize_t n=recv(s.fd,answer.data(),answer.size(),0);dns::need(n>=12&&n<=4096);answer.resize(n);
    }
    auto r=dns::response(answer,query);dns::need(r.rcode!=2);return answer;
  }
  Bytes resolve(const Bytes& original,bool tcp){
    auto q=dns::parse(original,true);if(q.edns_version)return dns::failure(original,16);
    if(!ready_&&idle_&&*idle_){
      *demand_=true;
      const auto end=Time::now()+std::chrono::seconds(3);
      while(alive()&&!ready_&&Time::now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    Bytes wire=original;dns::need(RAND_bytes(wire.data(),2)==1);
    for(const char* server:{"1.1.1.1","8.8.8.8"})try{
      auto answer=exchange(wire,server,tcp);answer[0]=original[0];answer[1]=original[1];
      auto r=dns::response(answer,original);
      if(!tcp&&answer.size()>q.udp_size){auto short_answer=dns::failure(original,r.rcode,true);dns::put16(short_answer,2,0x8200|(r.flags&0x019f));return short_answer;}
      return answer;
    }catch(...){if(!alive())throw;}
    return dns::failure(original);
  }
  void tcp_client(int fd){
    Socket s(fd);auto end=Time::now()+std::chrono::seconds(10);
    try{while(alive()){
      uint8_t prefix[2];read_all(s.fd,prefix,2,end,false);size_t n=(size_t(prefix[0])<<8)|prefix[1];dns::need(n>=12);
      Bytes query(n);read_all(s.fd,query.data(),n,end,false);auto answer=resolve(query,true);prefix[0]=answer.size()>>8;prefix[1]=answer.size();
      write_all(s.fd,prefix,2,end,false);write_all(s.fd,answer.data(),answer.size(),end,false);
    }}catch(...){}
  }
  void run(){
    while(alive()){
      for(auto i=jobs_.begin();i!=jobs_.end();)if((*i)->done)i=jobs_.erase(i);else ++i;
      pollfd p[]={{udp_.fd,POLLIN,0},{tcp_.fd,POLLIN,0}};if(poll(p,2,25)<=0)continue;
      if(p[0].revents&POLLIN){
        Bytes query(4097);sockaddr_in peer{};socklen_t len=sizeof(peer);ssize_t n=recvfrom(udp_.fd,query.data(),query.size(),0,reinterpret_cast<sockaddr*>(&peer),&len);
        if(n>=12&&n<=4096&&jobs_.size()<16){query.resize(n);auto job=std::make_unique<Job>();auto* done=&job->done;
          job->thread=std::thread([this,query=std::move(query),peer,done]{try{auto answer=resolve(query,false);if(alive())sendto(udp_.fd,answer.data(),answer.size(),MSG_NOSIGNAL,reinterpret_cast<const sockaddr*>(&peer),sizeof(peer));}catch(...){}*done=true;});jobs_.push_back(std::move(job));
        }
      }
      if(p[1].revents&POLLIN){int fd=accept4(tcp_.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd>=0){
        if(jobs_.size()>=16)close(fd);else{Socket pending(fd);auto job=std::make_unique<Job>();auto* done=&job->done;job->thread=std::thread([this,fd,done]{tcp_client(fd);*done=true;});pending.fd=-1;jobs_.push_back(std::move(job));}
      }}
    }
    jobs_.clear();
  }
public:
  DnsRelay(const std::string& tun,std::atomic<bool>& ready,std::atomic<bool>& failed,
      std::atomic<bool>* idle=nullptr,std::atomic<bool>* demand=nullptr,const std::string& local_ip="10.99.0.2"):
      ready_(ready),failed_(failed),tun_(tun),local_ip_(local_ip),idle_(idle),demand_(demand){
    dns::need((idle==nullptr)==(demand==nullptr));
    jobs_.reserve(16);
    for(auto* s:{&udp_,&tcp_}){s->fd=socket(AF_INET,(s==&udp_?SOCK_DGRAM:SOCK_STREAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0);dns::need(s->fd>=0);
      if(s==&tcp_){int one=1;dns::need(setsockopt(s->fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);}
      auto a=address(local_ip_.c_str(),1053);dns::need(bind(s->fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
    }
    dns::need(listen(tcp_.fd,16)==0);loop_=std::thread([this]{try{run();}catch(...){failed_=true;stop_=true;jobs_.clear();}});
  }
  ~DnsRelay(){stop_=true;if(loop_.joinable())loop_.join();}
};
}
