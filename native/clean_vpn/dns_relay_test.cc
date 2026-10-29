#include "dns_relay.hpp"
#include <dirent.h>
#include <iostream>
using namespace cvpn;
static const char* client_ip="10.99.0.2";
static sockaddr_in addr(const char* ip,int port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);dns::need(inet_pton(AF_INET,ip,&a.sin_addr)==1);return a;}
static size_t entries(const char* path){DIR* d=opendir(path);dns::need(d);size_t n=0;while(readdir(d))n++;closedir(d);return n;}
static Bytes question(){return {0x12,0x34,1,0,0,1,0,0,0,0,0,0,4,'t','e','s','t',0,0,1,0,1};}
struct Origin {
  int udp,tcp;std::atomic<bool> stop{false};std::atomic<int> mode{0},requests{0};std::thread thread;
  explicit Origin(const char* ip,unsigned port=53,const char* source=client_ip){
    udp=socket(AF_INET,SOCK_DGRAM,0);tcp=socket(AF_INET,SOCK_STREAM,0);dns::need(udp>=0&&tcp>=0);auto a=addr(ip,port);int one=1;setsockopt(tcp,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    dns::need(bind(udp,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0&&bind(tcp,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0&&listen(tcp,16)==0);
    thread=std::thread([this,source]{
      while(!stop){pollfd p[]={{udp,POLLIN,0},{tcp,POLLIN,0}};if(poll(p,2,20)<=0)continue;
        for(int i=0;i<2;i++)if(p[i].revents&POLLIN){
          int fd=i?accept(tcp,nullptr,nullptr):udp;if(fd<0)continue;
          timeval timeout{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
          unsigned char raw[4096];sockaddr_in peer{};socklen_t size=sizeof(peer);ssize_t n;
          if(i){unsigned char prefix[2];n=recv(fd,prefix,2,MSG_WAITALL);if(n!=2){close(fd);continue;}n=(size_t(prefix[0])<<8)|prefix[1];if(n>4096){close(fd);continue;}n=recv(fd,raw,n,MSG_WAITALL);}
          else n=recvfrom(fd,raw,sizeof(raw),0,reinterpret_cast<sockaddr*>(&peer),&size);
          if(n<12){if(i)close(fd);continue;}
          if(i)dns::need(getpeername(fd,reinterpret_cast<sockaddr*>(&peer),&size)==0);
          dns::need(peer.sin_addr.s_addr==addr(source,0).sin_addr.s_addr);
          requests++;Bytes q(raw,raw+n),a=dns::failure(q,mode==2?2:3);
          if(mode==1)a[0]^=1;
          if(mode==3){a=dns::failure(q,0);dns::put16(a,6,1);a.insert(a.end(),{0xc0,12,0,16,0,1,0,0,0,0,2,88});a.resize(a.size()+600);}
          if(i){unsigned char prefix[]={uint8_t(a.size()>>8),uint8_t(a.size())};send(fd,prefix,2,MSG_NOSIGNAL);send(fd,a.data(),a.size(),MSG_NOSIGNAL);close(fd);}
          else sendto(fd,a.data(),a.size(),0,reinterpret_cast<sockaddr*>(&peer),size);
        }
      }
    });
  }
  ~Origin(){stop=true;thread.join();close(udp);close(tcp);}
};
static Bytes query(const Bytes& q,bool tcp=false,const char* destination=client_ip,unsigned port=1053,const char* source=nullptr){
  int fd=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);dns::need(fd>=0);struct Close{int fd;~Close(){close(fd);}}cleanup{fd};timeval timeout{3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));auto a=addr(destination,port);
  if(source){auto local=addr(source,0);dns::need(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0);}
  dns::need(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
  if(tcp){uint8_t prefix[]={uint8_t(q.size()>>8),uint8_t(q.size())};dns::need(send(fd,prefix,2,MSG_NOSIGNAL)==2);}
  dns::need(send(fd,q.data(),q.size(),MSG_NOSIGNAL)==ssize_t(q.size()));Bytes b(65535);ssize_t n;
  if(tcp){uint8_t prefix[2];if(recv(fd,prefix,2,MSG_WAITALL)!=2){throw std::runtime_error("query_closed");}n=(size_t(prefix[0])<<8)|prefix[1];n=recv(fd,b.data(),n,MSG_WAITALL);}else n=recv(fd,b.data(),b.size(),0);
  dns::need(n>=12);b.resize(n);return b;
}
int main(int argc,char** argv){
  try{
    dns::need(argc==1||(argc==2&&std::string(argv[1])=="10.99.0.3"));
    if(argc==2)client_ip=argv[1];
    const auto baseline=entries("/proc/self/fd");
    {
      Origin primary("1.1.1.1"),backup("8.8.8.8"),private_origin("10.99.0.1",1055);std::atomic<bool> ready{false},failed{false},idle{false},demand{false};auto relay=std::make_unique<DnsRelay>("lo",ready,failed,&idle,&demand,client_ip);auto q=question();
      dns::need(dns::response(query(q),q).rcode==2&&primary.requests==0&&backup.requests==0);ready=true;
      for(bool tcp:{false,true})dns::need(dns::response(query(q,tcp),q).rcode==3);
      for(bool tcp:{false,true}){
        ready=false;idle=true;demand=false;
        std::atomic<bool> woke{false};
        std::thread wake([&]{
          auto end=std::chrono::steady_clock::now()+std::chrono::seconds(1);
          while(!demand&&std::chrono::steady_clock::now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(5));
          woke=demand.load();idle=false;ready=true;
        });
        auto answer=query(q,tcp);wake.join();dns::need(woke&&dns::response(answer,q).rcode==3);
      }
      for(int mode:{1,2}){primary.mode=mode;for(bool tcp:{false,true})dns::need(dns::response(query(q,tcp),q).rcode==3);}
      dns::need(backup.requests==4);primary.mode=3;
      dns::need(dns::response(query(q),q).flags&0x0200);dns::need(query(q,true).size()>512);
      primary.mode=1;backup.mode=1;dns::need(dns::response(query(q),q).rcode==2);primary.mode=0;backup.mode=0;
      auto edns=q;dns::put16(edns,10,1);edns.insert(edns.end(),{0,0,41,0x10,0,0,1,0,0,0,0});
      dns::need(dns::parse(query(edns)).rcode==16);
      auto private_q=q;private_q.insert(private_q.end()-5,{3,'m','p','n'});
      const int public_count=primary.requests+backup.requests;
      for(bool tcp:{false,true})dns::need(dns::response(query(private_q,tcp),private_q).rcode==3);
      private_origin.mode=2;
      for(bool tcp:{false,true})dns::need(dns::response(query(private_q,tcp),private_q).rcode==2);
      dns::need(primary.requests+backup.requests==public_count&&private_origin.requests==4);
      auto encoded=q;encoded[12]=8;encoded.insert(encoded.end()-5,{'.','m','p','n'});
      dns::need(dns::response(query(encoded),encoded).rcode==1&&primary.requests+backup.requests==public_count);
      for(int i=0;i<100;i++)dns::need(dns::response(query(q,i%2),q).rcode==3);
      std::vector<int> slow;
      for(int i=0;i<24;i++){int fd=socket(AF_INET,SOCK_STREAM,0);auto a=addr(client_ip,1053);dns::need(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);slow.push_back(fd);}
      std::this_thread::sleep_for(std::chrono::milliseconds(100));dns::need(entries("/proc/self/task")<=23);
      auto start=std::chrono::steady_clock::now();relay.reset();dns::need(std::chrono::steady_clock::now()-start<std::chrono::seconds(1));
      for(int fd:slow)close(fd);
      dns::need(!failed);
    }
    {
      Origin private_origin("127.0.0.1",1055,"127.0.0.1");std::atomic<bool> ready{true},failed{false};
      DnsRelay bridge("lo",ready,failed,nullptr,nullptr,"10.99.0.1",true,{addr(client_ip,0).sin_addr.s_addr});
      auto q=question(),private_q=q;private_q.insert(private_q.end()-5,{3,'m','p','n'});
      for(bool tcp:{false,true})dns::need(dns::response(query(private_q,tcp,"10.99.0.1",1055,client_ip),private_q).rcode==3);
      const auto count=private_origin.requests.load();
      for(bool tcp:{false,true})dns::need(dns::response(query(q,tcp,"10.99.0.1",1055,client_ip),q).rcode==5);
      dns::need(private_origin.requests==count);
      std::vector<int> held;
      for(int i=0;i<5;i++){int fd=socket(AF_INET,SOCK_STREAM,0);auto local=addr(client_ip,0),remote=addr("10.99.0.1",1055);dns::need(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0&&connect(fd,reinterpret_cast<sockaddr*>(&remote),sizeof(remote))==0);timeval limit{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));held.push_back(fd);}
      char byte;dns::need(recv(held.back(),&byte,1,0)==0);close(held.back());held.pop_back();
      bridge.replace_peers({});for(int fd:held){dns::need(recv(fd,&byte,1,0)==0);close(fd);}
      bool denied=false;try{query(private_q,true,"10.99.0.1",1055,client_ip);}catch(...){denied=true;}dns::need(denied);
      bridge.replace_peers({addr(client_ip,0).sin_addr.s_addr});
      dns::need(dns::response(query(private_q,true,"10.99.0.1",1055,client_ip),private_q).rcode==3);
      denied=false;try{query(private_q,true,"10.99.0.1",1055,"127.0.0.1");}catch(...){denied=true;}dns::need(denied&&!failed);
    }
    dns::need(entries("/proc/self/fd")==baseline);std::cout<<"native DNS UDP/TCP, identity, fallback, EDNS, truncation, 100 queries, saturation, cancellation, FD cleanup PASS\n";
  }catch(const std::exception& e){std::cerr<<e.what()<<" errno="<<errno<<"\n";return 1;}
}
