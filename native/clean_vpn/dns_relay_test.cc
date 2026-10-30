#include "dns_relay.hpp"
#include <dirent.h>
#include <iostream>
using namespace cvpn;
static void expect(bool value,int line){if(!value)throw std::runtime_error("dns_test_line_"+std::to_string(line));}
#define DNS_EXPECT(value) expect((value),__LINE__)
static const char* client_ip="10.99.0.2";
static sockaddr_in addr(const char* ip,int port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);DNS_EXPECT(inet_pton(AF_INET,ip,&a.sin_addr)==1);return a;}
static size_t entries(const char* path){DIR* d=opendir(path);DNS_EXPECT(d);size_t n=0;while(readdir(d))n++;closedir(d);return n;}
static Bytes question(){return {0x12,0x34,1,0,0,1,0,0,0,0,0,0,4,'t','e','s','t',0,0,1,0,1};}
struct Origin {
  int udp,tcp;std::atomic<bool> stop{false};std::atomic<int> mode{0},requests{0},delay_ms{0};std::thread thread;
  explicit Origin(const char* ip,unsigned port=53,const char* source=client_ip){
    udp=socket(AF_INET,SOCK_DGRAM,0);tcp=socket(AF_INET,SOCK_STREAM,0);DNS_EXPECT(udp>=0&&tcp>=0);auto a=addr(ip,port);int one=1;setsockopt(tcp,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    DNS_EXPECT(bind(udp,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0&&bind(tcp,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0&&listen(tcp,16)==0);
    thread=std::thread([this,source]{
      while(!stop){pollfd p[]={{udp,POLLIN,0},{tcp,POLLIN,0}};if(poll(p,2,20)<=0)continue;
        for(int i=0;i<2;i++)if(p[i].revents&POLLIN){
          int fd=i?accept(tcp,nullptr,nullptr):udp;if(fd<0)continue;
          timeval timeout{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
          unsigned char raw[4096];sockaddr_in peer{};socklen_t size=sizeof(peer);ssize_t n;
          if(i){unsigned char prefix[2];n=recv(fd,prefix,2,MSG_WAITALL);if(n!=2){close(fd);continue;}n=(size_t(prefix[0])<<8)|prefix[1];if(n>4096){close(fd);continue;}n=recv(fd,raw,n,MSG_WAITALL);}
          else n=recvfrom(fd,raw,sizeof(raw),0,reinterpret_cast<sockaddr*>(&peer),&size);
          if(n<12){if(i)close(fd);continue;}
          if(i)DNS_EXPECT(getpeername(fd,reinterpret_cast<sockaddr*>(&peer),&size)==0);
          DNS_EXPECT(peer.sin_addr.s_addr==addr(source,0).sin_addr.s_addr);
          requests++;if(mode==4){if(i)close(fd);continue;}if(delay_ms)std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms.load()));Bytes q(raw,raw+n),a=dns::failure(q,mode==2?2:3);
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
  int fd=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);DNS_EXPECT(fd>=0);struct Close{int fd;~Close(){close(fd);}}cleanup{fd};timeval timeout{4,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));auto a=addr(destination,port);
  if(source){auto local=addr(source,0);DNS_EXPECT(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0);}
  DNS_EXPECT(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
  if(tcp){uint8_t prefix[]={uint8_t(q.size()>>8),uint8_t(q.size())};DNS_EXPECT(send(fd,prefix,2,MSG_NOSIGNAL)==2);}
  DNS_EXPECT(send(fd,q.data(),q.size(),MSG_NOSIGNAL)==ssize_t(q.size()));Bytes b(65535);ssize_t n;
  if(tcp){uint8_t prefix[2];if(recv(fd,prefix,2,MSG_WAITALL)!=2){throw std::runtime_error("query_closed");}n=(size_t(prefix[0])<<8)|prefix[1];n=recv(fd,b.data(),n,MSG_WAITALL);}else n=recv(fd,b.data(),b.size(),0);
  DNS_EXPECT(n>=12);b.resize(n);return b;
}
int main(int argc,char** argv){
  try{
    DNS_EXPECT(argc==1||(argc==2&&std::string(argv[1])=="10.99.0.3"));
    if(argc==2)client_ip=argv[1];
    // Initialize runtime thread bookkeeping before measuring application
    // workers (TSan starts its own persistent helper on the first thread).
    std::thread([]{}).join();
    const auto baseline=entries("/proc/self/fd"),baseline_tasks=entries("/proc/self/task");
    {
      Origin primary("1.1.1.1"),backup("8.8.8.8"),private_origin("10.99.0.1",1055);std::atomic<bool> ready{false},failed{false},idle{false},demand{false};auto relay=std::make_unique<DnsRelay>("lo",ready,failed,&idle,&demand,client_ip);auto q=question();
      DNS_EXPECT(dns::response(query(q),q).rcode==2&&primary.requests==0&&backup.requests==0);ready=true;
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(q,tcp),q).rcode==3);
      for(bool tcp:{false,true}){
        ready=false;idle=true;demand=false;
        std::atomic<bool> woke{false};
        std::thread wake([&]{
          auto end=std::chrono::steady_clock::now()+std::chrono::seconds(1);
          while(!demand&&std::chrono::steady_clock::now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(5));
          woke=demand.load();idle=false;ready=true;
        });
        auto answer=query(q,tcp);wake.join();DNS_EXPECT(woke&&dns::response(answer,q).rcode==3);
      }
      for(int mode:{1,2}){primary.mode=mode;for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(q,tcp),q).rcode==3);}
      DNS_EXPECT(backup.requests==4);primary.mode=3;
      DNS_EXPECT(dns::response(query(q),q).flags&0x0200);DNS_EXPECT(query(q,true).size()>512);
      primary.mode=1;backup.mode=1;DNS_EXPECT(dns::response(query(q),q).rcode==2);primary.mode=0;backup.mode=0;
      auto edns=q;dns::put16(edns,10,1);edns.insert(edns.end(),{0,0,41,0x10,0,0,1,0,0,0,0});
      DNS_EXPECT(dns::parse(query(edns)).rcode==16);
      auto private_q=q;private_q.insert(private_q.end()-5,{3,'m','p','n'});
      const int public_count=primary.requests+backup.requests;
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(private_q,tcp),private_q).rcode==3);
      private_origin.mode=2;
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(private_q,tcp),private_q).rcode==2);
      DNS_EXPECT(primary.requests+backup.requests==public_count&&private_origin.requests==4);
      // The client deadline covers TCP connect AND response. A healthy tunnel
      // can deliver after 1.2s (e.g. one TCP retransmission); private DNS has no
      // second public upstream to retry. Keep the loopback bridge budget short.
      private_origin.mode=0;private_origin.delay_ms=1400;
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(private_q,tcp),private_q).rcode==3);
      private_origin.delay_ms=0;
      private_origin.mode=4;const auto metrics_before=relay->diagnostics();auto timeout_start=std::chrono::steady_clock::now();
      DNS_EXPECT(dns::response(query(private_q),private_q).rcode==2);
      const auto elapsed=std::chrono::steady_clock::now()-timeout_start;
      DNS_EXPECT(elapsed>=std::chrono::milliseconds(2800)&&elapsed<std::chrono::seconds(4));private_origin.mode=0;
      DNS_EXPECT(primary.requests+backup.requests==public_count);
      const auto metrics_after=relay->diagnostics();
      DNS_EXPECT(metrics_after.upstream_timeouts==metrics_before.upstream_timeouts+1&&
        metrics_after.servfail==metrics_before.servfail+1&&metrics_after.private_queries==metrics_before.private_queries+1&&
        metrics_after.answers==metrics_before.answers);
      auto encoded=q;encoded[12]=8;encoded.insert(encoded.end()-5,{'.','m','p','n'});
      DNS_EXPECT(dns::response(query(encoded),encoded).rcode==1&&primary.requests+backup.requests==public_count);
      for(int i=0;i<100;i++)DNS_EXPECT(dns::response(query(q,i%2),q).rcode==3);
      std::vector<int> slow;
      for(int i=0;i<24;i++){int fd=socket(AF_INET,SOCK_STREAM,0);auto a=addr(client_ip,1053);DNS_EXPECT(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);slow.push_back(fd);}
      std::this_thread::sleep_for(std::chrono::milliseconds(100));DNS_EXPECT(entries("/proc/self/task")<=baseline_tasks+20);
      auto start=std::chrono::steady_clock::now();relay.reset();DNS_EXPECT(std::chrono::steady_clock::now()-start<std::chrono::seconds(1));
      for(int fd:slow)close(fd);
      DNS_EXPECT(!failed);
    }
    {
      Origin private_origin("127.0.0.1",1055,"127.0.0.1");std::atomic<bool> ready{true},failed{false};
      DnsRelay bridge("lo",ready,failed,nullptr,nullptr,"10.99.0.1",true,{addr(client_ip,0).sin_addr.s_addr});
      auto q=question(),private_q=q;private_q.insert(private_q.end()-5,{3,'m','p','n'});
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(private_q,tcp,"10.99.0.1",1055,client_ip),private_q).rcode==3);
      const auto count=private_origin.requests.load();
      for(bool tcp:{false,true})DNS_EXPECT(dns::response(query(q,tcp,"10.99.0.1",1055,client_ip),q).rcode==5);
      DNS_EXPECT(private_origin.requests==count);
      std::vector<int> held;
      for(int i=0;i<5;i++){int fd=socket(AF_INET,SOCK_STREAM,0);auto local=addr(client_ip,0),remote=addr("10.99.0.1",1055);DNS_EXPECT(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0&&connect(fd,reinterpret_cast<sockaddr*>(&remote),sizeof(remote))==0);timeval limit{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));held.push_back(fd);}
      char byte;DNS_EXPECT(recv(held.back(),&byte,1,0)==0);close(held.back());held.pop_back();
      bridge.replace_peers({});for(int fd:held){DNS_EXPECT(recv(fd,&byte,1,0)==0);close(fd);}
      bool denied=false;try{query(private_q,true,"10.99.0.1",1055,client_ip);}catch(...){denied=true;}DNS_EXPECT(denied);
      bridge.replace_peers({addr(client_ip,0).sin_addr.s_addr});
      DNS_EXPECT(dns::response(query(private_q,true,"10.99.0.1",1055,client_ip),private_q).rcode==3);
      denied=false;try{query(private_q,true,"10.99.0.1",1055,"127.0.0.1");}catch(...){denied=true;}DNS_EXPECT(denied&&!failed);
    }
    // A single instantaneous final proc count failed under load. Observe
    // convergence for at most 500ms, as in relay resource tests. Keep exact
    // FD/task bounds and print the initial/final evidence; persistent leaks fail.
    auto cleanup_end=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);
    const auto first_fds=entries("/proc/self/fd"),first_tasks=entries("/proc/self/task");
    while((entries("/proc/self/fd")!=baseline||entries("/proc/self/task")>baseline_tasks)&&std::chrono::steady_clock::now()<cleanup_end)std::this_thread::sleep_for(std::chrono::milliseconds(5));
    if(first_fds!=baseline||first_tasks>baseline_tasks)std::cout<<"DNS_CLEANUP_OBSERVATION first_fds="<<first_fds<<" baseline_fds="<<baseline<<" first_tasks="<<first_tasks<<" baseline_tasks="<<baseline_tasks<<" final_fds="<<entries("/proc/self/fd")<<" final_tasks="<<entries("/proc/self/task")<<'\n';
    DNS_EXPECT(entries("/proc/self/fd")==baseline&&entries("/proc/self/task")<=baseline_tasks);std::cout<<"native DNS UDP/TCP, identity, fallback, EDNS, truncation, 100 queries, saturation, cancellation, FD cleanup PASS\n";
  }catch(const std::exception& e){std::cerr<<e.what()<<" errno="<<errno<<"\n";return 1;}
}
