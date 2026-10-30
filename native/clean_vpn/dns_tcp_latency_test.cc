// Real TCP DNS regression. Test-only send interposition models a preemption
// between prefix and body, short writes, EINTR and EAGAIN; production is unchanged.
#include "dns_relay.hpp"
#include <netinet/tcp.h>
#include <sys/time.h>
#include <iostream>
#include <condition_variable>
using namespace cvpn;
using Clock=std::chrono::steady_clock;
static std::atomic<bool> controlled{false},fragment{false},receiver_ready{false},origin_ready{false},stall_writes{false},write_stalled{false};
static std::atomic<unsigned> standalone_prefixes{0},short_writes{0},interrupted_writes{0},again_writes{0};
static thread_local unsigned sends=0;
extern "C" ssize_t __real_send(int,const void*,size_t,int);
extern "C" ssize_t __wrap_send(int fd,const void* bytes,size_t n,int flags){
  sockaddr_in local{},remote{};socklen_t size=sizeof(local);
  bool upstream=false,downstream=false;
  if(getsockname(fd,reinterpret_cast<sockaddr*>(&local),&size)==0&&getpeername(fd,reinterpret_cast<sockaddr*>(&remote),&size)==0){
    upstream=ntohs(remote.sin_port)==1055&&ntohl(remote.sin_addr.s_addr)==0x7f000001;
    downstream=ntohs(local.sin_port)==1055&&ntohl(local.sin_addr.s_addr)==0x0a630001;
  }
  if(!upstream&&!downstream)return __real_send(fd,bytes,n,flags);
  if(controlled){
    const auto until=Clock::now()+std::chrono::milliseconds(500);
    while(!(upstream?origin_ready.load():receiver_ready.load())&&Clock::now()<until)std::this_thread::sleep_for(std::chrono::microseconds(100));
    if(n==2){++standalone_prefixes;const auto result=__real_send(fd,bytes,n,flags);std::this_thread::sleep_for(std::chrono::milliseconds(2));return result;}
  }
  if(stall_writes&&downstream&&n>2){write_stalled=true;errno=EAGAIN;return -1;}
  if(fragment){
    ++sends;if(sends%5==1){++interrupted_writes;errno=EINTR;return -1;}if(sends%7==2){++again_writes;errno=EAGAIN;return -1;}
    if(n>97){n=97;++short_writes;}
  }
  return __real_send(fd,bytes,n,flags);
}
static void need(bool ok,const char* what){if(!ok)throw std::runtime_error(what);}
struct Socket{int fd;explicit Socket(int f):fd(f){need(fd>=0,"socket");}~Socket(){close(fd);}Socket(const Socket&)=delete;};
static sockaddr_in address(const char* ip,unsigned port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);need(inet_pton(AF_INET,ip,&a.sin_addr)==1,"address");return a;}
static void option(int fd,int level,int name,int n){need(setsockopt(fd,level,name,&n,sizeof(n))==0,"socket_option");}
static void timeout(int fd){timeval limit{2,0};need(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit))==0,"timeout");}
static void read_exact(int fd,uint8_t* p,size_t n){while(n){auto k=recv(fd,p,n,0);need(k>0,"read_exact");p+=k;n-=size_t(k);}}
static void send_exact(int fd,const Bytes& bytes,bool pieces=false){size_t at=0;while(at<bytes.size()){const auto n=pieces?size_t(1):bytes.size()-at;auto k=__real_send(fd,bytes.data()+at,n,MSG_NOSIGNAL);need(k>0,"send_exact");at+=size_t(k);if(pieces)std::this_thread::sleep_for(std::chrono::microseconds(200));}}
static Bytes frame(const Bytes& body){Bytes b{uint8_t(body.size()>>8),uint8_t(body.size())};b.insert(b.end(),body.begin(),body.end());return b;}
static Bytes question(){return {0x12,0x34,1,0,0,1,0,0,0,0,0,0,4,'t','e','s','t',3,'m','p','n',0,0,1,0,1};}
static Bytes answer(const Bytes& q,bool large){auto b=dns::failure(q,large?0:3);if(large){dns::put16(b,6,1);b.insert(b.end(),{0xc0,12,0,16,0,1,0,0,0,0,0xea,0x60});b.resize(b.size()+60000,0x5a);}return b;}
struct Origin{
  Socket listener{socket(AF_INET,SOCK_STREAM,0)};std::atomic<bool> stop{false},large{false},stall{false},stalled{false};std::atomic<bool> broken{false};std::atomic<unsigned> requests{0};std::atomic<long> body_gap_us{0};std::thread thread;
  Origin(){option(listener.fd,SOL_SOCKET,SO_REUSEADDR,1);auto a=address("127.0.0.1",1055);need(bind(listener.fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0&&listen(listener.fd,8)==0,"origin_listen");
    thread=std::thread([&]{try{while(!stop){pollfd p{listener.fd,POLLIN,0};if(poll(&p,1,20)<=0)continue;Socket s(accept(listener.fd,nullptr,nullptr));timeout(s.fd);option(s.fd,IPPROTO_TCP,TCP_NODELAY,1);option(s.fd,IPPROTO_TCP,TCP_QUICKACK,0);origin_ready=true;
      uint8_t prefix[2];read_exact(s.fd,prefix,2);auto start=Clock::now();size_t n=(size_t(prefix[0])<<8)|prefix[1];need(n>=12,"query_length");Bytes q(n);read_exact(s.fd,q.data(),n);body_gap_us=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count();
      need(dns::parse(q,true).question.key==dns::parse(question(),true).question.key,"upstream_question");++requests;
      const auto data=frame(answer(q,large));if(stall){send_exact(s.fd,Bytes(data.begin(),data.begin()+3));stalled=true;while(!stop)std::this_thread::sleep_for(std::chrono::milliseconds(5));}else send_exact(s.fd,data);
    }}catch(...){if(!stop)broken=true;}});
  }
  ~Origin(){stop=true;thread.join();}
};
struct Result{Bytes bytes;long first_us,gap_us,total_us;};
static Result request(bool pieces=false){Socket s(socket(AF_INET,SOCK_STREAM,0));timeout(s.fd);option(s.fd,IPPROTO_TCP,TCP_NODELAY,1);auto local=address("10.99.0.2",0),target=address("10.99.0.1",1055);need(bind(s.fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0&&connect(s.fd,reinterpret_cast<sockaddr*>(&target),sizeof(target))==0,"client_connect");
  const auto start=Clock::now();send_exact(s.fd,frame(question()),pieces);option(s.fd,IPPROTO_TCP,TCP_QUICKACK,0);receiver_ready=true;
  uint8_t prefix[2];read_exact(s.fd,prefix,2);const auto first=Clock::now();size_t n=(size_t(prefix[0])<<8)|prefix[1];need(n>=12,"answer_length");Bytes result(n);read_exact(s.fd,result.data(),n);auto end=Clock::now();
  return {result,std::chrono::duration_cast<std::chrono::microseconds>(first-start).count(),std::chrono::duration_cast<std::chrono::microseconds>(end-first).count(),std::chrono::duration_cast<std::chrono::microseconds>(end-start).count()};
}
int main(int argc,char** argv){try{
  need(argc==2&&(std::string(argv[1])=="--baseline"||std::string(argv[1])=="--expect-coalesced"),"mode");const bool fixed=std::string(argv[1])=="--expect-coalesced";
  Origin origin;std::atomic<bool> ready{true},failed{false};auto relay=std::make_unique<DnsRelay>("lo",ready,failed,nullptr,nullptr,"10.99.0.1",true,DnsRelay::Peers{address("10.99.0.2",0).sin_addr.s_addr});
  controlled=true;
  for(int i=0;i<5;i++){origin_ready=false;receiver_ready=false;const auto r=request();need(r.bytes==answer(question(),false),"exact_small_frame");std::cout<<"DNS_TCP_SAMPLE upstream_body_gap_us="<<origin.body_gap_us<<" downstream_body_gap_us="<<r.gap_us<<" total_us="<<r.total_us<<"\n";}
  if(fixed)need(standalone_prefixes==0,"standalone_prefix_send_regression");else need(standalone_prefixes==10,"baseline_prefix_count");
  controlled=false;fragment=true;origin.large=true;const auto large=request(true);need(large.bytes==answer(question(),true),"exact_large_fragmented_frame");need(short_writes>0&&interrupted_writes>0&&again_writes>0,"partial_write_injection");fragment=false;
  // Reuse one connection for two complete requests, followed by one byte of
  // the next prefix. Framing boundaries and cancellation are independent.
  origin.large=false;
  Socket held(socket(AF_INET,SOCK_STREAM,0));timeout(held.fd);auto local=address("10.99.0.2",0),target=address("10.99.0.1",1055);need(bind(held.fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0&&connect(held.fd,reinterpret_cast<sockaddr*>(&target),sizeof(target))==0,"held_connect");for(int i=0;i<2;i++){send_exact(held.fd,frame(question()));uint8_t prefix[2];read_exact(held.fd,prefix,2);size_t n=(size_t(prefix[0])<<8)|prefix[1];Bytes response(n);read_exact(held.fd,response.data(),n);need(response==answer(question(),false),"persistent_exact_frame");}
  send_exact(held.fd,Bytes{0});std::this_thread::sleep_for(std::chrono::milliseconds(20));
  auto start=Clock::now();relay.reset();need(Clock::now()-start<std::chrono::seconds(1),"partial_prefix_cancel");uint8_t byte;need(recv(held.fd,&byte,1,0)==0,"cancelled_peer_closed");need(!failed&&!origin.broken,"relay_or_origin_failed");
  relay=std::make_unique<DnsRelay>("lo",ready,failed,nullptr,nullptr,"10.99.0.1",true,DnsRelay::Peers{address("10.99.0.2",0).sin_addr.s_addr});
  origin.large=true;stall_writes=true;std::atomic<bool> cancelled{false};std::thread blocked([&]{try{request();}catch(...){cancelled=true;}});
  auto until=Clock::now()+std::chrono::seconds(1);while(!write_stalled&&Clock::now()<until)std::this_thread::sleep_for(std::chrono::milliseconds(1));
  const bool observed_stall=write_stalled;start=Clock::now();relay.reset();const bool bounded=Clock::now()-start<std::chrono::seconds(1);blocked.join();stall_writes=false;
  need(observed_stall&&bounded&&cancelled,"outgoing_backpressure_cancel");
  relay=std::make_unique<DnsRelay>("lo",ready,failed,nullptr,nullptr,"10.99.0.1",true,DnsRelay::Peers{address("10.99.0.2",0).sin_addr.s_addr});
  origin.stall=true;cancelled=false;std::thread partial([&]{try{request();}catch(...){cancelled=true;}});
  until=Clock::now()+std::chrono::seconds(1);while(!origin.stalled&&Clock::now()<until)std::this_thread::sleep_for(std::chrono::milliseconds(1));
  const bool upstream_partial=origin.stalled;start=Clock::now();relay.reset();const bool upstream_bounded=Clock::now()-start<std::chrono::seconds(1);partial.join();origin.stop=true;
  need(upstream_partial&&upstream_bounded&&cancelled&&!failed&&!origin.broken,"partial_upstream_cancel");
  std::cout<<"DNS_TCP_FRAMING_PASS mode="<<(fixed?"coalesced":"baseline")<<" standalone_prefixes="<<standalone_prefixes<<" short_writes="<<short_writes<<" EINTR="<<interrupted_writes<<" EAGAIN="<<again_writes<<" requests="<<origin.requests<<"\n";
 }catch(const std::exception& e){std::cerr<<e.what()<<" errno="<<errno<<"\n";return 1;}}
