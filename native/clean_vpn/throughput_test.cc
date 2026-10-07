#include "benchmark_wire.hpp"
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <future>
#include <iostream>
#include <string>

namespace bench=cvpn::benchmark;
struct Socket {
  int fd;
  explicit Socket(int value):fd(value) { bench::require(fd>=0); }
  ~Socket(){close(fd);}
  Socket(const Socket&)=delete;
  void timeout() {
    timeval value{15,0};
    bench::require(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&value,sizeof(value))==0);
    bench::require(setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&value,sizeof(value))==0);
  }
  void tcp() { timeout(); int one=1; bench::require(setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one))==0); }
};
static auto reader(int fd) { return [fd](uint8_t* p,size_t n){return recv(fd,p,n,0);}; }
static auto writer(int fd) { return [fd](const uint8_t* p,size_t n){return send(fd,p,n,MSG_NOSIGNAL);}; }
static void guard(const std::string& parent,bool server) {
  char ns[128]; const auto n=readlink("/proc/self/ns/net",ns,sizeof(ns));
  bench::require(n>0 && parent.rfind("net:[",0)==0 && parent.back()==']' && std::string(ns,n)!=parent);
  auto* names=if_nameindex(); bench::require(names); unsigned count=0;bool safe=true;
  for(auto* a=names;a->if_index;++a) { ++count; const std::string name=a->if_name;safe &= name=="lo" || name==(server?"cvpublic1":"cvpublic0"); }
  if_freenameindex(names);bench::require(safe && count==2);
}
static void self_test() {
  for(char mode : {'U','D','L'}) {
    int pair[2];bench::require(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0);
    Socket left(pair[0]),right(pair[1]);left.timeout();right.timeout();
    auto server=std::async(std::launch::async,[&]{
      try { bench::Header h{};bench::read_all(reader(right.fd),h.data(),h.size());bench::serve(h,reader(right.fd),writer(right.fd)); }
      catch(...) { shutdown(right.fd,SHUT_RDWR);throw; }
    });
    try { bench::require(bench::client(mode,reader(left.fd),writer(left.fd)).seconds>0); }
    catch(...) { shutdown(left.fd,SHUT_RDWR);throw; }
    server.get();
  }
  // Fragmented I/O, malformed header, truncation and corrupt payload must fail.
  auto no_read=[](uint8_t*,size_t){return 0;}; auto sink=[](const uint8_t*,size_t n){return int(n);};
  auto reject=[&](auto f){bool failed=false;try{f();}catch(const std::runtime_error&){failed=true;}bench::require(failed);};
  auto h=bench::header('U');h[15]=1;reject([&]{bench::serve(h,no_read,sink);});
  reject([&]{bench::client('D',no_read,sink);});
  reject([&]{bench::bulk([](uint8_t* p,size_t n){std::fill(p,p+n,0);return int(n);},sink,false);});
  std::array<uint8_t,4> b{};size_t count=0;
  bench::read_all([&](uint8_t* p,size_t){*p=uint8_t(++count);return 1;},b.data(),b.size());
  bench::require(b==std::array<uint8_t,4>{1,2,3,4});count=0;
  bench::write_all([&](const uint8_t* p,size_t){bench::require(*p==++count);return 1;},b.data(),b.size());
  std::cout<<"NATIVE_THROUGHPUT_SELF_TEST_PASS\n";
}
int main(int argc,char** argv) {
  signal(SIGPIPE,SIG_IGN);
  try {
    if(argc==2 && std::string(argv[1])=="--self-test") {self_test();return 0;}
    const bool server=argc==3 && std::string(argv[1])=="--server";
    bench::require(server || argc==6);
    const std::string mode=server?"":argv[1], branch=server?"":argv[2];
    bench::require(server || ((mode=="upload"||mode=="download"||mode=="latency") && (branch=="boring"||branch=="transparent")));
    guard(server?argv[2]:argv[4],server); // Before bind/connect, lab namespace only.
    Socket fd(socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));fd.tcp();
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(branch=="transparent"?443:4445);
    bench::require(inet_pton(AF_INET,"1.1.1.1",&address.sin_addr)==1);
    if(server) {
      int one=1;bench::require(setsockopt(fd.fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);
      bench::require(bind(fd.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 && listen(fd.fd,8)==0);
      std::cout<<"benchmark-origin-ready"<<std::endl;
      for(;;) {
        const int accepted=accept4(fd.fd,nullptr,nullptr,SOCK_CLOEXEC);
        if(accepted<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)) continue;
        Socket peer(accepted);peer.tcp();bench::Header h{};
        bench::read_all(reader(peer.fd),h.data(),h.size());bench::serve(h,reader(peer.fd),writer(peer.fd));
      }
    }
    bench::require(std::string(argv[5])=="--lab-only");
    bench::require(connect(fd.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);
    const char wireMode=mode=="upload"?'U':mode=="download"?'D':'L';bench::Result result;
    if(branch=="transparent") {
      bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));bench::require(bool(ctx));
      bench::require(SSL_CTX_load_verify_locations(ctx.get(),argv[3],nullptr)==1);SSL_CTX_set_verify(ctx.get(),SSL_VERIFY_PEER,nullptr);
      bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));bench::require(bool(ssl));
      bench::require(SSL_set_min_proto_version(ssl.get(),TLS1_3_VERSION) && SSL_set_max_proto_version(ssl.get(),TLS1_3_VERSION));
      bench::require(SSL_set_tlsext_host_name(ssl.get(),"localhost") && SSL_set1_host(ssl.get(),"localhost"));
      bench::require(SSL_set_fd(ssl.get(),fd.fd) && SSL_connect(ssl.get())==1 && SSL_get_verify_result(ssl.get())==X509_V_OK);
      result=bench::client(wireMode,[&](uint8_t* p,size_t n){return SSL_read(ssl.get(),p,int(n));},[&](const uint8_t* p,size_t n){return SSL_write(ssl.get(),p,int(n));});
      bench::require(SSL_shutdown(ssl.get())>=0);
      uint8_t last=0;const int n=SSL_read(ssl.get(),&last,1);bench::require(n==0 && SSL_get_error(ssl.get(),n)==SSL_ERROR_ZERO_RETURN);
    } else result=bench::client(wireMode,reader(fd.fd),writer(fd.fd));
    const long ticks=sysconf(_SC_CLK_TCK);bench::require(ticks>0);
    nlohmann::json out={{"status","passed"},{"branch",branch},{"phase",mode},{"payloadVerified",true},
      {"seconds",result.seconds},{"clockTicksPerSecond",ticks},{"streams",1},
      {"payloadBytes",mode=="latency"?0:bench::bytes},{"rounds",mode=="latency"?bench::rounds:0},
      {"warmupRounds",mode=="latency"?bench::warmup:0},
      {"goodputMbps",mode=="latency"?0:bench::bytes*8/result.seconds/1e6},
      {"latencyMedianMs",result.median_ms},{"latencyP95Ms",result.p95_ms}};
    std::cout<<out.dump()<<std::endl;return 0;
  } catch(const std::exception& e) {std::cerr<<e.what()<<std::endl;return 1;}
}
