// Disposable-VM application workload. No production engine code linked here.
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
using json=nlohmann::json;
using Clock=std::chrono::steady_clock;
static volatile sig_atomic_t stopped=0;
static void stop(int){stopped=1;}
static void check(bool ok){if(!ok)throw std::runtime_error("goodput_protocol_or_io");}
static double now(){return std::chrono::duration<double,std::milli>(Clock::now().time_since_epoch()).count();}
static constexpr size_t total=8*1024*1024;
static const auto pattern=[](){std::array<uint8_t,65536> b{};for(size_t i=0;i<b.size();i++)b[i]=uint8_t((i*31+i/251)%251);return b;}();
struct Socket{
  int fd;explicit Socket(int f):fd(f){check(f>=0);timeval t{15,0};int one=1;
    check(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))==0&&setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t))==0);
    check(setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one))==0);}
  ~Socket(){close(fd);}Socket(const Socket&)=delete;
};
static bool read_all(int fd,void* data,size_t length,bool eof=false){
  auto* p=static_cast<uint8_t*>(data);size_t at=0;
  while(at<length){const auto n=recv(fd,p+at,length-at,0);if(n<0&&errno==EINTR)continue;
    if(n==0&&at==0&&eof)return false;
    check(n>0);at+=size_t(n);}
  return true;
}
static void write_all(int fd,const void* data,size_t length){
  const auto* p=static_cast<const uint8_t*>(data);size_t at=0;
  while(at<length){const auto n=send(fd,p+at,length-at,MSG_NOSIGNAL);if(n<0&&errno==EINTR)continue;check(n>0);at+=size_t(n);}
}
static uint32_t retrans(int fd){tcp_info info{};socklen_t size=sizeof(info);check(getsockopt(fd,IPPROTO_TCP,TCP_INFO,&info,&size)==0);return info.tcpi_total_retrans;}
static void bulk(int fd,bool send){std::array<uint8_t,65536> b{};
  for(size_t i=0;i<total;i+=b.size()){
    if(send)write_all(fd,pattern.data(),pattern.size());
    else{read_all(fd,b.data(),b.size());check(b==pattern);}
  }
}
static void serve(int fd){
  Socket s(fd);char mode;read_all(fd,&mode,1);check(mode=='U'||mode=='D'||mode=='L');write_all(fd,"R",1);
  if(mode=='L'){std::array<uint8_t,32>b{};while(read_all(fd,b.data(),b.size(),true))write_all(fd,b.data(),b.size());return;}
  char marker;read_all(fd,&marker,1);check(marker=='G');bulk(fd,mode=='D');write_all(fd,"K",1);
  read_all(fd,&marker,1);check(marker=='K');const uint32_t count=htonl(retrans(fd));write_all(fd,&count,sizeof(count));
}
int main(int argc,char**argv){
  signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop);signal(SIGINT,stop);
  try{
    std::ifstream cmdline("/proc/cmdline");std::string cmd;std::getline(cmdline,cmd);check(cmd.find("meshpn.h2-goodput=1")!=std::string::npos);
    check(argc==2||argc==3);const std::string mode=argv[1];
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(4445);
    Socket s(socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));
    if(mode=="server"){
      check(argc==2);int one=1;check(setsockopt(s.fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);
      check(bind(s.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0&&listen(s.fd,8)==0);
      static std::atomic<int> active{0},failed{0};timeval t{1,0};check(setsockopt(s.fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))==0);
      std::cout<<"H2_ORIGIN_READY"<<std::endl;
      while(!stopped){const int fd=accept4(s.fd,nullptr,nullptr,SOCK_CLOEXEC);
        if(fd<0){check(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK);continue;}
        check(++active<=8);
        std::thread([fd]{try{serve(fd);}catch(...){failed++;}active--;}).detach();
      }
      const auto end=Clock::now()+std::chrono::seconds(20);while(active&&Clock::now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(20));
      // Exit immediately if a worker is stuck: it must not outlive its counters.
      if(active)_exit(2);
      check(failed==0);return 0;
    }
    check(argc==3&&(mode=="download"||mode=="upload"||mode=="probe"));
    check(inet_pton(AF_INET,argv[2],&address.sin_addr)==1&&connect(s.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);
    const char wire=mode=="download"?'D':mode=="upload"?'U':'L';write_all(s.fd,&wire,1);
    char marker;read_all(s.fd,&marker,1);check(marker=='R');
    if(mode=="probe"){
      std::cout<<"H2_PROBE_READY"<<std::endl;json samples=json::array();std::array<uint8_t,32>b{},reply{};
      const auto end=Clock::now()+std::chrono::seconds(60);
      while(!stopped&&Clock::now()<end){for(size_t i=0;i<b.size();i++)b[i]=uint8_t(i+samples.size());
        const double start=now();write_all(s.fd,b.data(),b.size());read_all(s.fd,reply.data(),reply.size());check(reply==b);
        samples.push_back({{"startMs",start},{"endMs",now()}});std::this_thread::sleep_for(std::chrono::milliseconds(50));}
      check(stopped);std::cout<<json({{"kind","probe"},{"verified",true},{"samples",samples}}).dump()<<std::endl;return 0;
    }
    const double start=now();write_all(s.fd,"G",1);bulk(s.fd,mode=="upload");read_all(s.fd,&marker,1);check(marker=='K');
    const double finish=now();write_all(s.fd,"K",1);uint32_t peer;read_all(s.fd,&peer,sizeof(peer));
    rusage usage{};check(getrusage(RUSAGE_SELF,&usage)==0);
    std::cout<<json({{"kind",mode},{"verified",true},{"bytes",total},{"startMs",start},{"endMs",finish},
      {"goodputMbps",total*8/((finish-start)*1000)},{"localRetransmits",retrans(s.fd)},{"peerRetransmits",ntohl(peer)},
      {"clockTicksPerSecond",sysconf(_SC_CLK_TCK)},
      {"applicationCpuSeconds",usage.ru_utime.tv_sec+usage.ru_utime.tv_usec/1e6+usage.ru_stime.tv_sec+usage.ru_stime.tv_usec/1e6}}).dump()<<std::endl;
    return 0;
  }catch(const std::exception&e){std::cerr<<e.what()<<std::endl;return 1;}
}
