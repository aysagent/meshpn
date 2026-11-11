// Linux integration harness for the same CVPN_ANDROID entry used by JNI.
// socketpairs model packet FDs; actual TLS/H2/H1 and authentication use TCP.
#include "android_platform.hpp"
#include "protocol.hpp"
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <thread>
#include <iostream>
#include <mutex>
#include <map>
namespace cvpn {thread_local AndroidRuntime* android_runtime=nullptr;}
using namespace cvpn;
using json=nlohmann::json;
using Clock=std::chrono::steady_clock;
static void need(bool ok,const char* code){if(!ok)throw std::runtime_error(code);}
struct Exit {
  pid_t pid=-1;int packet=-1,control=-1;
  Exit(const char* exe,const char* config){
    int pk[2],cmd[2];need(socketpair(AF_UNIX,SOCK_DGRAM,0,pk)==0&&pipe(cmd)==0,"exit_pipes");
    pid=fork();need(pid>=0,"fork");
    if(!pid){
      dup2(cmd[0],0);dup2(pk[1],4);
      // The CLI exit legitimately sets its stdout nonblocking. Give it a
      // separate open file description so it cannot alter the harness's flags.
      int sink=open("/dev/null",O_WRONLY);if(sink<0)_exit(126);dup2(sink,1);
      for(int fd=3;fd<1024;fd++)if(fd!=4)close(fd);
      execl(exe,exe,"--config",config,"--test-packet-fd","4",nullptr);_exit(127);
    }
    close(pk[1]);close(cmd[0]);packet=pk[0];control=cmd[1];
  }
  ~Exit(){if(pid>0){kill(pid,SIGKILL);waitpid(pid,nullptr,0);}if(packet>=0)close(packet);if(control>=0)close(control);}
};
struct Client {
  AndroidRuntime runtime;std::thread worker;int packet=-1;std::atomic<int> protections{0};int result=-1;
  std::mutex mutex;std::condition_variable changed;std::map<std::string,int> states;
  explicit Client(const char* path,bool protect_ok=true){
    int pk[2];need(socketpair(AF_UNIX,SOCK_DGRAM,0,pk)==0,"client_pair");packet=pk[0];runtime.tun_fd=pk[1];
    runtime.protect=[this,protect_ok](int fd){
      sockaddr_storage address{};socklen_t length=sizeof(address);
      need(getpeername(fd,reinterpret_cast<sockaddr*>(&address),&length)<0&&errno==ENOTCONN,"protect_before_connect");
      ++protections;return protect_ok;
    };
    runtime.event=[this](const std::string& line){
      auto j=json::parse(line);
      if(j.value("event","")=="state"){
        std::lock_guard<std::mutex> lock(mutex);++states[j.at("state").get<std::string>()];changed.notify_all();
      }
    };
    worker=std::thread([this,path]{
      android_runtime=&runtime;char name[]="android-test",mode[]="--config";
      char* args[]={name,mode,const_cast<char*>(path)};
      result=cvpn_android_main(3,args);android_runtime=nullptr;
    });
  }
  ~Client(){runtime.stop=true;if(worker.joinable())worker.join();close(packet);close(runtime.tun_fd);}
  void await(const char* name,int count=1){
    std::unique_lock<std::mutex> lock(mutex);
    need(changed.wait_for(lock,std::chrono::seconds(10),[&]{return states[name]>=count;}),"state_timeout");
  }
  void stop(){
    const auto start=Clock::now();runtime.stop=true;worker.join();
    need(result==0,"stop_result");need(Clock::now()-start<std::chrono::seconds(2),"bounded_stop");
    need(fcntl(runtime.tun_fd,F_GETFD)>=0,"borrowed_tun_owned_by_host");
  }
};
static Bytes packet(bool reverse,unsigned seed,bool dns=false){
  Bytes p(1280,uint8_t(seed));p[0]=0x45;p[1]=0;p[2]=5;p[3]=0;p[6]=p[7]=0;p[8]=64;p[9]=dns?17:6;p[10]=p[11]=0;
  const uint8_t local[]={10,99,0,2},remote[]={1,1,1,1};
  std::copy_n(reverse?remote:local,4,p.data()+12);std::copy_n(reverse?local:remote,4,p.data()+16);
  if(dns){p[20]=reverse?0:0xc0;p[21]=reverse?53:1;p[22]=reverse?0xc0:0;p[23]=reverse?1:53;
    p[24]=4;p[25]=236;p[26]=p[27]=0;}
  uint32_t sum=0;for(int i=0;i<20;i+=2)sum+=(uint16_t(p[i])<<8)|p[i+1];while(sum>>16)sum=(sum&65535)+(sum>>16);
  p[10]=uint8_t(~sum>>8);p[11]=uint8_t(~sum);return p;
}
static void transfer(int from,int to,const Bytes& data){
  need(send(from,data.data(),data.size(),MSG_NOSIGNAL)==ssize_t(data.size()),"send_packet");
  pollfd p{to,POLLIN,0};need(poll(&p,1,3000)>0,"packet_timeout");
  Bytes got(65536);auto size=read(to,got.data(),got.size());need(size>0,"read_packet");got.resize(size);need(got==data,"packet_bytes");
}
int main(int argc,char** argv){
  try{
    need(argc==4||argc==5,"usage_exit_exe_client_exit_optional_reject");
    Exit server(argv[1],argv[3]);
    struct sigaction before{},after{};sigaction(SIGPIPE,nullptr,&before);
    const int stdin_flags=fcntl(0,F_GETFL),stdout_flags=fcntl(1,F_GETFL);
    if(argc==5){Client client(argv[2]);std::this_thread::sleep_for(std::chrono::seconds(2));
      {std::lock_guard<std::mutex> lock(client.mutex);need(client.states["ready"]==0&&client.protections>0,"rejected_credentials");}
      pollfd p{server.packet,POLLIN,0};need(poll(&p,1,0)==0,"no_packet_injection");client.stop();
      std::cout<<"android negative authentication PASS\n";return 0;}
    {
      Client client(argv[2]);client.await("ready");
      for(unsigned i=0;i<64;i++){
        transfer(client.packet,server.packet,packet(false,i,i%2==0));
        transfer(server.packet,client.packet,packet(true,i,i%2==0));
      }
      ++client.runtime.network_generation;client.await("ready",2);
      need(client.protections>=2,"protect_every_reconnect");
      transfer(client.packet,server.packet,packet(false,99));transfer(server.packet,client.packet,packet(true,99));client.stop();
    }
    {
      Client denied(argv[2],false);denied.await("android_socket_protect");
      {std::lock_guard<std::mutex> lock(denied.mutex);need(denied.states["handshake"]==0,"no_unprotected_tls");}
      denied.stop();
    }
    // Repeat after teardown: no process-global stop flag or stale descriptors.
    {Client client(argv[2]);client.await("ready");client.stop();}
    sigaction(SIGPIPE,nullptr,&after);need(before.sa_handler==after.sa_handler,"process_signal_unchanged");
    need(fcntl(0,F_GETFL)==stdin_flags&&fcntl(1,F_GETFL)==stdout_flags,"stdio_flags_unchanged");
    std::cout<<"android adapter PASS: packets/DNS-port traffic, reconnect/protect, denied protect, stop/restart, borrowed FD, SIGPIPE isolation\n";
    return 0;
  }catch(const std::exception& e){std::cerr<<"android adapter FAIL: "<<e.what()<<"\n";return 1;}
}
