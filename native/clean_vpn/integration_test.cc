// Packet generation/checking lives in C++, never in the Node control harness.
#include "protocol.hpp"
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <chrono>
#include <iostream>
#include <thread>
#include <fstream>
#include <dirent.h>
using namespace cvpn;
using json=nlohmann::json;
using Clock=std::chrono::steady_clock;
static void require(bool b,const char* e){if(!b)throw std::runtime_error(e);}
static size_t fd_count(pid_t pid){
  auto path="/proc/"+std::to_string(pid)+"/fd";
  DIR* dir=opendir(path.c_str());require(dir!=nullptr,"fd_directory");size_t count=0;
  while(auto* entry=readdir(dir))if(entry->d_name[0]!='.')++count;
  closedir(dir);return count;
}
struct Child {
  int packet=-1,control=-1,events=-1;pid_t pid=-1;std::string input;
  Child(const char* exe,const char* config){
    int pkt[2],cmd[2],out[2];require(socketpair(AF_UNIX,SOCK_DGRAM,0,pkt)==0&&pipe(cmd)==0&&pipe(out)==0,"pipes");
    const auto parent=getpid();pid=fork();require(pid>=0,"fork");
    if(pid==0){
      if(prctl(PR_SET_PDEATHSIG,SIGKILL)!=0||getppid()!=parent)_exit(126);
      dup2(cmd[0],0);dup2(out[1],1);dup2(pkt[1],4);
      for(int fd=3;fd<1024;fd++)if(fd!=4)close(fd);
      execl(exe,exe,"--config",config,"--test-packet-fd","4",nullptr);_exit(127);
    }
    close(pkt[1]);close(cmd[0]);close(out[1]);packet=pkt[0];control=cmd[1];events=out[0];
    fcntl(events,F_SETFL,O_NONBLOCK);
  }
  ~Child(){
    if(pid>0){kill(pid,SIGCONT);kill(pid,SIGKILL);waitpid(pid,nullptr,0);}
    for(int fd:{packet,control,events})if(fd>=0)close(fd);
  }
  void command(const char* s){require(write(control,s,strlen(s))==ssize_t(strlen(s)),"command");}
  json await_state(const std::string& wanted,int ms=12000){
    auto end=Clock::now()+std::chrono::milliseconds(ms);
    while(Clock::now()<end){
      size_t e;
      while((e=input.find('\n'))!=std::string::npos){auto j=json::parse(input.substr(0,e));input.erase(0,e+1);
        std::cout<<"engine "<<pid<<" "<<j.dump()<<"\n";
        require(j.size()==7&&!j.contains("packet")&&!j.contains("payload"),"metadata_only");
        if(j.at("state")==wanted)return j;
      }
      char b[4096];ssize_t n=read(events,b,sizeof(b));
      if(n>0)input.append(b,n);else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,20);}
    }
    throw std::runtime_error("state_timeout: "+wanted);
  }
  void reject_for(int ms){
    auto end=Clock::now()+std::chrono::milliseconds(ms);bool attempted=false;
    while(Clock::now()<end){
      size_t e;
      while((e=input.find('\n'))!=std::string::npos){
        auto j=json::parse(input.substr(0,e));input.erase(0,e+1);
        require(j.at("state")!="ready","unexpected_auth_success");
        attempted|=j.at("state")=="handshake";
      }
      char b[4096];ssize_t n=read(events,b,sizeof(b));
      if(n>0)input.append(b,n);else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,20);}
    }
    require(attempted,"no_handshake_attempt");
  }
  json healthy_status(){
    command("{\"op\":\"status\"}\n");
    auto end=Clock::now()+std::chrono::seconds(2);
    while(Clock::now()<end){
      size_t e;
      while((e=input.find('\n'))!=std::string::npos){
        auto j=json::parse(input.substr(0,e));input.erase(0,e+1);
        require(j.size()==7&&j.at("event")=="status"&&j.at("state")=="ready","soak_unexpected_session_event");
        return j;
      }
      char b[4096];auto n=read(events,b,sizeof(b));
      if(n>0)input.append(b,n);else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,20);}
    }
    throw std::runtime_error("soak_status_timeout");
  }
  void stop(){
    command("{\"op\":\"stop\"}\n");await_state("stopped",2000);
    auto end=Clock::now()+std::chrono::seconds(2);int status;
    while(Clock::now()<end){if(waitpid(pid,&status,WNOHANG)==pid){pid=-1;require(WIFEXITED(status)&&WEXITSTATUS(status)==0,"exit_status");return;}std::this_thread::sleep_for(std::chrono::milliseconds(10));}
    throw std::runtime_error("stop_deadline");
  }
};
static Bytes packet(size_t n,bool reverse,uint8_t seed){
  Bytes b(n);for(size_t i=20;i<n;i++)b[i]=(i*17+seed)%251;
  b[0]=0x45;b[2]=n>>8;b[3]=n;b[8]=64;b[9]=17;
  const uint8_t src[]={10,99,0,2},dst[]={1,1,1,1};
  memcpy(b.data()+12,reverse?dst:src,4);memcpy(b.data()+16,reverse?src:dst,4);
  uint32_t s=0;for(size_t i=0;i<20;i+=2)s+=(uint16_t(b[i])<<8)|b[i+1];
  while(s>>16) s=(s&65535)+(s>>16);
  b[10]=(~s)>>8;b[11]=~s;return b;
}
static void transfer(Child& from,Child& to,size_t n,bool reverse,uint8_t seed){
  auto b=packet(n,reverse,seed);require(send(from.packet,b.data(),b.size(),0)==ssize_t(b.size()),"packet_send");
  pollfd p{to.packet,POLLIN,0};require(poll(&p,1,3000)>0,"packet_timeout");
  Bytes got(65536);ssize_t len=recv(to.packet,got.data(),got.size(),0);require(len>0,"packet_receive");got.resize(len);require(got==b,"packet_bytes");
}
static void reflect(Child& client,size_t n,uint8_t seed){
  // The legacy reference echoes framed bytes. Use an inbound-addressed test
  // packet so the production client's destination isolation remains enabled.
  auto b=packet(n,true,seed);require(send(client.packet,b.data(),b.size(),0)==ssize_t(b.size()),"echo_send");
  pollfd p{client.packet,POLLIN,0};require(poll(&p,1,3000)>0,"echo_timeout");
  Bytes got(65536);auto len=recv(client.packet,got.data(),got.size(),0);require(len>0,"echo_receive");
  got.resize(len);require(got==b,"echo_bytes");
}
static long rss(pid_t pid){
  std::ifstream stat("/proc/"+std::to_string(pid)+"/status");std::string line;
  while(std::getline(stat,line))if(line.rfind("VmRSS:",0)==0)return std::stol(line.substr(6));
  throw std::runtime_error("rss_sample");
}
static void soak(Child& client,Child* server,int seconds){
  const auto start=Clock::now(),end=start+std::chrono::seconds(seconds);
  auto sample=start;uint64_t rounds=0,bytes=0;long peak=0,growth=0;size_t samples=0;
  const auto crss=rss(client.pid),srss=server?rss(server->pid):0;
  const auto cfds=fd_count(client.pid),sfds=server?fd_count(server->pid):0;
  const size_t sizes[]={64,1400,8192,65535};
  while(Clock::now()<end){
    auto size=sizes[rounds%4];
    if(server){transfer(client,*server,size,false,rounds);transfer(*server,client,size,true,rounds);}
    else reflect(client,size,rounds);
    rounds++;bytes+=size*2;
    if(Clock::now()>=sample){
      for(auto* child:{&client,server})if(child){
        auto state=child->healthy_status();
        require(state.at("tx_packets")==rounds&&state.at("rx_packets")==rounds&&state.at("dropped_packets")==0,"soak_packet_counts");
        require(fd_count(child->pid)==(child==&client?cfds:sfds),"soak_fd_leak");
        auto memory=rss(child->pid);peak=std::max(peak,memory);require(memory<128*1024,"soak_rss_limit");
        growth=std::max(growth,memory-(child==&client?crss:srss));require(growth<32*1024,"soak_rss_growth");
      }
      samples++;sample=Clock::now()+std::chrono::seconds(5);
    }
  }
  for(auto* child:{&client,server})if(child){
    auto state=child->healthy_status();
    require(state.at("tx_packets")==rounds&&state.at("rx_packets")==rounds&&state.at("dropped_packets")==0,"soak_final_counts");
  }
  std::cout<<"soak "<<json({{"seconds",std::chrono::duration<double>(Clock::now()-start).count()},
    {"packets",rounds*2},{"bytes",bytes},{"resource_samples",samples},{"peak_rss_kib",peak},{"max_rss_growth_kib",growth},
    {"unexpected_reconnects",0},{"dropped_packets",0},{"payload_verified",true}}).dump()<<" PASS\n";
}
int main(int argc,char** argv){
  signal(SIGPIPE,SIG_IGN);
  std::cout<<std::unitbuf;
  try{
    if(argc==4&&std::string(argv[3]).rfind("client-event:",0)==0){
      Child client(argv[1],argv[2]);client.await_state(std::string(argv[3]).substr(13));
      pollfd p{client.packet,POLLIN,0};require(poll(&p,1,50)==0,"fault_injected_packet");
      client.await_state("ready");reflect(client,1400,7);client.stop();
      std::cout<<"classified session failure and reconnect PASS\n";return 0;
    }
    if(argc==5&&std::string(argv[3])=="client-soak"){
      int seconds=std::stoi(argv[4]);require(seconds>=10&&seconds<=600,"soak_duration");
      Child client(argv[1],argv[2]);client.await_state("ready");soak(client,nullptr,seconds);client.stop();return 0;
    }
    if(argc==6&&std::string(argv[4])=="soak"){
      int seconds=std::stoi(argv[5]);require(seconds>=10&&seconds<=600,"soak_duration");
      Child server(argv[1],argv[3]);server.await_state("listening");
      Child client(argv[1],argv[2]);client.await_state("ready");server.await_state("ready");
      soak(client,&server,seconds);client.stop();server.stop();return 0;
    }
    if(argc==4&&std::string(argv[3])=="client-handshake"){
      Child client(argv[1],argv[2]);client.await_state("ready");client.stop();
      std::cout<<"legacy exit handshake PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3]).rfind("client-reject:",0)==0){
      Child client(argv[1],argv[2]);
      auto state=client.await_state(std::string(argv[3]).substr(14));
      require(state.at("tx_packets")==0&&state.at("rx_packets")==0,"rejected_tls_packets");
      client.reject_for(400);client.stop();
      std::cout<<"TLS rejected with expected diagnostic PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3])=="exit-denied"){
      Child server(argv[1],argv[2]);server.await_state("listening");std::cout<<"native exit listening\n";
      server.reject_for(1200);pollfd p{server.packet,POLLIN,0};require(poll(&p,1,50)==0,"unauthenticated_h2_injection");server.stop();
      std::cout<<"unauthenticated H2 rejected PASS\n";return 0;
    }
    if(argc==4&&(std::string(argv[3])=="exit-handshake"||std::string(argv[3])=="exit-malformed")){
      Child server(argv[1],argv[2]);server.await_state("listening");
      std::cout<<"native exit listening\n";server.await_state("ready");
      if(std::string(argv[3])=="exit-malformed"){
        server.await_state("invalid_frame_length");pollfd p{server.packet,POLLIN,0};require(poll(&p,1,50)==0,"malformed_injection");
        std::cout<<"malformed frame rejected before packet injection PASS\n";
      }
      server.stop();
      std::cout<<"legacy client handshake PASS\n";return 0;
    }
    require(argc==4||argc==5,"usage");Child server(argv[1],argv[3]);server.await_state("listening");
    Child client(argv[1],argv[2]);
    if(argc==5){
      require(std::string(argv[4])=="reject","mode");
      auto b=packet(64,false,1);require(send(client.packet,b.data(),b.size(),0)==ssize_t(b.size()),"packet_send");
      client.reject_for(2000);server.reject_for(100);pollfd p{server.packet,POLLIN,0};require(poll(&p,1,50)==0,"unauthenticated_packet");
      client.stop();server.stop();std::cout<<"negative authentication PASS\n";return 0;
    }
    client.await_state("ready");server.await_state("ready");
    for(size_t n:{28,64,1400,1500,8192,65535}){transfer(client,server,n,false,1);transfer(server,client,n,true,2);}
    std::cout<<"bidirectional sizes PASS\n";
    for(int i=0;i<1000;i++){transfer(client,server,64,false,i);transfer(server,client,1400,true,i);}
    std::cout<<"2000 packets PASS\n";
    client.command("{\"op\":\"uplink\",\"ready\":false}\n");client.await_state("waiting_uplink");
    client.command("{\"op\":\"uplink\",\"ready\":true}\n");client.await_state("ready");server.await_state("ready");
    transfer(client,server,4096,false,3);transfer(server,client,4096,true,4);
    std::cout<<"uplink reconnect PASS\n";
    kill(server.pid,SIGSTOP);auto begin=Clock::now();client.await_state("h2_ping_timeout",9000);
    kill(server.pid,SIGCONT);client.await_state("ready",15000);server.await_state("ready",15000);
    transfer(client,server,1400,false,5);transfer(server,client,1400,true,6);
    std::cout<<"blackhole recovery "<<std::chrono::duration<double>(Clock::now()-begin).count()<<"s PASS\n";
    const auto client_fds=fd_count(client.pid),server_fds=fd_count(server.pid);
    for(int round=0;round<5;++round){
      client.command("{\"op\":\"uplink\",\"ready\":false}\n");client.await_state("waiting_uplink");
      client.command("{\"op\":\"uplink\",\"ready\":true}\n");client.await_state("ready");server.await_state("ready");
      transfer(client,server,1400,false,round);transfer(server,client,1400,true,round);
      require(fd_count(client.pid)==client_fds&&fd_count(server.pid)==server_fds,"reconnect_fd_leak");
    }
    std::cout<<"five repeated reconnects, stable descriptor counts PASS\n";
    // Stop consuming exit packets, fill the path, and prove control stays live.
    fcntl(client.packet,F_SETFL,O_NONBLOCK);auto pressure=packet(1400,false,9);int accepted=0;
    auto until=Clock::now()+std::chrono::milliseconds(1500);
    while(Clock::now()<until){
      auto n=send(client.packet,pressure.data(),pressure.size(),0);
      if(n==ssize_t(pressure.size()))accepted++;
      else require(errno==EAGAIN||errno==EWOULDBLOCK,"pressure_send");
      if(accepted>=10000)break;
    }
    client.command("{\"op\":\"status\"}\n");client.await_state("ready",2000);
    server.command("{\"op\":\"status\"}\n");server.await_state("ready",2000);
    for(auto pid:{client.pid,server.pid}){
      std::ifstream stat("/proc/"+std::to_string(pid)+"/status");std::string line;bool found=false;
      while(std::getline(stat,line))if(line.rfind("VmRSS:",0)==0){auto kb=std::stoll(line.substr(6));require(kb<128*1024,"bounded_rss");found=true;std::cout<<"pressure "<<line<<"\n";}
      require(found,"rss_sample");
    }
    std::cout<<"backpressure control responsive, accepted "<<accepted<<" packets PASS\n";
    client.stop();server.stop();std::cout<<"native integration PASS\n";return 0;
  }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
