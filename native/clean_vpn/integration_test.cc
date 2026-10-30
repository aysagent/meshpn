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
#include <arpa/inet.h>
#include <memory>
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
  bool service=false;
  int packet=-1,control=-1,events=-1;pid_t pid=-1;std::string input;
  Child(const char* exe,const char* config,bool service_mode=false):service(service_mode){
    int pkt[2],cmd[2],out[2];require(socketpair(AF_UNIX,SOCK_DGRAM,0,pkt)==0&&pipe(cmd)==0&&pipe(out)==0,"pipes");
    const auto parent=getpid();pid=fork();require(pid>=0,"fork");
    if(pid==0){
      if(prctl(PR_SET_PDEATHSIG,SIGKILL)!=0||getppid()!=parent)_exit(126);
      dup2(cmd[0],0);dup2(out[1],1);dup2(pkt[1],4);
      for(int fd=3;fd<1024;fd++)if(fd!=4)close(fd);
      if(service)execl(exe,exe,"--config",config,"--test-packet-fd","4","--service",nullptr);
      else execl(exe,exe,"--config",config,"--test-packet-fd","4",nullptr);
      _exit(127);
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
        if(j.at("event")=="peer_reload_ready"){
          const auto digest=j.at("config_sha256").get<std::string>();
          require(j.size()==3&&j.at("version")==1&&digest.size()==64
            &&digest.find_first_not_of("0123456789abcdef")==std::string::npos,"reload_ready_metadata");continue;
        }
        if(j.at("event")=="peer_address_rejected"){
          in_addr src{},dst{};auto protocol=j.at("protocol").get<int>();
          require(j.size()==6&&(j.at("role")=="client"||j.at("role")=="exit")&&protocol>=0&&protocol<=255
            &&inet_pton(AF_INET,j.at("source").get<std::string>().c_str(),&src)==1
            &&inet_pton(AF_INET,j.at("destination").get<std::string>().c_str(),&dst)==1,"address_metadata");continue;
        }
        if(j.at("event")=="diagnostics"){
          require(j.size()==8&&j.at("diagnostics").at("schema")==1&&j.at("diagnostics").at("scope")=="process-lifetime-sampled","diagnostics_metadata");continue;
        }
        require(j.size()==7&&!j.contains("packet")&&!j.contains("payload"),"metadata_only");
        if(j.at("state")==wanted)return j;
      }
      char b[4096];ssize_t n=read(events,b,sizeof(b));
      if(n>0)input.append(b,n);else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,20);}
    }
    throw std::runtime_error("state_timeout: "+wanted);
  }
  json await_reload(const char* status,uint64_t revision) {
    const auto end=Clock::now()+std::chrono::seconds(3);
    while(Clock::now()<end) {
      size_t e;
      while((e=input.find('\n'))!=std::string::npos) {
        auto j=json::parse(input.substr(0,e));input.erase(0,e+1);
        if(j.at("event")!="peer_reload")continue;
        require(j.at("status")==status&&j.at("revision")==revision,"reload_result");
        require(j.at("config_sha256").get<std::string>().size()==64,"reload_digest");
        std::cout<<"RELOAD_ACK "<<j.dump()<<"\n";return j;
      }
      char b[4096];auto n=read(events,b,sizeof(b));
      if(n>0)input.append(b,n);else {require(n!=0,"reload_engine_exit");pollfd p{events,POLLIN,0};poll(&p,1,10);}
    }
    throw std::runtime_error("reload_ack_timeout");
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
  json budget_status(bool healthy=true){
    command("{\"op\":\"status\"}\n");
    const auto end=Clock::now()+std::chrono::seconds(2);
    while(Clock::now()<end){
      size_t e;
      while((e=input.find('\n'))!=std::string::npos){
        auto j=json::parse(input.substr(0,e));input.erase(0,e+1);
        if(healthy)require(j.at("state")=="ready","budget_unexpected_session_event");
        if(j.at("event")=="status"){
          require(j.size()==8&&j.contains("fixture_h2_budget"),"budget_fixture_required");return j;
        }
      }
      char b[4096];const auto n=read(events,b,sizeof(b));
      if(n>0){input.append(b,n);require(input.size()<16384,"budget_event_bound");}
      else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,10);}
    }
    throw std::runtime_error("budget_status_timeout");
  }
  json diagnostic_status(){
    command("{\"op\":\"diagnostics\"}\n");const auto end=Clock::now()+std::chrono::seconds(2);
    while(Clock::now()<end){
      size_t e;while((e=input.find('\n'))!=std::string::npos){
        const auto raw=input.substr(0,e);auto j=json::parse(raw);input.erase(0,e+1);
        if(j.at("event")!="diagnostics")continue;
        require(j.size()==8&&raw.size()<4096&&j.at("state")=="ready","diagnostics_event_bound");
        const auto& d=j.at("diagnostics");require(d.at("schema")==1&&d.at("scope")=="process-lifetime-sampled"&&d.at("packet").at("ready_events")>=1,"diagnostics_packet_ready");
        require(!d.contains("config")&&!d.contains("secret")&&!d.contains("payload"),"diagnostics_privacy");return d;
      }
      char b[4096];const auto n=read(events,b,sizeof(b));if(n>0)input.append(b,n);else{require(n!=0,"engine_exited");pollfd p{events,POLLIN,0};poll(&p,1,20);}
    }throw std::runtime_error("diagnostics_timeout");
  }
  void stop(){
    if(service)kill(pid,SIGTERM);else command("{\"op\":\"stop\"}\n");
    await_state("stopped",2000);
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
static void peer_transfer(Child& from,Child& to,Child& uninvolved,bool reverse,uint8_t peer){
  auto b=packet(1400,reverse,peer);b[reverse?19:15]=peer;b[10]=b[11]=0;
  uint32_t sum=0;for(int i=0;i<20;i+=2)sum+=(uint16_t(b[i])<<8)|b[i+1];
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  b[10]=(~sum)>>8;b[11]=~sum;
  require(send(from.packet,b.data(),b.size(),0)==ssize_t(b.size()),"multi_send");
  pollfd p{to.packet,POLLIN,0};require(poll(&p,1,2000)>0,"multi_timeout");
  Bytes got(65536);auto n=recv(to.packet,got.data(),got.size(),0);require(n>0,"multi_read");got.resize(n);
  require(got==b,"multi_bytes");
  pollfd isolated{uninvolved.packet,POLLIN,0};require(poll(&isolated,1,0)==0,"cross_peer_injection");
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
static void reflect_pair(Child& client,uint8_t seed){
  // Two packets queued before reconnect: the retained wake packet must not
  // be overtaken by the second packet when the response headers arrive.
  auto first=packet(1400,true,seed),second=packet(1400,true,seed+1);
  for(const auto* b:{&first,&second})require(send(client.packet,b->data(),b->size(),0)==ssize_t(b->size()),"idle_pair_send");
  for(const auto* b:{&first,&second}){
    pollfd p{client.packet,POLLIN,0};require(poll(&p,1,3000)>0,"idle_pair_timeout");
    Bytes got(65536);auto n=recv(client.packet,got.data(),got.size(),0);require(n>0,"idle_pair_read");got.resize(n);
    require(got==*b,"idle_pair_order");
  }
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
    child->diagnostic_status();
  }
  std::cout<<"soak "<<json({{"seconds",std::chrono::duration<double>(Clock::now()-start).count()},
    {"packets",rounds*2},{"bytes",bytes},{"resource_samples",samples},{"peak_rss_kib",peak},{"max_rss_growth_kib",growth},
    {"unexpected_reconnects",0},{"dropped_packets",0},{"payload_verified",true}}).dump()<<" PASS\n";
}
static json discover_address(const char* engine,const std::string& config,int success){
  int output[2];require(pipe(output)==0,"discovery_pipe");const auto parent=getpid();const auto child=fork();require(child>=0,"discovery_fork");
  if(child==0){
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)!=0||getppid()!=parent)_exit(126);
    dup2(output[1],STDOUT_FILENO);for(int fd=3;fd<1024;++fd)close(fd);
    execl(engine,engine,"--discover-address",config.c_str(),nullptr);_exit(127);
  }
  close(output[1]);fcntl(output[0],F_SETFL,O_NONBLOCK);std::string text;int status=0;bool ended=false;
  const auto deadline=Clock::now()+std::chrono::seconds(13);
  while(Clock::now()<deadline){
    char buffer[2048];const auto n=read(output[0],buffer,sizeof(buffer));if(n>0)text.append(buffer,n);
    if(text.size()>4096)break;
    if(waitpid(child,&status,WNOHANG)==child){ended=true;ssize_t remaining;while((remaining=read(output[0],buffer,sizeof(buffer)))>0)text.append(buffer,remaining);break;}
    pollfd fd{output[0],POLLIN,0};poll(&fd,1,10);
  }
  close(output[0]);if(!ended){kill(child,SIGKILL);waitpid(child,&status,0);throw std::runtime_error("discovery_deadline");}
  require(WIFEXITED(status)&&(WEXITSTATUS(status)==0||WEXITSTATUS(status)==1),"discovery_exit_status");
  if(success>=0)require((WEXITSTATUS(status)==0)==bool(success),"discovery_expected_status");
  if(WEXITSTATUS(status)!=0){require(text.empty(),"unverified_discovery_output");return {};}
  auto result=json::parse(text);require(result.size()==5&&result.at("version")==1&&result.at("event")=="address_discovery"&&result.at("status")=="verified"&&result.at("assignment")=="v1","discovery_metadata");return result;
}
#include "h2_budget_test.hpp"
int main(int argc,char** argv){
  signal(SIGPIPE,SIG_IGN);
  std::cout<<std::unitbuf;
  try{
    if(argc==6&&std::string(argv[4])=="address-concurrency"){
      const std::string directory=argv[2],config=argv[3],a_config=directory+"/a.json",probe_config=directory+"/discover.json";
      Child server(argv[1],config.c_str(),true);server.await_state("listening");
      Child a(argv[1],a_config.c_str());a.await_state("ready");server.await_state("ready");
      const auto server_pid=server.pid,client_pid=a.pid;const auto baseline_fd=fd_count(server.pid);const auto baseline_rss=rss(server.pid);
      uint64_t revision=0;unsigned verified=0,refused=0;
      const auto reload=[&](const char* stage){
        std::ifstream source(directory+"/"+stage+".json");const std::string bytes((std::istreambuf_iterator<char>(source)),std::istreambuf_iterator<char>());
        {std::ofstream output(config+".next");output<<bytes;require(bool(output),"discovery_reload_write");}
        require(rename((config+".next").c_str(),config.c_str())==0&&kill(server.pid,SIGHUP)==0,"discovery_reload");server.await_reload("applied",++revision);
      };
      const auto concurrent=[&](const char* stage){
        std::array<json,4> results;std::array<std::exception_ptr,4> errors;std::array<std::thread,4> workers;
        for(size_t i=0;i<workers.size();++i)workers[i]=std::thread([&,i]{try{results[i]=discover_address(argv[5],probe_config,-1);}catch(...){errors[i]=std::current_exception();}});
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        try{reload(stage);transfer(a,server,1400,false,3);transfer(server,a,1400,true,4);}
        catch(...){for(auto& worker:workers)worker.join();throw;}
        for(auto& worker:workers)worker.join();
        for(size_t i=0;i<results.size();++i){if(errors[i])std::rethrow_exception(errors[i]);if(results[i].is_null()){++refused;continue;}
          const auto address=results[i].at("ipv4");require(address=="10.99.0.3"||address=="10.99.0.4","discovery_non_registry_address");++verified;}
        a.healthy_status();require(server.pid==server_pid&&a.pid==client_pid,"discovery_churn_restarted_session");
      };
      for(int round=0;round<6;++round)concurrent(round%2?"move3":"move4");
      require(discover_address(argv[5],probe_config,true).at("ipv4")=="10.99.0.3","discovery_final_mapping");
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      std::ifstream maps("/proc/"+std::to_string(server.pid)+"/maps");
      const std::string mapping((std::istreambuf_iterator<char>(maps)),std::istreambuf_iterator<char>());
      // ASAN allocator/redzones/thread metadata change RSS accounting. Keep
      // the production 8-MiB drift budget unchanged; instrumented processes
      // get a separate bounded budget and must also pass leak detection.
      const bool sanitized=mapping.find("libasan.so")!=std::string::npos;
      const long rss_limit=sanitized?32768:8192;
      std::cout<<"ADDRESS_RESOURCES "<<json({{"baselineFds",baseline_fd},{"fds",fd_count(server.pid)},{"baselineRssKiB",baseline_rss},{"rssKiB",rss(server.pid)},{"sanitized",sanitized},{"growthLimitKiB",rss_limit}}).dump()<<"\n";
      require(fd_count(server.pid)<=baseline_fd&&rss(server.pid)-baseline_rss<rss_limit,"discovery_churn_resources");
      concurrent("revoke");discover_address(argv[5],probe_config,false);
      transfer(a,server,65535,false,5);transfer(server,a,65535,true,6);a.healthy_status();
      a.stop();server.stop();std::cout<<"ADDRESS_CONCURRENCY_PASS "<<json({{"verified",verified},{"refusedDuringReload",refused},{"reloads",revision},{"existingSessionPreserved",true},{"resourcesReclaimed",true}}).dump()<<"\n";return 0;
    }
    if(argc==6&&std::string(argv[4])=="address-assignment"){
      const std::string directory=argv[2],config=argv[3],a_config=directory+"/a.json",b_config=directory+"/b.json";
      Child server(argv[1],config.c_str(),true);server.await_state("listening");
      Child a(argv[1],a_config.c_str());a.await_state("ready");server.await_state("ready");
      const auto server_pid=server.pid,client_pid=a.pid;
      require(discover_address(argv[5],a_config,true).at("ipv4")=="10.99.0.2","discovery_active_identity");
      require(discover_address(argv[5],directory+"/discover.json",true).at("ipv4")=="10.99.0.3","discovery_registry_identity");
      require(discover_address(argv[5],directory+"/mismatch.json",true).at("ipv4")=="10.99.0.3","discovery_ignores_claimed_address");
      discover_address(argv[5],directory+"/wrong-key.json",false);discover_address(argv[5],directory+"/wrong-name.json",false);
      {Child mismatch(argv[1],(directory+"/mismatch.json").c_str());mismatch.reject_for(700);mismatch.stop();}
      Child b(argv[1],b_config.c_str());b.await_state("ready");
      for(int i=0;i<4;++i){peer_transfer(a,server,b,false,2);peer_transfer(server,b,a,true,3);}
      a.healthy_status();require(server.pid==server_pid&&a.pid==client_pid,"discovery_restarted_existing_session");
      std::ifstream source(directory+"/revoke.json");const std::string bytes((std::istreambuf_iterator<char>(source)),std::istreambuf_iterator<char>());
      {std::ofstream output(config+".next");output<<bytes;require(bool(output),"discovery_revoke_write");}
      require(rename((config+".next").c_str(),config.c_str())==0&&kill(server.pid,SIGHUP)==0,"discovery_revoke");server.await_reload("applied",1);
      b.reject_for(700);discover_address(argv[5],directory+"/discover.json",false);
      transfer(a,server,1400,false,1);transfer(server,a,1400,true,2);a.healthy_status();
      b.stop();a.stop();server.stop();std::cout<<"ADDRESS_ASSIGNMENT_PASS no_TUN_discovery_auth_registry_bound_active_session_preserved_mismatch_revoke\n";return 0;
    }
    if(argc==5&&std::string(argv[4])=="peer-reload") {
      const std::string directory=argv[2], config=argv[3];
      const auto a_config=directory+"/a.json",b_config=directory+"/b.json",rotated_config=directory+"/rotated.json";
      Child server(argv[1],config.c_str(),true);server.await_state("listening");
      Child a(argv[1],a_config.c_str());a.await_state("ready");server.await_state("ready");
      const auto server_pid=server.pid,client_pid=a.pid;uint64_t revision=0;
      auto reload=[&](const char* stage,bool valid) {
        std::ifstream source(directory+"/"+stage+".json");require(bool(source),"reload_stage_file");
        const std::string bytes((std::istreambuf_iterator<char>(source)),std::istreambuf_iterator<char>());
        {std::ofstream output(config+".next");output<<bytes;require(bool(output),"reload_stage_write");}
        require(rename((config+".next").c_str(),config.c_str())==0,"reload_stage_rename");
        require(kill(server.pid,SIGHUP)==0,"reload_signal");
        auto ack=server.await_reload(valid?"applied":"rejected",revision+(valid?1:0));if(valid)++revision;
        require(server.pid==server_pid&&a.pid==client_pid,"reload_pid_changed");
      };
      reload("add",true);Child b(argv[1],b_config.c_str());b.await_state("ready");
      for(int i=0;i<10;++i){peer_transfer(a,server,b,false,2);peer_transfer(server,b,a,true,3);}
      a.healthy_status();
      for(const auto stage:{"invalid","immutable","missing-key"}) {
        reload(stage,false);peer_transfer(b,server,a,false,3);peer_transfer(server,a,b,true,2);a.healthy_status();
      }
      if(std::ifstream(directory+"/invalid-relay.json")){reload("invalid-relay",false);peer_transfer(b,server,a,false,3);a.healthy_status();}
      reload("rotate",true);b.reject_for(700);
      Child rotated(argv[1],rotated_config.c_str());rotated.await_state("ready");
      peer_transfer(rotated,server,a,false,3);peer_transfer(server,a,rotated,true,2);a.healthy_status();
      b.stop();reload("revoke",true);rotated.reject_for(700);
      transfer(a,server,65535,false,55);transfer(server,a,65535,true,56);a.healthy_status();
      rotated.stop();reload("deny",true);a.reject_for(700);a.stop();
      server.stop();
      std::cout<<"PEER_RELOAD_PASS add_invalid_immutable_missing_rotate_revoke_deny_no_restart_preserve_unaffected\n";
      return 0;
    }
    if(argc==6&&std::string(argv[4])=="h2-budget"){
      const int count=std::stoi(argv[5]);require(count==1||count==4||count==8,"budget_peer_count");
      h2_budget(argv[1],argv[2],argv[3],count);return 0;
    }
    if(argc==5&&std::string(argv[4])=="service"){
      unsetenv("NOTIFY_SOCKET");
      Child server(argv[1],argv[3],true);server.await_state("listening");
      Child client(argv[1],argv[2],true);client.await_state("ready");server.await_state("ready");
      // Stdin is deliberately ignored in explicit service mode, including EOF.
      for(auto* child:{&client,&server}){
        child->command("{\"op\":\"stop\"}\n");close(child->control);child->control=-1;
      }
      for(int i=0;i<50;i++){transfer(client,server,1400,false,i);transfer(server,client,1400,true,i);}
      client.stop();server.stop();
      std::cout<<"service mode ignores stdin/EOF, 100 packets, SIGTERM clean stop PASS\n";return 0;
    }
    if(argc==5&&(std::string(argv[4])=="many"||std::string(argv[4])=="many-service")){
      const bool service=std::string(argv[4])=="many-service";
      Child server(argv[1],argv[3],service);server.await_state("listening");
      std::vector<std::unique_ptr<Child>> peers;
      for(int i=0;i<32;i++){
        auto config=std::string(argv[2])+"/client-"+std::to_string(i)+".json";
        peers.push_back(std::make_unique<Child>(argv[1],config.c_str(),service));
      }
      for(auto& peer:peers)peer->await_state("ready",6000);
      server.await_state("ready");
      for(int round=0;round<4;round++)for(size_t i=0;i<peers.size();i++){
        auto& other=*peers[(i+1)%peers.size()];
        peer_transfer(*peers[i],server,other,false,uint8_t(i+2));
        peer_transfer(server,*peers[i],other,true,uint8_t(i+2));
      }
      require(fd_count(server.pid)<=42,"many_fd_bound");require(rss(server.pid)<128*1024,"many_rss_bound");
      for(auto& peer:peers)peer->stop();
      server.stop();std::cout<<"32 authenticated peers, 256 addressed packets, bounded FD/RSS PASS\n";return 0;
    }
    if(argc==7&&std::string(argv[4])=="multi"){
      Child server(argv[1],argv[3]);server.await_state("listening");
      json config;std::ifstream input(argv[3]);input>>config;
      sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(config.at("port").get<int>());
      require(inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr)==1,"loopback");
      std::vector<int> slow;
      for(int i=0;i<12;i++){
        int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);require(fd>=0,"slow_socket");
        require(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0,"slow_connect");slow.push_back(fd);
        if(i%2){uint8_t partial=0x16;require(send(fd,&partial,1,0)==1,"partial_tls");}
      }
      auto began=Clock::now();
      Child a(argv[1],argv[2]),b(argv[1],argv[5]);a.await_state("ready",3000);b.await_state("ready",3000);
      require(Clock::now()-began<std::chrono::seconds(3),"slow_tls_blocks_peers");server.await_state("ready");
      for(int i=0;i<100;i++){
        peer_transfer(a,server,b,false,2);peer_transfer(server,a,b,true,2);
        peer_transfer(b,server,a,false,3);peer_transfer(server,b,a,true,3);
      }
      std::cout<<"two independent authenticated native peers, 400 isolated packets PASS\n";
      {
        Child duplicate(argv[1],argv[2]);std::this_thread::sleep_for(std::chrono::milliseconds(350));
        auto forbidden=packet(64,false,42);require(send(duplicate.packet,forbidden.data(),forbidden.size(),0)>0,"duplicate_send");
        for(int i=0;i<10;i++){peer_transfer(a,server,b,false,2);peer_transfer(server,b,a,true,3);}
        duplicate.stop();
      }
      std::cout<<"duplicate credential cannot evict active owner PASS\n";
      {
        auto crossed=packet(64,false,1);crossed[16]=10;crossed[17]=99;crossed[18]=0;crossed[19]=3;
        crossed[10]=crossed[11]=0;uint32_t sum=0;
        for(int i=0;i<20;i+=2)sum+=(uint16_t(crossed[i])<<8)|crossed[i+1];
        while(sum>>16)sum=(sum&65535)+(sum>>16);
        crossed[10]=(~sum)>>8;crossed[11]=~sum;
        require(send(a.packet,crossed.data(),crossed.size(),0)>0,"cross_send");
        pollfd p{server.packet,POLLIN,0};require(poll(&p,1,300)==0,"client_to_client_tun_injection");
        a.await_state("ready",3000);peer_transfer(b,server,a,false,3);
      }
      std::cout<<"client-to-client forwarding denied by native exit PASS\n";
      {
        Child spoof(argv[1],argv[6]);spoof.await_state("ready",3000);
        auto forged=packet(64,false,9);forged[15]=3;forged[10]=forged[11]=0;
        uint32_t sum=0;for(int i=0;i<20;i+=2)sum+=(uint16_t(forged[i])<<8)|forged[i+1];
        while(sum>>16)sum=(sum&65535)+(sum>>16);
        forged[10]=(~sum)>>8;forged[11]=~sum;
        require(send(spoof.packet,forged.data(),forged.size(),0)>0,"spoof_send");
        pollfd p{server.packet,POLLIN,0};require(poll(&p,1,300)==0,"spoof_injection");
        peer_transfer(a,server,b,false,2);peer_transfer(server,b,a,true,3);spoof.stop();
      }
      std::cout<<"authenticated wrong-source peer isolated without disrupting others PASS\n";
      for(int i=0;i<40;i++){
        int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);require(fd>=0,"flood_socket");
        require(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0,"flood_connect");slow.push_back(fd);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      require(fd_count(server.pid)<=32,"pending_admission_limit");
      auto until=Clock::now()+std::chrono::seconds(6);
      while(Clock::now()<until){peer_transfer(a,server,b,false,2);peer_transfer(server,b,a,true,3);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));}
      for(int fd:slow){pollfd p{fd,POLLIN,0};require(poll(&p,1,100)>0,"slow_tls_not_expired");
        char byte;require(recv(fd,&byte,1,0)<=0,"slow_tls_unexpected_response");close(fd);}
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      const auto baseline=fd_count(server.pid);
      for(int i=0;i<5;i++){
        a.command("{\"op\":\"uplink\",\"ready\":false}\n");a.await_state("waiting_uplink");
        peer_transfer(b,server,a,false,3);
        a.command("{\"op\":\"uplink\",\"ready\":true}\n");a.await_state("ready",3000);
        peer_transfer(a,server,b,false,2);peer_transfer(server,a,b,true,2);
        require(fd_count(server.pid)==baseline,"multi_fd_leak");
      }
      // Freeze only one authenticated recipient and fill its outbound path.
      // The other client's traffic must still traverse the same shared TUN.
      require(kill(a.pid,SIGSTOP)==0,"slow_peer_pause");
      auto pressure=packet(1400,true,7);
      auto end=Clock::now()+std::chrono::milliseconds(900);
      while(Clock::now()<end){
        auto n=send(server.packet,pressure.data(),pressure.size(),MSG_DONTWAIT);
        require(n==ssize_t(pressure.size())||(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK)),"slow_peer_flood");
      }
      peer_transfer(b,server,a,false,3);peer_transfer(server,b,a,true,3);
      require(kill(a.pid,SIGCONT)==0,"slow_peer_resume");
      a.command("{\"op\":\"uplink\",\"ready\":false}\n");a.await_state("waiting_uplink");
      Bytes drain(65536);while(recv(a.packet,drain.data(),drain.size(),MSG_DONTWAIT)>0){}
      a.command("{\"op\":\"uplink\",\"ready\":true}\n");a.await_state("ready",3000);
      peer_transfer(a,server,b,false,2);peer_transfer(server,a,b,true,2);
      std::cout<<"slow authenticated recipient cannot block other peer PASS\n";
      require(rss(server.pid)<128*1024,"multi_rss_bound");
      a.stop();b.stop();server.stop();
      std::cout<<"slow TLS deadline, independent reconnect, bounded RSS/FDs, stop PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3])=="client-multicast"){
      Child client(argv[1],argv[2]);client.await_state("ready");
      auto deadline=Clock::now()+std::chrono::seconds(5);bool done=false;
      while(Clock::now()<deadline){
        auto state=client.healthy_status();
        require(state.at("rx_packets")==0&&state.at("tx_packets")==0,"multicast_not_forwarded");
        pollfd p{client.packet,POLLIN,0};require(poll(&p,1,0)==0,"multicast_tun_injection");
        if(state.at("dropped_packets")==2054){done=true;break;}
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      require(done,"multicast_drop_count");
      reflect_pair(client,42);
      auto state=client.healthy_status();
      require(state.at("tx_packets")==2&&state.at("rx_packets")==2&&state.at("dropped_packets")==2054,"multicast_following_unicast");
      client.stop();std::cout<<"multicast discarded, same session unicast and flow control PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3]).rfind("client-incoming:",0)==0){
      const auto close_code=std::string(argv[3]).substr(16);
      Child client(argv[1],argv[2]);
      for(int round=0;round<3;round++){
        client.await_state("ready");
        pollfd p{client.packet,POLLIN,0};require(poll(&p,1,4000)>0,"incoming_without_outbound_timeout");
        Bytes got(65536);const auto n=recv(client.packet,got.data(),got.size(),0);
        require(n>0,"incoming_read");got.resize(n);
        require(got==packet(20,true,0),"incoming_bytes");
        if(round<2)client.await_state(close_code);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1500));
      const auto state=client.healthy_status();
      require(state.at("tx_packets")==0&&state.at("rx_packets")==3,"incoming_no_synthetic_uplink");
      client.stop();std::cout<<"persistent incoming after graceful reconnect without outbound wake PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3])=="client-idle"){
      Child client(argv[1],argv[2]);client.await_state("ready");
      for(int round=0;round<4;round++){
        client.await_state("h2_peer_end_stream");client.await_state("idle_wait");
        if(round==0){
          const uint8_t invalid[40]={0x60};send(client.packet,invalid,sizeof(invalid),0);
          client.command("{\"op\":\"uplink\",\"ready\":false}\n");client.await_state("waiting_uplink");
          client.command("{\"op\":\"uplink\",\"ready\":true}\n");client.await_state("uplink_ready");client.await_state("idle_wait");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        client.command("{\"op\":\"status\"}\n");
        auto state=client.await_state("idle_wait",1000);
        require(state.at("event")=="status"&&state.at("tx_packets")==round*2&&state.at("rx_packets")==round*2,"idle_quiet_counts");
        if(round<3){reflect_pair(client,round*2);client.await_state("ready");}
      }
      client.stop();std::cout<<"idle cycles wake packet, uplink, invalid traffic and stop PASS\n";return 0;
    }
    if(argc==4&&std::string(argv[3]).rfind("client-event:",0)==0){
      const auto code=std::string(argv[3]).substr(13);
      Child client(argv[1],argv[2]);client.await_state(code);
      pollfd p{client.packet,POLLIN,0};require(poll(&p,1,50)==0,"fault_injected_packet");
      if(code=="h2_peer_end_stream"||code=="h2_goaway_no_error"||code=="h1_peer_end_stream"){
        client.await_state("idle_wait");
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
        client.command("{\"op\":\"status\"}\n");
        auto state=client.await_state("idle_wait",1000);require(state.at("event")=="status","idle_no_reconnect");
        // First packet, with no retransmission, must wake and survive connect.
        reflect(client,1400,7);client.await_state("ready");
      }else{client.await_state("ready");reflect(client,1400,7);}
      client.stop();
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
    // Bounded two-host probe. The fixture owns a datagram socketpair, never a
    // TUN or host route. Each endpoint runs separately with fresh trial keys.
    if((argc==4||argc==5)&&(std::string(argv[3])=="wan-client"||std::string(argv[3])=="wan-exit")){
      const bool client=std::string(argv[3])=="wan-client";
      in_addr peer_ip{};const std::string peer_text=argc==5?argv[4]:"10.99.0.2";
      require(inet_pton(AF_INET,peer_text.c_str(),&peer_ip)==1,"wan_peer_ipv4");
      const uint32_t address=ntohl(peer_ip.s_addr);
      require((address&0xffffff00)==0x0a630000&&(address&255)>=2&&(address&255)<=254,"wan_peer_ipv4");
      auto packet_for=[&](size_t size,bool reverse,uint8_t seed){
        auto bytes=packet(size,reverse,seed);std::memcpy(bytes.data()+(reverse?16:12),&peer_ip.s_addr,4);
        bytes[10]=bytes[11]=0;uint32_t sum=0;for(size_t i=0;i<20;i+=2)sum+=(uint16_t(bytes[i])<<8)|bytes[i+1];
        while(sum>>16)sum=(sum&65535)+(sum>>16);
        bytes[10]=(~sum)>>8;bytes[11]=~sum;return bytes;
      };
      Child peer(argv[1],argv[2],!client);peer.await_state(client?"ready":"listening");
      if(!client){std::cout<<"WAN_LISTENING"<<std::endl;peer.await_state("ready",60000);}
      auto receive=[&](const Bytes& expected){pollfd p{peer.packet,POLLIN,0};require(poll(&p,1,10000)>0,"wan_packet_timeout");Bytes got(65536);const auto n=recv(peer.packet,got.data(),got.size(),0);require(n>0,"wan_packet_read");got.resize(n);require(got==expected,"wan_packet_bytes");};
      auto send_packet=[&](const Bytes& b){require(send(peer.packet,b.data(),b.size(),0)==ssize_t(b.size()),"wan_packet_send");};
      unsigned count=0;size_t bytes=0;
      for(unsigned round=0;round<8;round++)for(size_t size:{64,1400,16384,65535}){
        if(client){send_packet(packet_for(size,false,count));receive(packet_for(size,true,count));}
        else{receive(packet_for(size,false,count));send_packet(packet_for(size,true,count));}
        count++;bytes+=size;
      }
      // Exit must not stop before its final downlink has actually arrived.
      if(client)send_packet(packet_for(64,false,250));else receive(packet_for(64,false,250));
      if(client)std::this_thread::sleep_for(std::chrono::milliseconds(300));
      peer.stop();std::cout<<json({{"kind","native-wan-fixture"},{"role",client?"client":"exit"},{"packets_each_direction",count},{"bytes_each_direction",bytes},{"status","passed"},{"real_tun",false}}).dump()<<std::endl;return 0;
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
    if(argc==4&&(std::string(argv[3])=="exit-handshake"||std::string(argv[3])=="exit-confirmed"||std::string(argv[3])=="exit-malformed"||std::string(argv[3])=="exit-spoofed-multicast")){
      Child server(argv[1],argv[2]);server.await_state("listening");
      std::cout<<"native exit listening\n";server.await_state("ready");
      if(std::string(argv[3])=="exit-confirmed"){
        // Do not stop as soon as local auth completes: the 200 response may
        // still be queued. Wait for the test client to observe it and send.
        pollfd p{server.packet,POLLIN,0};require(poll(&p,1,3000)>0,"confirmed_packet_timeout");
        Bytes got(65536);auto n=recv(server.packet,got.data(),got.size(),0);require(n>0,"confirmed_packet_read");
        got.resize(n);require(got==packet(64,false,7),"confirmed_packet_bytes");
        std::cout<<"client observed success and native packet injection PASS\n";
      }
      if(std::string(argv[3])=="exit-malformed"){
        server.await_state("invalid_frame_length");pollfd p{server.packet,POLLIN,0};require(poll(&p,1,50)==0,"malformed_injection");
        std::cout<<"malformed frame rejected before packet injection PASS\n";
      }
      if(std::string(argv[3])=="exit-spoofed-multicast"){
        server.await_state("peer_address");pollfd p{server.packet,POLLIN,0};require(poll(&p,1,50)==0,"spoofed_multicast_injection");
        std::cout<<"spoofed multicast source rejected before packet injection PASS\n";
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
    json server_config;std::ifstream server_input(argv[3]);server_input>>server_config;
    const bool h1=server_config.value("http_version",std::string{})=="1.1";
    kill(server.pid,SIGSTOP);auto begin=Clock::now();client.await_state(h1?"h1_ping_timeout":"h2_ping_timeout",9000);
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
