#include "transparent_socket.hpp"
#include "combo.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <iostream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <future>

using namespace cvpn;
using namespace cvpn::transparent;
static void need(bool ok, int line = __builtin_LINE()) {
  if (!ok) throw std::runtime_error("transparent_socket_test_line_" + std::to_string(line) + "_errno_" + std::to_string(errno));
}
struct Listener {
  RelaySocket socket;
  Destination destination{{127,0,0,1},0};
  explicit Listener(Destination bind_to = {{127,0,0,1},0}) : socket(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)), destination(bind_to) {
    need(socket.fd >= 0); auto address = socket_address(destination);
    int one=1;need(setsockopt(socket.fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);
    need(bind(socket.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socklen_t n = sizeof(address); need(getsockname(socket.fd, reinterpret_cast<sockaddr*>(&address), &n) == 0);
    destination.port = ntohs(address.sin_port); need(listen(socket.fd, 32) == 0);
  }
  int release() { int fd = socket.fd; socket.fd = -1; return fd; }
};
static int connected(const Destination& dst, bool marked = false) {
  RelaySocket s(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)); need(s.fd >= 0);
  if (marked) { int mark = 66; need(setsockopt(s.fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)) == 0); }
  timeval timeout{5,0};
  need(setsockopt(s.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  need(setsockopt(s.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
  auto a = socket_address(dst); need(connect(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
  int fd = s.fd; s.fd = -1; return fd;
}
static void write_bytes(int fd, const Bytes& b) {
  size_t at = 0;
  while (at < b.size()) { ssize_t n = send(fd, b.data() + at, b.size() - at, MSG_NOSIGNAL); need(n > 0); at += size_t(n); }
}
template<class F> static void until(F f) {
  const auto deadline = monotonic_ms() + 3000;
  while (!f()) { need(monotonic_ms() < deadline); std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
}
static Bytes client_hello(SSL_CTX* ctx) {
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx)); need(bool(ssl));
  BIO* in = BIO_new(BIO_s_mem()); BIO* out = BIO_new(BIO_s_mem()); need(in && out);
  BIO_set_mem_eof_return(in, -1); SSL_set_bio(ssl.get(), in, out); SSL_set_connect_state(ssl.get());
  need(SSL_set_tlsext_host_name(ssl.get(), "localhost"));
  int rc = SSL_do_handshake(ssl.get()); need(rc < 0 && SSL_get_error(ssl.get(), rc) == SSL_ERROR_WANT_READ);
  Bytes b(16384); int n = BIO_read(out, b.data(), b.size()); need(n > 0); b.resize(n); return b;
}
class Origin {
  Listener listener_;
  SSL_CTX* ctx_;
  size_t bulk_size_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
  void run() {
    while (!stop_) {
      pollfd p{listener_.socket.fd,POLLIN,0}; if (poll(&p,1,25) <= 0) continue;
      RelaySocket fd(accept4(listener_.socket.fd,nullptr,nullptr,SOCK_CLOEXEC)); if (fd.fd < 0) continue;
      ++connections; timeval timeout{2,0};
      setsockopt(fd.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
      setsockopt(fd.fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
      if (bulk_size_) { int size = 262144; setsockopt(fd.fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size)); }
      try {
        bssl::UniquePtr<SSL> ssl(SSL_new(ctx_)); need(bool(ssl)); need(SSL_set_fd(ssl.get(),fd.fd));
        need(SSL_accept(ssl.get()) == 1);
        const char* name = SSL_get_servername(ssl.get(),TLSEXT_NAMETYPE_host_name);
        need(name && std::string(name) == "localhost");
        uint8_t buffer[16384]; size_t total = 0; SHA256_CTX hash; SHA256_Init(&hash);
        for (;;) {
          int n = SSL_read(ssl.get(),buffer,sizeof(buffer));
          if (n <= 0) { need(SSL_get_error(ssl.get(),n) == SSL_ERROR_ZERO_RETURN); break; }
          // Slow origin consumer. The relay must not collect unlimited input.
          std::this_thread::sleep_for(std::chrono::milliseconds(bulk_size_ ? 5 : 1));
          if (bulk_size_) {
            total += n; need(total <= bulk_size_); SHA256_Update(&hash,buffer,n);
            if (total == bulk_size_) { Digest value{}; SHA256_Final(value.data(),&hash); need(SSL_write(ssl.get(),value.data(),value.size()) == int(value.size())); }
          } else need(SSL_write(ssl.get(),buffer,n) == n);
          bytes += n;
        }
        need(!bulk_size_ || total == bulk_size_); need(SSL_shutdown(ssl.get()) >= 0); ++completed;
      } catch (...) { ++failed; ERR_clear_error(); }
    }
  }
public:
  std::atomic<unsigned> connections{0}, completed{0}, failed{0};
  std::atomic<uint64_t> bytes{0};
  explicit Origin(SSL_CTX* ctx, size_t bulk_size = 0, Destination bind_to = {{127,0,0,1},0})
    : listener_(bind_to), ctx_(ctx), bulk_size_(bulk_size) { thread_ = std::thread([this] {run();}); }
  ~Origin() { stop_ = true; thread_.join(); }
  Destination destination() const { return listener_.destination; }
};
static void denied(const Destination& exit, const Bytes& wire) {
  RelaySocket s(connected(exit)); write_bytes(s.fd,wire);
  uint8_t b; ssize_t n = recv(s.fd,&b,1,0); need(n == 0 || (n < 0 && errno == ECONNRESET));
}
static void transfer(SSL_CTX* ctx, const Destination& client, int version, bool marked = false) {
  RelaySocket s(connected(client,marked)); bssl::UniquePtr<SSL> ssl(SSL_new(ctx)); need(bool(ssl));
  need(SSL_set_min_proto_version(ssl.get(),version) && SSL_set_max_proto_version(ssl.get(),version));
  need(SSL_set_tlsext_host_name(ssl.get(),"localhost") && SSL_set1_host(ssl.get(),"localhost"));
  need(SSL_set_fd(ssl.get(),s.fd)); need(SSL_connect(ssl.get()) == 1);
  need(SSL_get_verify_result(ssl.get()) == X509_V_OK);
  for (size_t batch = 0; batch < 64; ++batch) {
    Bytes data(16384), answer(data.size());
    for (size_t i = 0; i < data.size(); ++i) data[i] = uint8_t(i + batch);
    need(SSL_write(ssl.get(),data.data(),data.size()) == int(data.size()));
    size_t at = 0;
    while (at < answer.size()) {
      int n = SSL_read(ssl.get(),answer.data() + at,std::min(size_t(1024),answer.size() - at));
      need(n > 0); at += n;
    }
    need(answer == data);
  }
  need(SSL_shutdown(ssl.get()) >= 0); need(shutdown(s.fd,SHUT_WR) == 0);
  uint8_t last; int n = SSL_read(ssl.get(),&last,1);
  need(n == 0 && SSL_get_error(ssl.get(),n) == SSL_ERROR_ZERO_RETURN);
}
static void bulk_transfer(SSL_CTX* cc, SSL_CTX* sc, const SniAuthorization& auth) {
  constexpr size_t size = 8 * 1048576;
  Origin origin(sc,size); const auto dst = origin.destination(); Listener e, c;
  const auto exit_address = e.destination, client_address = c.destination;
  RelayListener exit(e.release(),false,auth,{}, {},DestinationPolicy({dst}));
  RelayListener client(c.release(),true,auth,dst,exit_address,DestinationPolicy({dst}));
  RelaySocket s(connected(client_address)); bssl::UniquePtr<SSL> ssl(SSL_new(cc)); need(bool(ssl));
  need(SSL_set_tlsext_host_name(ssl.get(),"localhost") && SSL_set1_host(ssl.get(),"localhost"));
  need(SSL_set_fd(ssl.get(),s.fd)); need(SSL_connect(ssl.get()) == 1);
  Bytes block(16384,0xa5); SHA256_CTX hash; SHA256_Init(&hash);
  for (size_t i = 0; i < size; i += block.size()) {
    need(SSL_write(ssl.get(),block.data(),block.size()) == int(block.size())); SHA256_Update(&hash,block.data(),block.size());
  }
  Digest expected{}, result{}; SHA256_Final(expected.data(),&hash);
  need(SSL_read(ssl.get(),result.data(),result.size()) == int(result.size()) && result == expected);
  need(SSL_shutdown(ssl.get()) >= 0); need(shutdown(s.fd,SHUT_WR) == 0);
  uint8_t last; int n = SSL_read(ssl.get(),&last,1); need(n == 0 && SSL_get_error(ssl.get(),n) == SSL_ERROR_ZERO_RETURN);
  until([&] { return client.completed == 1 && exit.completed == 1 && origin.completed == 1; });
  need(client.failed == 0 && exit.failed == 0 && exit.paused_polls > 0);
  need(exit.peak_queue <= queue_limit && client.peak_queue <= queue_limit);
  std::cout << "native transparent backpressure PASS: 8 MiB slow consumer, peak_queue=" << exit.peak_queue << " paused_polls=" << exit.paused_polls << '\n';
}
static void durable_socket_restart(SSL_CTX* cc, SSL_CTX* sc, const SniAuthorization& auth) {
  char p[] = "/tmp/cvpn-replay-socket-XXXXXX"; need(mkdtemp(p));
  struct Cleanup { std::string path; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path,ec); } } cleanup{p};
  Origin origin(sc); const auto dst = origin.destination(); const auto hello = parse(client_hello(cc));
  auto wire = auth.seal(hello,dst,wall_seconds());
  {
    auto replay = std::make_shared<ReplayWindow>(p,auth.replay_scope(),true);
    Listener e; const auto endpoint = e.destination;
    RelayListener exit(e.release(),false,auth,{}, {},DestinationPolicy({dst}),{},replay);
    { RelaySocket s(connected(endpoint)); write_bytes(s.fd,wire); uint8_t b; need(recv(s.fd,&b,1,0) == 1); }
    until([&] { return exit.failed == 1 && origin.failed == 1; });
  }
  {
    auto replay = std::make_shared<ReplayWindow>(p,auth.replay_scope());
    Listener e; const auto endpoint = e.destination;
    RelayListener exit(e.release(),false,auth,{}, {},DestinationPolicy({dst}),{},replay);
    denied(endpoint,wire); until([&] { return exit.failed == 1; });
    need(exit.last_failure() == "relay_replayed" && origin.connections == 1);
    // A storage failure precedes origin connect and poisons live admission.
    const std::string pending = std::string(p) + "/pending";
    { ReplayFd fd(open(pending.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600)); need(fd.get() >= 0); }
    denied(endpoint,auth.seal(hello,dst,wall_seconds()));
    until([&] { return exit.failed == 2; }); need(origin.connections == 1);
    need(unlink(pending.c_str()) == 0);
    denied(endpoint,auth.seal(hello,dst,wall_seconds()));
    until([&] { return exit.failed == 3; });
    need(exit.last_failure() == "relay_replay_failed" && origin.connections == 1);
  }
  {
    auto replay = std::make_shared<ReplayWindow>(p,auth.replay_scope());
    Listener e; const auto endpoint = e.destination;
    RelayListener exit(e.release(),false,auth,{}, {},DestinationPolicy({dst}),{},replay);
    denied(endpoint,wire); until([&] { return exit.failed == 1; }); need(origin.connections == 1);
    { RelaySocket s(connected(endpoint)); write_bytes(s.fd,auth.seal(hello,dst,wall_seconds())); uint8_t b; need(recv(s.fd,&b,1,0) == 1); }
    until([&] { return origin.failed == 2 && exit.failed == 2; }); need(origin.connections == 2);
  }
  std::cout << "native transparent durable sockets PASS: replay across listener restart, storage failure opens no origin, fresh token after restart\n";
}
struct Child {
  pid_t pid = -1;
  RelaySocket output;
  RelaySocket packets;
  explicit Child(std::vector<std::string> args, bool packet_fixture = false) {
    int pair[2]{-1,-1}; RelaySocket peer;
    if(packet_fixture) {
      need(socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,pair)==0);
      packets.fd=pair[0];peer.fd=pair[1];
    }
    std::vector<char*> argv; for (auto& a : args) argv.push_back(a.data()); argv.push_back(nullptr);
    int pipefd[2]; need(pipe2(pipefd,O_CLOEXEC) == 0); output.fd = pipefd[0]; RelaySocket writer(pipefd[1]);
    const auto parent = getpid(); pid = fork(); need(pid >= 0);
    if (!pid) {
      if (prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid() != parent || dup2(writer.fd,STDOUT_FILENO) < 0) _exit(126);
      if(packet_fixture && (dup2(peer.fd,4)<0 || fcntl(4,F_SETFD,0)<0)) _exit(126);
      execv(argv[0],argv.data()); _exit(127);
    }
    need(fcntl(output.fd,F_SETFL,O_NONBLOCK) == 0);
  }
  ~Child() { if (pid > 0) { kill(pid,SIGKILL); while (waitpid(pid,nullptr,0) < 0 && errno == EINTR) {} } }
  std::string text;
  bool read() {
    char b[1024]; auto n = ::read(output.fd,b,sizeof(b));
    if (n > 0) { text.append(b,n); need(text.size() < 16384); }
    return n != 0;
  }
  int wait() {
    int status=0; bool done=false;
    until([&] { read(); auto result=waitpid(pid,&status,WNOHANG); need(result >= 0); done=result==pid; return done; });
    pid=-1; return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
  }
  void ready(const std::string& state = "listening") { until([&] { need(read()); return text.find("\"state\":\""+state+"\"") != std::string::npos; }); }
};
static int command(std::vector<std::string> args) { Child child(std::move(args)); return child.wait(); }
static void write_fixture(const std::string& path, const std::string& text) {
  ReplayFd fd(open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600)); need(fd.get() >= 0);
  need(write(fd.get(),text.data(),text.size()) == ssize_t(text.size()));
}
static void packet_transfer(Child& from, Child& to, bool reverse, uint8_t seed) {
  Bytes packet(1400,seed);packet[0]=0x45;packet[1]=0;packet[2]=packet.size()>>8;packet[3]=packet.size();
  packet[6]=packet[7]=0;packet[8]=64;packet[9]=17;packet[10]=packet[11]=0;
  const uint8_t local[4]={10,99,0,2},remote[4]={1,1,1,1};
  std::memcpy(packet.data()+12,reverse?remote:local,4);std::memcpy(packet.data()+16,reverse?local:remote,4);
  uint32_t sum=0;for(size_t i=0;i<20;i+=2)sum+=(uint16_t(packet[i])<<8)|packet[i+1];
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  packet[10]=(~sum)>>8;packet[11]=~sum;
  need(send(from.packets.fd,packet.data(),packet.size(),0)==ssize_t(packet.size()));
  pollfd p{to.packets.fd,POLLIN,0};need(poll(&p,1,3000)>0);
  Bytes got(65536);auto n=recv(to.packets.fd,got.data(),got.size(),0);need(n>0);got.resize(n);need(got==packet);
}
static void engine_redirect(SSL_CTX* cc, SSL_CTX* sc, const std::string& engine, const std::string& parent_netns,
                            bool combined = false, const std::string& cert = {}, const std::string& private_key = {}) {
  char ns[128]; const auto n=readlink("/proc/self/ns/net",ns,sizeof(ns));
  need(n>0 && std::string(ns,n) != parent_netns && parent_netns.rfind("net:[",0)==0);
  // Fail before touching any network state unless in the new, empty namespace.
  unsigned links=0; bool only_loopback=true;
  auto* names=if_nameindex();need(names);
  for(auto* entry=names;entry->if_index;++entry) { only_loopback &= std::string(entry->if_name)=="lo"; ++links; }
  if_freenameindex(names);
  need(only_loopback && links==1); need(command({"/usr/sbin/ip","link","set","lo","up"})==0);
  char temp[]="/tmp/cvpn-transparent-engine-XXXXXX"; need(mkdtemp(temp));
  struct Cleanup { std::string path; ~Cleanup(){ std::error_code ec; std::filesystem::remove_all(path,ec); } } cleanup{temp};
  const std::string dir=temp, state=dir+"/replay", secret=dir+"/secret", ecfg=dir+"/exit.json", ccfg=dir+"/client.json";
  need(mkdir(state.c_str(),0700)==0); write_fixture(secret,std::string(32,'B'));
  Origin origin(sc); const auto dst=origin.destination();
  Destination eaddr,caddr;
  { Listener e,c; eaddr=e.destination; caddr=c.destination; }
  using J=nlohmann::json;
  auto ep=[](const Destination& d){return J{{"ipv4","127.0.0.1"},{"port",d.port}};};
  J common={{"version",1},{"transport","transparent-tls"},{"public_name","relay.example"},{"secret_path",secret},{"destinations",J::array({ep(dst)})}};
  auto ej=common; ej["role"]="exit";ej["listen"]=ep(eaddr);ej["replay_directory"]=state;
  auto cj=common; cj["role"]="client";cj["listen"]=ep(caddr);cj["exit"]=ep(eaddr);
  if(combined) {
    const auto psk=dir+"/boring-secret";write_fixture(psk,std::string(32,'A'));
    J base={{"version",1},{"address","127.0.0.1"},{"port",eaddr.port},{"tun","cvcombo0"},{"secret_path",psk}};
    auto bclient=base;bclient["role"]="client";bclient["ca"]=cert;bclient["server_name"]="localhost";bclient["sni"]="relay.example";
    auto bexit=base;bexit["role"]="exit";bexit["cert"]=cert;bexit["key"]=private_key;
    ej=J{{"version",1},{"transport","combo-tls"},{"role","exit"},{"boring",bexit},{"transparent",ej}};
    cj=J{{"version",1},{"transport","combo-tls"},{"role","client"},{"boring",bclient},{"transparent",cj}};
  }
  write_fixture(ecfg,ej.dump());write_fixture(ccfg,cj.dump());
  need(command({engine,"--check-config",ecfg})==0 && command({engine,"--check-config",ccfg})==0);
  need(!std::filesystem::exists(state+"/lock")); // validation is read-only
  if(!combined)need(command({engine,"--config",ecfg,"--service"})!=0); // no implicit replay reset
  need(command({engine,"--init-transparent-replay",ecfg})==0);
  need(command({engine,"--init-transparent-replay",ecfg})!=0);
  unsigned invalid=0;
  for (const auto& mutation : {"tun","dns","secret","destination","replay_directory"}) {
    auto bad=cj; bad[mutation]="unexpected"; const auto path=dir+"/invalid"+std::to_string(invalid++)+".json";
    write_fixture(path,bad.dump());need(command({engine,"--check-config",path})!=0);
  }
  auto launch=[&](const std::string& config) {
    std::vector<std::string> args{engine,"--config",config};
    if(combined)args.insert(args.end(),{"--test-packet-fd","4"});
    args.push_back("--service");return std::make_unique<Child>(args,combined);
  };
  auto exit=launch(ecfg);exit->ready();
  if(!combined)need(command({engine,"--config",ecfg,"--service"})!=0); // same durable scope has one owner
  auto client_owner=launch(ccfg);auto& client=*client_owner;client.ready(combined?"ready":"listening");
  if(combined){exit->ready("ready");packet_transfer(client,*exit,false,1);packet_transfer(*exit,client,true,2);}
  // Mark only the test application, so the separate exit engine's origin
  // connection is never redirected back into the client in this one-netns lab.
  need(command({"/usr/sbin/iptables","-t","nat","-A","OUTPUT","-p","tcp","-d","127.0.0.1",
    "--dport",std::to_string(dst.port),"-m","mark","--mark","66","-j","REDIRECT","--to-ports",std::to_string(caddr.port)})==0);
  { RelaySocket direct(connected(caddr));uint8_t b;auto result=recv(direct.fd,&b,1,0);need(result==0||(result<0&&errno==ECONNRESET)); }
  need(origin.connections==0);
  auto tls=std::async(std::launch::async,[&]{transfer(cc,dst,TLS1_2_VERSION,true);transfer(cc,dst,TLS1_3_VERSION,true);});
  if(combined)for(int i=0;i<100;++i){packet_transfer(client,*exit,false,i);packet_transfer(*exit,client,true,i);}
  tls.get();
  until([&]{return origin.completed==2;});need(origin.connections==2);
  Digest key{};key.fill('B');SniAuthorization auth(key,"relay.example");
  const auto wire=auth.seal(parse(client_hello(cc)),dst,wall_seconds());
  { RelaySocket s(connected(eaddr));write_bytes(s.fd,wire);uint8_t b;need(recv(s.fd,&b,1,0)==1); }
  until([&]{return origin.failed==1;});
  need(kill(exit->pid,SIGKILL)==0 && exit->wait()==128+SIGKILL);exit.reset();
  // With interception still installed, a missing exit must fail, not connect
  // directly to the origin. No application payload is handed to Node.
  { RelaySocket s(connected(dst,true));write_bytes(s.fd,client_hello(cc));uint8_t b;auto result=recv(s.fd,&b,1,0);need(result==0||(result<0&&errno==ECONNRESET)); }
  need(origin.connections==3);
  exit=launch(ecfg);exit->ready();
  denied(eaddr,wire); need(origin.connections==3);
  transfer(cc,dst,TLS1_3_VERSION,true);until([&]{return origin.completed==3;});need(origin.connections==4);
  if(combined){exit->ready("ready");packet_transfer(client,*exit,false,3);packet_transfer(*exit,client,true,4);}
  need(kill(client.pid,SIGTERM)==0 && client.wait()==0);
  need(kill(exit->pid,SIGTERM)==0 && exit->wait()==0);
  std::cout<<(combined?"native combo engine REDIRECT PASS: single exit port, concurrent 204 packets and TLS12/TLS13-HRR, C++ only, replay after SIGKILL, no direct fallback, clean stop\n":
    "native transparent engine REDIRECT PASS: C++ client/exit, kernel SO_ORIGINAL_DST, TLS12/TLS13-HRR, SIGKILL replay refusal, no direct fallback, strict config, clean stop\n");
}
static void public_lab_guard(const std::string& parent, bool origin) {
  char ns[128]; const auto n=readlink("/proc/self/ns/net",ns,sizeof(ns));
  need(n>0 && parent.rfind("net:[",0)==0 && std::string(ns,n)!=parent);
  auto* names=if_nameindex();need(names);bool safe=true;unsigned count=0;
  for(auto* a=names;a->if_index;++a) {++count; const std::string name=a->if_name;
    safe &= name=="lo" || (!origin && name=="cvpublic0"); }
  if_freenameindex(names);need(safe && count==(origin?1u:2u));
}
static void public_origin(SSL_CTX* sc, const std::string& parent, bool network = false) {
  public_lab_guard(parent,true);
  need(command({"/usr/sbin/ip","link","set","lo","up"})==0);
  need(command({"/usr/sbin/ip","addr","add","1.1.1.1/32","dev","lo"})==0);
  need(command({"/usr/sbin/ip","addr","add","11.0.0.2/32","dev","lo"})==0);
  std::cout<<"{\"stage\":\"namespace-ready\"}"<<std::endl;
  until([]{return if_nametoindex("cvpublic1")!=0;});
  need(command({"/usr/sbin/ip","addr","add",network?"198.18.0.2/24":"198.18.0.2/30","dev","cvpublic1"})==0);
  need(command({"/usr/sbin/ip","link","set","cvpublic1","up"})==0);
  RelaySocket capture;
  if(network) {
    capture.fd=socket(AF_PACKET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,htons(ETH_P_IP));need(capture.fd>=0);
    sockaddr_ll a{};a.sll_family=AF_PACKET;a.sll_protocol=htons(ETH_P_IP);a.sll_ifindex=if_nametoindex("cvpublic1");
    need(bind(capture.fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
  }
  Origin origin(sc,0,Destination{{0,0,0,0},443});
  std::cout<<"{\"stage\":\"origin-ready\"}"<<std::endl;
  unsigned previous=~0u, forbidden=0, previous_forbidden=~0u;
  for(;;) {
    if(network) {
      uint8_t b[2048];ssize_t n;
      while((n=recv(capture.fd,b,sizeof(b),0))>0) {
        if(n<20 || b[16]!=1 || b[17]!=1 || b[18]!=1 || b[19]!=1) continue;
        const size_t ihl=(b[0]&15)*4;
        if(b[9]!=6 || size_t(n)<ihl+4 || b[ihl+2]!=1 || b[ihl+3]!=187) ++forbidden;
      }
      need(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
    }
    const unsigned count=origin.connections;
    if(count!=previous || forbidden!=previous_forbidden) {
      std::cout<<nlohmann::json({{"connections",count},{"forbiddenPackets",forbidden}}).dump()<<std::endl;
      previous=count;previous_forbidden=forbidden;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
static void network_blocked(const Destination& dst) {
  RelaySocket s(socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));need(s.fd>=0);
  auto a=socket_address(dst);
  int rc=connect(s.fd,reinterpret_cast<sockaddr*>(&a),sizeof(a));need(rc<0);
  if(errno==ECONNREFUSED || errno==ENETUNREACH || errno==EHOSTUNREACH) return;
  need(errno==EINPROGRESS);pollfd p{s.fd,POLLOUT,0};rc=poll(&p,1,200);need(rc>=0);
  if(rc==0) return;
  int error=0;socklen_t len=sizeof(error);need(getsockopt(s.fd,SOL_SOCKET,SO_ERROR,&error,&len)==0 && error!=0);
}
static void network_udp() {
  for(uint16_t port : {uint16_t(53),uint16_t(443)}) {
    RelaySocket s(socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0));need(s.fd>=0);
    auto a=socket_address(Destination{{1,1,1,1},port});const uint8_t probe=0;
    need(sendto(s.fd,&probe,1,0,reinterpret_cast<sockaddr*>(&a),sizeof(a))==1);
  }
}
static void network_negative(bool crash) {
  if(crash) network_blocked(Destination{{1,1,1,1},443});
  else {
    for(const Destination d : {Destination{{1,1,1,1},80}, {{1,1,1,1},53}, {{8,8,8,8},443},
        {{192,168,7,1},33002}, {{198,18,0,3},33001}}) network_blocked(d);
    // UDP has no connect handshake: send bounded datagrams for the namespace
    // capture to check, never treat send() success as reachability evidence.
    network_udp();
  }
  std::cout<<"native transparent network blocked PASS"<<std::endl;
}
static void public_probe(SSL_CTX* cc, SSL_CTX* sc) {
  Digest key{};key.fill('B');SniAuthorization auth(key,"relay.example");const auto hello=parse(client_hello(cc));
  // A real local TLS listener makes a missing local-address guard observable:
  // refusal cannot pass merely because no server exists at the denied address.
  Origin local(sc,0,Destination{{0,0,0,0},443});
  { RelaySocket s(connected(Destination{{127,0,0,1},443}));write_bytes(s.fd,hello.wire);uint8_t b;need(recv(s.fd,&b,1,0)==1); }
  until([&]{return local.failed==1;});
  for(const Destination d : {Destination{{127,0,0,1},443}, {{169,254,169,254},443}, {{10,0,0,1},443},
      {{100,100,100,200},443}, {{192,168,0,1},443}, {{198,18,0,2},443}, {{224,0,0,1},443},
      {{192,0,0,9},443}, {{8,8,8,8},443}, {{11,0,0,1},443}, {{11,0,0,2},443}, {{1,1,1,1},80}})
    denied(Destination{{127,0,0,1},33001},auth.seal(hello,d,wall_seconds()));
  need(local.connections==1);
  std::cout<<"native public policy rejection PASS"<<std::endl;
}
int main(int argc, char** argv) {
  if (argc != 3 && argc != 5 && !(argc == 6 && std::string(argv[5]) == "--combo")) return 2;
  try {
    const bool public_mode=argc==5 && std::string(argv[1]).rfind("--public-",0)==0;
    const int offset=public_mode?1:0;
    bssl::UniquePtr<SSL_CTX> cc(SSL_CTX_new(TLS_method())), sc(SSL_CTX_new(TLS_method())); need(cc && sc);
    need(SSL_CTX_use_certificate_chain_file(sc.get(),argv[1+offset]) && SSL_CTX_use_PrivateKey_file(sc.get(),argv[2+offset],SSL_FILETYPE_PEM));
    need(SSL_CTX_load_verify_locations(cc.get(),argv[1+offset],nullptr)); SSL_CTX_set_verify(cc.get(),SSL_VERIFY_PEER,nullptr);
    need(SSL_CTX_set1_groups_list(cc.get(),"X25519:P-256") && SSL_CTX_set1_groups_list(sc.get(),"P-256"));
    if(public_mode) {
      const std::string mode=argv[1];
      if(mode=="--public-holder") {
        public_lab_guard(argv[4],true);std::cout<<"{\"stage\":\"namespace-ready\"}"<<std::endl;
        for(;;) pause();
      }
      else if(mode=="--public-origin" || mode=="--public-network-origin") public_origin(sc.get(),argv[4],mode=="--public-network-origin");
      else {
        public_lab_guard(argv[4],false);
        if(mode=="--public-network-udp") { network_udp();std::cout<<"UDP sent"<<std::endl; }
        else if(mode=="--public-network-negative" || mode=="--public-network-crash") network_negative(mode=="--public-network-crash");
        else if(mode=="--public-client") {
          transfer(cc.get(),Destination{{1,1,1,1},443},TLS1_2_VERSION,true);
          transfer(cc.get(),Destination{{1,1,1,1},443},TLS1_3_VERSION,true);
          std::cout<<"native public policy TLS12/TLS13-HRR PASS"<<std::endl;
        } else if(mode=="--public-probe") public_probe(cc.get(),sc.get());
        else if(mode=="--public-client-blocked" || mode=="--public-client-local") {
          std::unique_ptr<Listener> decoy;
          if(mode=="--public-client-local") decoy=std::make_unique<Listener>(Destination{{127,0,0,1},33001});
          RelaySocket s(connected(Destination{{1,1,1,1},443},true));write_bytes(s.fd,client_hello(cc.get()));
          uint8_t b;const auto n=recv(s.fd,&b,1,0);need(n==0||(n<0&&errno==ECONNRESET));
          if(decoy) {
            RelaySocket attempted(accept4(decoy->socket.fd,nullptr,nullptr,SOCK_CLOEXEC));
            need(attempted.fd<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
          }
          std::cout<<"native public policy no fallback PASS"<<std::endl;
        } else need(false);
      }
      return 0;
    }
    if (argc>=5) { engine_redirect(cc.get(),sc.get(),argv[3],argv[4],argc==6,argv[1],argv[2]); return 0; }
    Origin origin(sc.get()); const auto dst = origin.destination();
    Digest secret{}; secret.fill(0x42); SniAuthorization auth(secret,"relay.example");
    durable_socket_restart(cc.get(),sc.get(),auth);
    Listener e, c; const auto exit_address = e.destination, client_address = c.destination;
    RelayLimits limits; limits.sessions = 2; limits.hello_ms = 500;
    RelayListener exit(e.release(),false,auth,{}, {},DestinationPolicy({dst}),limits);
    RelayListener client(c.release(),true,auth,dst,exit_address,DestinationPolicy({dst}),limits);
    const auto hello = parse(client_hello(cc.get()));
    auto wire = auth.seal(hello,dst,wall_seconds());
    // A valid authenticated prefix opens exactly one origin connection. Its
    // replay, bad keys, tampered CH, plaintext, and denied destination open none.
    { RelaySocket s(connected(exit_address)); write_bytes(s.fd,wire); uint8_t b; need(recv(s.fd,&b,1,0) == 1); }
    until([&] {return origin.failed == 1 && exit.failed == 1;});
    denied(exit_address,wire);
    auto tampered = wire; tampered[11] ^= 1; denied(exit_address,tampered);
    Digest bad = secret; bad[0] ^= 1; SniAuthorization wrong(bad,"relay.example");
    denied(exit_address,wrong.seal(hello,dst,wall_seconds()));
    auto forbidden = dst; forbidden.port = forbidden.port == 65535 ? 1 : forbidden.port + 1;
    denied(exit_address,auth.seal(hello,forbidden,wall_seconds()));
    denied(exit_address,Bytes{'G','E','T',' ','/'});
    denied(exit_address,Bytes{22,3,3,255,255});
    denied(exit_address,Bytes{22,3,3}); // incomplete hello expires without a connect
    need(origin.connections == 1);
    // Admission cap includes slow/incomplete hellos, not just ready sessions.
    until([&] {return exit.failed == 8;});
    {
      RelaySocket a(connected(exit_address)), b(connected(exit_address));
      until([&] {return exit.accepted >= 10;});
      RelaySocket extra(connected(exit_address)); uint8_t byte; ssize_t n = recv(extra.fd,&byte,1,0);
      need(n == 0 || (n < 0 && errno == ECONNRESET));
      until([&] {return exit.admission_dropped >= 1;});
    }
    until([&] {return exit.failed >= 10;});
    try {
      transfer(cc.get(),client_address,TLS1_2_VERSION);
      transfer(cc.get(),client_address,TLS1_3_VERSION);
    } catch (...) {
      std::cerr << "client=" << client.last_failure() << " exit=" << exit.last_failure() << '\n'; throw;
    }
    until([&] {return client.completed == 2 && exit.completed == 2 && origin.completed == 2;});
    need(!exit.broken && !client.broken && client.failed == 0 && origin.connections == 3 && origin.bytes == 2 * 1048576);
    bulk_transfer(cc.get(),sc.get(),auth);
    // Owner cancellation interrupts workers waiting for incomplete ClientHello.
    Listener cancelled; const auto cancelled_address = cancelled.destination;
    auto owner = std::make_unique<RelayListener>(cancelled.release(),false,auth,Destination{},Destination{},DestinationPolicy({dst}));
    RelaySocket pending(connected(cancelled_address)); until([&] { return owner->accepted == 1; });
    const auto stopped = monotonic_ms(); owner.reset(); need(monotonic_ms() - stopped < 1000);
    uint8_t byte; need(recv(pending.fd,&byte,1,0) == 0);
    std::cout << "native transparent sockets PASS: TLS12/TLS13-HRR, 2 MiB echo, half-close, auth-before-connect, replay, admission\n";
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; ERR_print_errors_fp(stderr); return 1; }
}
