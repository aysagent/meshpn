#include "transparent_credentials.hpp"
#include <openssl/ssl.h>
#include <filesystem>
#include <iostream>
using namespace cvpn;
using namespace cvpn::transparent;
static void need(bool ok) { require(ok,"quota_test_assert"); }
template<class F> static void fails(F f,const char* expected) {
  try { f(); } catch(const std::runtime_error& e) { need(std::string(e.what())==expected); return; }
  throw std::runtime_error("quota_test_missing_failure");
}
static Hello hello() {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  BIO* in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());need(in&&out);
  SSL_set_bio(ssl.get(),in,out);SSL_set_connect_state(ssl.get());
  need(SSL_set_tlsext_host_name(ssl.get(),"origin.example"));
  need(SSL_do_handshake(ssl.get())<0);Bytes bytes(16384);
  int n=BIO_read(out,bytes.data(),bytes.size());need(n>0);bytes.resize(n);return parse(bytes);
}
static void same_address_sockets(const Hello& h, const std::vector<std::shared_ptr<SniAuthorization>>& keys) {
  auto listen=[](Destination& d){
    RelaySocket fd(socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));need(fd.fd>=0);
    auto a=socket_address(d);need(bind(fd.fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
    socklen_t n=sizeof(a);need(getsockname(fd.fd,reinterpret_cast<sockaddr*>(&a),&n)==0);d.port=ntohs(a.sin_port);
    need(::listen(fd.fd,16)==0);int owned=fd.fd;fd.fd=-1;return owned;
  };
  auto until=[](auto fn){auto end=monotonic_ms()+3000;while(!fn()){need(monotonic_ms()<end);std::this_thread::sleep_for(std::chrono::milliseconds(5));}};
  Destination dst{{127,0,0,1},0},endpoint=dst;RelaySocket origin(listen(dst));
  auto admission=std::make_shared<ExitAdmission>(4,2);
  for(auto k:keys)admission->add(k,std::make_shared<ReplayWindow>());
  auto exit=std::make_unique<RelayListener>(listen(endpoint),false,*keys[0],Destination{},Destination{},DestinationPolicy({dst}),RelayLimits{},nullptr,false,admission);
  auto connect=[&](size_t identity){
    auto app=std::make_unique<RelaySocket>(socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));need(app->fd>=0);
    auto a=socket_address(endpoint);need(::connect(app->fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
    need(fcntl(app->fd,F_SETFL,O_NONBLOCK)==0);
    const auto token=keys[identity]->seal(h,dst,wall_seconds());
    need(send(app->fd,token.data(),token.size(),MSG_NOSIGNAL)==ssize_t(token.size()));return app;
  };
  auto receive_origin=[&]{
    int fd=-1;until([&]{fd=accept4(origin.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);return fd>=0;});
    auto peer=std::make_unique<RelaySocket>(fd);const std::atomic<bool> stop{false};
    need(socket_hello(fd,monotonic_ms()+2000,stop).hello.wire==h.wire);return peer;
  };
  auto a=connect(0),pa=receive_origin();auto b=connect(0),pb=receive_origin();
  auto blocked=connect(0);until([&]{char byte;const auto n=recv(blocked->fd,&byte,1,0);return n==0||(n<0&&errno==ECONNRESET);});
  need(accept4(origin.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC)<0&&errno==EAGAIN);
  auto c=connect(1),pc=receive_origin();need(admission->active()==3);
  // Both identities arrive from precisely the same source IPv4, not different NATs.
  for(auto* app:{a.get(),b.get(),c.get()}){sockaddr_in local{};socklen_t n=sizeof(local);need(getsockname(app->fd,reinterpret_cast<sockaddr*>(&local),&n)==0&&ntohl(local.sin_addr.s_addr)==0x7f000001);}
  // Reload retains the first identity and its quota, but cancels the second.
  // Both were authenticated from the same source address.
  auto kept=admission->retained(*keys[0],"");need(bool(kept));
  admission->replace({kept});
  until([&]{char byte;const auto n=recv(c->fd,&byte,1,0);return n==0||(n<0&&errno==ECONNRESET);});
  until([&]{return admission->active()==2;});
  for(auto* app:{a.get(),b.get()}){char byte;need(recv(app->fd,&byte,1,0)<0&&errno==EAGAIN);}
  auto denied=connect(1);until([&]{char byte;const auto n=recv(denied->fd,&byte,1,0);return n==0||(n<0&&errno==ECONNRESET);});
  need(accept4(origin.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC)<0&&errno==EAGAIN);
  admission->replace({});until([&]{return admission->active()==0;});
  exit.reset();need(admission->active()==0);
}
int main() { try {
  const auto h=hello(); const Destination dst{{11,22,33,44},443};const DestinationPolicy policy({dst});
  std::vector<std::shared_ptr<SniAuthorization>> keys;
  for(unsigned i=0;i<4;++i){Digest key{};key[0]=i+1;keys.push_back(std::make_shared<SniAuthorization>(key,"relay.example"));}
  auto token=[&](size_t i){return parse(keys[i]->seal(h,dst,100));};
  const auto clock=[] {return std::make_pair(uint64_t(100),uint64_t(1000));};
  ExitAdmission quota(4,2);
  for(auto k:keys)quota.add(k,std::make_shared<ReplayWindow>());
  fails([&]{quota.add(keys[0],std::make_shared<ReplayWindow>());},"relay_duplicate_key");
  auto a=quota.accept(token(0),policy,clock),b=quota.accept(token(0),policy,clock);
  const auto blocked=token(0);fails([&]{quota.accept(blocked,policy,clock);},"relay_peer_limit");
  auto c=quota.accept(token(1),policy,clock),d=quota.accept(token(2),policy,clock);
  need(quota.active()==4);fails([&]{quota.accept(token(3),policy,clock);},"relay_global_limit");
  b.lease.reset();auto admitted=quota.accept(blocked,policy,clock);need(quota.active()==4);
  admitted.lease.reset();fails([&]{quota.accept(blocked,policy,clock);},"relay_replayed");need(quota.active()==3);
  // Invalid binding consumes no slot, including exception unwinding after reservation.
  auto altered=token(3);altered.payload[6]^=1;
  fails([&]{quota.accept(altered,policy,clock);},"relay_hello_binding");need(quota.active()==3);
  a.lease.reset();c.lease.reset();d.lease.reset();need(quota.active()==0);
  Digest unknown{};SniAuthorization stranger(unknown,"relay.example");
  fails([&]{quota.accept(parse(stranger.seal(h,dst,100)),policy,clock);},"relay_token_auth");
  // Same key from many threads never escapes its quota. Other keys keep progress.
  std::atomic<unsigned> ready{0},success{0};std::atomic<bool> release{false};std::vector<std::thread> threads;
  for(unsigned i=0;i<24;++i)threads.emplace_back([&]{
    std::shared_ptr<void> held;
    try{held=quota.accept(token(0),policy,clock).lease;++success;}catch(const std::runtime_error& e){need(std::string(e.what())=="relay_peer_limit");}
    ++ready;while(!release)std::this_thread::yield();
  });
  while(ready<24) { std::this_thread::yield(); }
  need(success==2&&quota.active()==2);
  {auto other=quota.accept(token(1),policy,clock);need(quota.active()==3);}
  release=true;for(auto& t:threads)t.join();need(quota.active()==0);
  same_address_sockets(h,keys);
  // Config bounds, IDs, duplicate keys and durable independent replay on restart.
  using J=nlohmann::json;
  J config={{"version",1},{"transport","transparent-tls"},{"role","exit"},{"listen",{{"ipv4","0.0.0.0"},{"port",3443}}},
    {"public_name","relay.example"},{"destination_policy",{{"mode","public-https"},{"deny_ipv4",J::array()}}},
    {"replay_directory","/tmp/unused"},{"peers",J::array({{{"id","a"},{"secret_path","/key-a"}},{{"id","b"},{"secret_path","/key-b"}}})},
    {"limits",{{"sessions",128},{"per_client",64}}}};
  for(auto total:{0,1,257}){auto bad=config;bad["limits"]["sessions"]=total;fails([&]{TransparentConfig c0(bad);},"relay_quota_config");}
  {auto bad=config;bad["limits"]["per_client"]=128;fails([&]{TransparentConfig c0(bad);},"relay_quota_config");}
  {auto bad=config;bad["peers"][1]["id"]="../x";fails([&]{TransparentConfig c0(bad);},"relay_peer_id");}
  {auto bad=config;bad["peers"][1]["id"]="a";fails([&]{TransparentConfig c0(bad);},"relay_peer_id");}
  char temp[]="/tmp/cvpn-quota-XXXXXX";need(mkdtemp(temp));config["replay_directory"]=temp;
  struct Cleanup{std::string p;~Cleanup(){std::filesystem::remove_all(p);}} cleanup{temp};
  TransparentConfig conf(config);
  fails([&]{RelayCredentials duplicate(conf,[](const std::string&){return std::string(32,'x');});},"relay_duplicate_key");
  RelayCredentials credentials(conf,[](const std::string& p){std::string key(32,0);key[0]=p=="/key-a"?1:2;return key;});
  credentials.initialize();fails([&]{credentials.initialize();},"relay_peer_replay_exists_or_create_failed");
  const auto saved=token(0);
  {auto live=credentials.open();auto first=live->accept(saved,policy,clock);auto second=live->accept(token(1),policy,clock);need(live->active()==2);}
  {auto reopened=credentials.open();fails([&]{reopened->accept(saved,policy,clock);},"relay_replayed");
    // Live replacement must reuse the locked ReplayWindow, never reset/reopen it.
    auto next=credentials.prepare(*reopened);need(next.size()==2);
    reopened->replace(std::move(next));fails([&]{reopened->accept(saved,policy,clock);},"relay_replayed");
    auto bad=config;bad["peers"][1]["id"]="changed-path";TransparentConfig changed(bad);
    RelayCredentials moved(changed,[](const std::string& p){std::string key(32,0);key[0]=p=="/key-a"?1:2;return key;});
    fails([&]{moved.prepare(*reopened);},"relay_reload_replay_path_changed");
    auto ok=reopened->accept(token(1),policy,clock);need(reopened->active()==1);
    auto retained=reopened->retained(*keys[1],std::string(temp)+"/b");need(bool(retained));
    reopened->replace({retained});need(!ok.identity->revoked.load()&&reopened->active()==1);
    reopened->replace({});need(ok.identity->revoked.load());ok.lease.reset();need(reopened->active()==0);
  }
  // Removing a peer revokes its key; retained peer keeps its original replay scope.
  config["peers"].erase(0);TransparentConfig revoked(config);
  RelayCredentials remaining(revoked,[](const std::string&){std::string key(32,0);key[0]=2;return key;});
  {auto live=remaining.open();fails([&]{live->accept(token(0),policy,clock);},"relay_token_auth");auto ok=live->accept(token(1),policy,clock);}
  std::cout<<"QUOTA_PASS=key_identity_per_peer_global_concurrent_release_replay_revocation_config_same_ip_sockets_live_reload\n";
  return 0;
} catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;} }
