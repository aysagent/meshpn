// Experimental M1 engine. No Node/N-API packet callbacks, routing commands or
// payload IPC. The supervisor must provision TUN addresses/routes/guard first.
#include "protocol.hpp"
#include "dns_relay.hpp"
#include <nlohmann/json.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <chrono>
#include <array>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <functional>

using json = nlohmann::json;
using namespace cvpn;
using Clock = std::chrono::steady_clock;
static volatile sig_atomic_t interrupted = 0;
static void on_signal(int) { interrupted = 1; }
static void check(bool ok, const char* msg) { if (!ok) throw std::runtime_error(msg); }
struct Fd {
  int n = -1;
  explicit Fd(int x=-1):n(x){}
  ~Fd(){if(n>=0) close(n);}
  Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete;
};
static void nonblock(int fd) { int f=fcntl(fd,F_GETFL); check(f>=0 && fcntl(fd,F_SETFL,f|O_NONBLOCK)==0,"nonblock"); }
static std::string file(const std::string& path, size_t limit, bool secret=false) {
  Fd fd(open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW)); struct stat s{};
  check(fd.n>=0 && fstat(fd.n,&s)==0 && S_ISREG(s.st_mode) && s.st_size>=0 && size_t(s.st_size)<=limit,"file_invalid");
  if(secret) check((s.st_mode&077)==0 && s.st_uid==geteuid(),"secret_permissions");
  std::string b; char buf[4096]; ssize_t n;
  while((n=read(fd.n,buf,sizeof(buf)))>0){b.append(buf,n); check(b.size()<=limit,"file_limit");}
  check(n==0,"file_read"); return b;
}
struct Config {
  struct Peer { uint32_t address; std::string secret; };
  std::vector<Peer> peers;
  std::string peer_ipv4="10.99.0.2";
  uint32_t peer_address=0;
  bool client;
  bool dns=false;
  std::string address, name, sni, ca, cert, key, tun, secret_path;
  uint16_t port;
  explicit Config(const json& j) {
    check(j.is_object(),"config_object");
    const std::set<std::string> fields={"version","role","address","port","server_name","sni","ca","cert","key","tun","secret_path","dns","peer_ipv4","peers"};
    for(auto it=j.begin();it!=j.end();++it) check(fields.count(it.key()),"unknown_config_field");
    check(j.at("version")==1,"config_version");
    auto role=j.at("role").get<std::string>(); check(role=="client"||role=="exit","role"); client=role=="client";
    dns=j.value("dns",false);check(!dns||client,"dns_client_only");
    address=j.at("address").get<std::string>(); in_addr ip{};
    check(inet_pton(AF_INET,address.c_str(),&ip)==1,"numeric_ipv4_required");
    auto p=j.at("port").get<int>(); check(p>0&&p<=65535,"port"); port=p;
    tun=j.at("tun").get<std::string>(); check(!tun.empty()&&tun.size()<IFNAMSIZ,"tun_name");
    for(char c:tun) check(std::isalnum(static_cast<unsigned char>(c))||c=='_'||c=='-',"tun_name");
    auto peer_ip=[](const std::string& text){in_addr a{};
      check(inet_pton(AF_INET,text.c_str(),&a)==1,"peer_ipv4");
      auto n=ntohl(a.s_addr);check((n&0xffffff00)==0x0a630000&&(n&255)>=2&&(n&255)<=254,"peer_ipv4");return a.s_addr;};
    peer_ipv4=j.value("peer_ipv4",peer_ipv4);peer_address=peer_ip(peer_ipv4);
    if(j.contains("peers")){
      check(!client&&!j.contains("secret_path")&&!j.contains("peer_ipv4"),"peer_config_conflict");
      const auto& list=j.at("peers");check(list.is_array()&&!list.empty()&&list.size()<=32,"peer_limit");
      for(const auto& p:list){
        check(p.is_object()&&p.size()==2&&p.contains("ipv4")&&p.contains("secret_path"),"peer_config");
        Peer next{peer_ip(p.at("ipv4").get<std::string>()),file(p.at("secret_path").get<std::string>(),32,true)};
        check(next.secret.size()==32,"secret_length");
        for(const auto& old:peers)check(next.address!=old.address&&next.secret!=old.secret,"duplicate_peer");
        peers.push_back(std::move(next));
      }
    }else{
      secret_path=j.at("secret_path").get<std::string>();
      if(!client){auto key_bytes=file(secret_path,32,true);check(key_bytes.size()==32,"secret_length");peers.push_back({peer_address,std::move(key_bytes)});}
    }
    if(client){
      name=j.at("server_name").get<std::string>(); sni=j.value("sni",name); ca=j.at("ca").get<std::string>();
      for(const auto& host:{name,sni}) {
        check(!host.empty()&&host.size()<=253,"tls_name");
        for(char c:host) check(std::isalnum(static_cast<unsigned char>(c))||c=='-'||c=='.',"tls_name");
      }
    } else {cert=j.at("cert").get<std::string>(); key=j.at("key").get<std::string>();}
  }
  ~Config(){for(auto& p:peers)OPENSSL_cleanse(p.secret.data(),p.secret.size());}
};
struct Control {
  std::atomic<bool> dns_ready{false};
  std::atomic<bool> dns_failed{false};
  std::atomic<bool> dns_idle{false}, dns_demand{false};
  unsigned address_reports=0;
  bool stop=false, uplink=true;
  uint64_t generation=0, tx=0, rx=0, dropped=0;
  std::string input, state="starting";
  void emit(const std::string& event) {
    std::string line=json({{"version",1},{"event",event},{"state",state},{"generation",generation},
      {"tx_packets",tx},{"rx_packets",rx},{"dropped_packets",dropped}}).dump()+"\n";
    // Events are smaller than PIPE_BUF; a blocked supervisor cannot retain data.
    ssize_t n=write(STDOUT_FILENO,line.data(),line.size());
    if(n!=ssize_t(line.size())) stop=true;
  }
  void set(const std::string& s){
    if(s=="ready")dns_demand=false; // Coalesce concurrent DNS wake requests.
    dns_idle=s=="idle_wait";dns_ready=s=="ready";state=s;emit("state");
  }
  void rejected_address(const Bytes& packet,bool client){
    // Bounded, explicit metadata only. Never expose packet bytes or ports.
    if(address_reports>=16)return;
    address_reports++;
    char src[INET_ADDRSTRLEN],dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,packet.data()+12,src,sizeof(src));inet_ntop(AF_INET,packet.data()+16,dst,sizeof(dst));
    auto line=json({{"version",1},{"event","peer_address_rejected"},{"role",client?"client":"exit"},
      {"source",src},{"destination",dst},{"protocol",packet[9]}}).dump()+"\n";
    if(write(STDOUT_FILENO,line.data(),line.size())!=ssize_t(line.size()))stop=true;
  }
  void read_commands() {
    char b[1024]; ssize_t n;
    unsigned reads=0;
    while(reads++<4 && (n=read(STDIN_FILENO,b,sizeof(b)))>0) {
      input.append(b,n); if(input.size()>4096){stop=true;return;}
      size_t e;
      while((e=input.find('\n'))!=std::string::npos){
        auto line=input.substr(0,e);input.erase(0,e+1);
        try {
          auto j=json::parse(line); check(j.is_object(),"command_object");
          auto op=j.at("op").get<std::string>();
          if(op=="status"&&j.size()==1) emit("status");
          else if(op=="stop"&&j.size()==1) stop=true;
          else if(op=="uplink"&&j.size()==2&&j.at("ready").is_boolean()){
            bool next=j.at("ready"); if(next!=uplink){uplink=next;generation++;set(next?"uplink_ready":"waiting_uplink");}
          } else stop=true;
        } catch(...){stop=true;}
      }
    }
    if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))stop=true;
    if(interrupted||dns_failed)stop=true;
  }
};
static void wait_fd(int fd, short events, Control& ctl, Clock::time_point deadline, uint64_t generation) {
  while(true){
    ctl.read_commands();
    check(!ctl.stop&&ctl.uplink&&ctl.generation==generation,"cancelled");
    auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
    check(left>0,"connect_deadline");
    pollfd p[]={{fd,events,0},{STDIN_FILENO,POLLIN,0}};
    int rc=poll(p,2,int(std::min<int64_t>(left,100)));
    if(rc<0){check(errno==EINTR,"poll");continue;}
    if(p[0].revents&(events|POLLERR|POLLHUP)) return;
  }
}
static sockaddr_in endpoint(const Config& c) {
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(c.port);inet_pton(AF_INET,c.address.c_str(),&a.sin_addr);return a;
}
static int packet_fd(const Config& c, int test_fd) {
#ifdef CVPN_TEST_PACKET_FD
  if(test_fd>=0){
    int type=0; socklen_t len=sizeof(type); sockaddr_storage a{};socklen_t alen=sizeof(a);
    check(getsockopt(test_fd,SOL_SOCKET,SO_TYPE,&type,&len)==0&&type==SOCK_DGRAM&&getsockname(test_fd,reinterpret_cast<sockaddr*>(&a),&alen)==0&&a.ss_family==AF_UNIX,"fixture_fd");
    nonblock(test_fd);return test_fd;
  }
#else
  check(test_fd<0,"fixture_disabled");
#endif
  // Require a provisioned device: do not silently create/configure a new link.
  check(if_nametoindex(c.tun.c_str())!=0,"tun_not_provisioned");
  Fd fd(open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC));check(fd.n>=0,"tun_open");
  ifreq req{};req.ifr_flags=IFF_TUN|IFF_NO_PI;std::memcpy(req.ifr_name,c.tun.c_str(),c.tun.size());
  check(ioctl(fd.n,TUNSETIFF,&req)==0&&c.tun==req.ifr_name,"tun_attach");
  int result=fd.n;fd.n=-1;return result;
}
static int alpn(SSL*,const uint8_t** out,uint8_t* outlen,const uint8_t* in,unsigned n,void*) {
  for(unsigned i=0;i<n;){unsigned len=in[i++];if(len>n-i)return SSL_TLSEXT_ERR_ALERT_FATAL;
    if(len==2&&std::memcmp(in+i,"h2",2)==0){*out=in+i;*outlen=2;return SSL_TLSEXT_ERR_OK;}i+=len;}
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
static std::array<uint8_t,32> exporter(SSL* ssl) {
  std::array<uint8_t,32> b{}; const char label[]="EXPORTER-clean-vpn-bind";
  check(SSL_export_keying_material(ssl,b.data(),b.size(),label,sizeof(label)-1,nullptr,0,0)==1,"exporter");return b;
}
static std::string token(const std::string& secret,const std::array<uint8_t,32>& exp,int64_t window) {
  std::string message="clean-vpn-tls-v2:";message.append(reinterpret_cast<const char*>(exp.data()),exp.size());message+=":"+std::to_string(window);
  uint8_t out[32];unsigned len=0;
  check(HMAC(EVP_sha256(),secret.data(),secret.size(),reinterpret_cast<const uint8_t*>(message.data()),message.size(),out,&len)!=nullptr&&len==32,"hmac");
  const char hex[]="0123456789abcdef";std::string result;
  for(int i=0;i<16;i++){result+=hex[out[i]>>4];result+=hex[out[i]&15];}OPENSSL_cleanse(out,sizeof(out));return result;
}
static bool authenticate(const std::string& provided,const std::string& secret,SSL* ssl) {
  if(provided.size()!=39||provided.substr(0,7)!="Bearer ")return false;
  auto exp=exporter(ssl); auto window=int64_t(time(nullptr))/900;bool ok=false;
  for(int offset:{0,-1,1}){auto expected=token(secret,exp,window+offset);ok|=CRYPTO_memcmp(expected.data(),provided.data()+7,32)==0;}
  return ok; // No legacy unbound-token fallback.
}
static void h2check(int rc){check(rc>=0,"http2_error");}
struct Session {
  const Config& config;Control& ctl;SSL* ssl;const std::string& secret;
  nghttp2_session* h2=nullptr;
  Queue outgoing, network, packets; Decoder decoder;
  int32_t stream=-1;bool ready=false,deferred=false;
  uint32_t peer_address;
  std::function<bool(uint32_t)> claim;
  const char* failure=nullptr;
  size_t header_bytes=0;std::map<std::string,std::string> headers;
  Clock::time_point next_ping=Clock::now()+std::chrono::seconds(2),ping_deadline{};
  std::array<uint8_t,8> ping{}; bool ping_pending=false;
  Session(const Config& c,Control& x,SSL* s,const std::string& k):config(c),ctl(x),ssl(s),secret(k),peer_address(c.peer_address){}
  ~Session(){if(h2)nghttp2_session_del(h2);}
  void fail(const char* code){if(!failure)failure=code;}
  static const char* callback_error(const char* message){
    // Only our own fixed vocabulary can cross the metadata boundary. Never
    // surface library exceptions, peer headers, GOAWAY debug data or payloads.
    for(const char* code:{"unexpected_headers","headers_limit","duplicate_header","request_invalid",
        "auth_rejected","peer_busy","early_end","vpn_response_rejected","data_before_auth","peer_address","peer_destination",
        "invalid_ipv4","invalid_frame_length","queue_limit","queue_consume","http2_error","exporter","hmac",
        "auth_deadline","h2_ping_timeout","h2_goaway_no_error","h2_goaway_error","h2_reset_no_error","h2_reset_error",
        "h2_peer_end_stream","h2_stream_closed","h2_stream_error","h2_invalid_frame","h2_local_goaway_error",
        "h2_local_reset_error","h2_flooded","h2_no_memory","h2_bad_client_magic","http2_receive",
        "tls_handshake","tls_write","tls_read","tls_peer_closed","h2_required","tun_write"})
      if(std::strcmp(message,code)==0)return code;
    return "h2_callback_failure";
  }
  template<class F> static int safe(void* u,F f){auto& s=*static_cast<Session*>(u);try{f(s);return 0;}
    catch(const std::exception& e){s.fail(callback_error(e.what()));return NGHTTP2_ERR_CALLBACK_FAILURE;}
    catch(...){s.fail("h2_callback_failure");return NGHTTP2_ERR_CALLBACK_FAILURE;}}
  static ssize_t send_cb(nghttp2_session*,const uint8_t* b,size_t n,int,void* u){
    auto& s=*static_cast<Session*>(u);
    if(n>queue_limit-s.network.size())return NGHTTP2_ERR_WOULDBLOCK;
    try{s.network.push(Bytes(b,b+n));return n;}catch(...){s.fail("h2_send_callback_failure");return NGHTTP2_ERR_CALLBACK_FAILURE;}
  }
  static ssize_t data_read(nghttp2_session*,int32_t,uint8_t* b,size_t n,uint32_t*,nghttp2_data_source*,void* u){
    auto& s=*static_cast<Session*>(u);if(s.outgoing.empty()){s.deferred=true;return NGHTTP2_ERR_DEFERRED;}
    return s.outgoing.read(b,n);
  }
  static int header_cb(nghttp2_session*,const nghttp2_frame* f,const uint8_t* name,size_t nl,const uint8_t* value,size_t vl,uint8_t,void* u){
    return safe(u,[&](Session& s){
      check(!s.ready&&f->hd.stream_id==1,"unexpected_headers");
      s.header_bytes+=nl+vl;check(s.header_bytes<=8192&&s.headers.size()<32,"headers_limit");
      check(s.headers.emplace(std::string(reinterpret_cast<const char*>(name),nl),std::string(reinterpret_cast<const char*>(value),vl)).second,"duplicate_header");
    });
  }
  void respond(){
    check(headers[":method"]=="POST"&&headers[":path"]=="/clean-vpn"&&headers[":scheme"]=="https","request_invalid");
    bool authenticated=false;
    for(const auto& peer:config.peers)if(authenticate(headers["authorization"],peer.secret,ssl)){
      authenticated=true;peer_address=peer.address;
    }
    check(authenticated,"auth_rejected");
    check(!claim||claim(peer_address),"peer_busy");
    stream=1;
    submit_headers({{":status","200"},{"content-type","application/octet-stream"}},false);
    ready=true;headers.clear(); // Exit reactor claims address before packet I/O.
  }
  static int frame_cb(nghttp2_session*,const nghttp2_frame* f,void* u){
    return safe(u,[&](Session& s){
      if(f->hd.type==NGHTTP2_HEADERS){
        check(!(f->hd.flags&NGHTTP2_FLAG_END_STREAM),"early_end");
        if(s.config.client){check(s.headers[":status"]=="200"&&s.headers["content-type"]=="application/octet-stream","vpn_response_rejected");s.ready=true;s.headers.clear();s.ctl.set("ready");}
        else s.respond();
      }
      if(f->hd.type==NGHTTP2_GOAWAY)s.fail(f->goaway.error_code==NGHTTP2_NO_ERROR?"h2_goaway_no_error":"h2_goaway_error");
      if(f->hd.type==NGHTTP2_RST_STREAM&&f->hd.stream_id==s.stream)
        s.fail(f->rst_stream.error_code==NGHTTP2_NO_ERROR?"h2_reset_no_error":"h2_reset_error");
      if(f->hd.type==NGHTTP2_DATA&&f->hd.stream_id==s.stream&&(f->hd.flags&NGHTTP2_FLAG_END_STREAM))s.fail("h2_peer_end_stream");
      if(f->hd.type==NGHTTP2_PING&&(f->hd.flags&NGHTTP2_FLAG_ACK)&&s.ping_pending&&CRYPTO_memcmp(f->ping.opaque_data,s.ping.data(),8)==0){s.ping_pending=false;s.next_ping=Clock::now()+std::chrono::seconds(2);}
    });
  }
  static int invalid_frame_cb(nghttp2_session*,const nghttp2_frame*,int,void* u){
    static_cast<Session*>(u)->fail("h2_invalid_frame");return 0;
  }
  static int sent_frame_cb(nghttp2_session*,const nghttp2_frame* f,void* u){
    auto& s=*static_cast<Session*>(u);
    // Some parse errors (e.g. invalid PING size) terminate inside nghttp2
    // without on_invalid_frame_recv. Do not wait for a misleading PING timeout.
    if(f->hd.type==NGHTTP2_GOAWAY&&f->goaway.error_code!=NGHTTP2_NO_ERROR)s.fail("h2_local_goaway_error");
    if(f->hd.type==NGHTTP2_RST_STREAM&&f->hd.stream_id==s.stream&&f->rst_stream.error_code!=NGHTTP2_NO_ERROR)
      s.fail("h2_local_reset_error");
    return 0;
  }
  static int stream_close_cb(nghttp2_session*,int32_t id,uint32_t error,void* u){
    auto& s=*static_cast<Session*>(u);
    if(id==s.stream)s.fail(error==NGHTTP2_NO_ERROR?"h2_stream_closed":"h2_stream_error");
    return 0;
  }
  static int data_cb(nghttp2_session* h,uint8_t,int32_t id,const uint8_t* b,size_t n,void* u){
    return safe(u,[&](Session& s){
      check(s.ready&&id==s.stream,"data_before_auth");
      s.decoder.feed(b,n,[&](Bytes p){
        // M1 does not deliver multicast to the client TUN. A legacy exit may
        // send its own IGMP reports (e.g. 10.99.0.1 -> 224.0.0.22). Discard
        // the validated frame without tearing down the authenticated session.
        // Decoder has already checked IPv4 size/header/checksum; unicast
        // destination and exit-side source isolation below remain strict.
        if(s.config.client&&(p[16]&0xf0)==0xe0){s.ctl.dropped++;return;}
        // Current single-peer address contract, enforced before TUN injection.
        size_t off=s.config.client?16:12;
        if(std::memcmp(p.data()+off,&s.peer_address,4)!=0){s.ctl.rejected_address(p,s.config.client);s.ctl.dropped++;throw std::runtime_error("peer_address");}
        if(!s.config.client){
          // No implicit client-to-client routing through the shared TUN.
          for(const auto& peer:s.config.peers)check(std::memcmp(p.data()+16,&peer.address,4)!=0,"peer_destination");
        }
        s.packets.push(std::move(p));
      });
      h2check(nghttp2_session_consume(h,id,n));
    });
  }
  void submit_headers(const std::vector<std::pair<std::string,std::string>>& list,bool request){
    std::vector<nghttp2_nv> nv;
    for(const auto& kv:list)nv.push_back({reinterpret_cast<uint8_t*>(const_cast<char*>(kv.first.data())),reinterpret_cast<uint8_t*>(const_cast<char*>(kv.second.data())),kv.first.size(),kv.second.size(),NGHTTP2_NV_FLAG_NONE});
    nghttp2_data_provider provider{};provider.read_callback=data_read;
    if(request){stream=nghttp2_submit_request(h2,nullptr,nv.data(),nv.size(),&provider,nullptr);h2check(stream);}
    else h2check(nghttp2_submit_response(h2,stream,nv.data(),nv.size(),&provider));
  }
  void init(){
    nghttp2_session_callbacks* raw=nullptr;h2check(nghttp2_session_callbacks_new(&raw));
    std::unique_ptr<nghttp2_session_callbacks,decltype(&nghttp2_session_callbacks_del)> cb(raw,nghttp2_session_callbacks_del);
    nghttp2_session_callbacks_set_send_callback(raw,send_cb);
    nghttp2_session_callbacks_set_on_header_callback(raw,header_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(raw,frame_cb);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(raw,invalid_frame_cb);
    nghttp2_session_callbacks_set_on_frame_send_callback(raw,sent_frame_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(raw,stream_close_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(raw,data_cb);
    nghttp2_option* option=nullptr;h2check(nghttp2_option_new(&option));
    std::unique_ptr<nghttp2_option,decltype(&nghttp2_option_del)> opt(option,nghttp2_option_del);
    nghttp2_option_set_no_auto_window_update(option,1);
    nghttp2_option_set_max_deflate_dynamic_table_size(option,4096);
    nghttp2_option_set_max_send_header_block_length(option,8192);
    nghttp2_option_set_max_continuations(option,4);
    nghttp2_option_set_max_outbound_ack(option,128);
    nghttp2_option_set_max_settings(option,16);
    nghttp2_option_set_max_reserved_remote_streams(option,0);
    h2check(config.client?nghttp2_session_client_new2(&h2,raw,this,option):nghttp2_session_server_new2(&h2,raw,this,option));
    nghttp2_settings_entry settings[]={{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,1},{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,65535},{NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,8192}};
    h2check(nghttp2_submit_settings(h2,NGHTTP2_FLAG_NONE,settings,3));
    if(config.client){nghttp2_settings_entry no_push{NGHTTP2_SETTINGS_ENABLE_PUSH,0};h2check(nghttp2_submit_settings(h2,NGHTTP2_FLAG_NONE,&no_push,1));}
    if(config.client)submit_headers({{":method","POST"},{":path","/clean-vpn"},{":scheme","https"},{":authority",config.name},
      {"authorization","Bearer "+token(secret,exporter(ssl),int64_t(time(nullptr))/900)},{"accept","*/*"}},true);
  }
  short step(int tun,Clock::time_point deadline,Bytes& pending,bool shared_tun=false){
      std::array<uint8_t,65536> buffer{};
      if(failure)throw std::runtime_error(failure);
      if(!ready)check(Clock::now()<deadline,"auth_deadline");
      if(ready){
        if(ping_pending)check(Clock::now()<ping_deadline,"h2_ping_timeout");
        else if(Clock::now()>=next_ping){check(RAND_bytes(ping.data(),ping.size())==1,"random");h2check(nghttp2_submit_ping(h2,NGHTTP2_FLAG_NONE,ping.data()));ping_pending=true;ping_deadline=Clock::now()+std::chrono::seconds(5);}
      }
      int sent=nghttp2_session_send(h2);if(failure)throw std::runtime_error(failure);h2check(sent);
      bool read_wants_write=false;
      if(!network.empty()){
        int n=SSL_write(ssl,network.data(),network.front_size());
        if(n>0)network.consume(n);
        else{int e=SSL_get_error(ssl,n);check(e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE,"tls_write");}
      }
      // Bounded per-tick work: control/health cannot be starved by flood traffic.
      for(int i=0;i<32&&packets.size()<queue_limit-max_packet-16384;i++){
        int n=SSL_read(ssl,buffer.data(),16384);
        if(n<=0){int e=SSL_get_error(ssl,n);check(e!=SSL_ERROR_ZERO_RETURN,"tls_peer_closed");
          check(e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE,"tls_read");read_wants_write=e==SSL_ERROR_WANT_WRITE;break;}
        ssize_t used=nghttp2_session_mem_recv(h2,buffer.data(),n);
        if(failure)throw std::runtime_error(failure);
        check(used!=NGHTTP2_ERR_FLOODED,"h2_flooded");
        check(used!=NGHTTP2_ERR_NOMEM,"h2_no_memory");
        check(used!=NGHTTP2_ERR_BAD_CLIENT_MAGIC,"h2_bad_client_magic");
        check(used==n,"http2_receive");
      }
      if(!shared_tun){
      for(int i=0;i<32&&!packets.empty();i++){
        ssize_t n=write(tun,packets.data(),packets.front_size());
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        check(n==ssize_t(packets.front_size()),"tun_write");packets.consume(n);ctl.rx++;
      }
      // The wake packet precedes everything still in the kernel TUN queue,
      // including packets arriving in the same tick as authenticated headers.
      if(ready&&!pending.empty()){
        outgoing.push(frame(pending.data(),pending.size()));pending.clear();ctl.tx++;
        if(deferred){h2check(nghttp2_session_resume_data(h2,stream));deferred=false;}
      }
      if(ready)for(int i=0;i<32&&outgoing.size()<queue_limit-max_packet-4;i++){
        ssize_t n=read(tun,buffer.data(),buffer.size());
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        check(n>0,"tun_read");
        if(!ipv4(buffer.data(),n)){ctl.dropped++;continue;}
        outgoing.push(frame(buffer.data(),n));ctl.tx++;
        if(deferred){h2check(nghttp2_session_resume_data(h2,stream));deferred=false;}
      }
      }
      // Newly read TUN packets must arm writable interest in this tick, not
      // wait for the next polling timeout before serialising HTTP/2 DATA.
      sent=nghttp2_session_send(h2);if(failure)throw std::runtime_error(failure);h2check(sent);
      return (packets.size()<queue_limit-max_packet-16384?POLLIN:0)|(!network.empty()||read_wants_write?POLLOUT:0);
  }
  void enqueue(const uint8_t* data,size_t n){
    outgoing.push(frame(data,n));ctl.tx++;
    if(deferred){h2check(nghttp2_session_resume_data(h2,stream));deferred=false;}
  }
  void run(int socket,int tun,Clock::time_point deadline,uint64_t generation,Bytes& pending){
    init();
    while(!ctl.stop&&!interrupted&&ctl.uplink&&ctl.generation==generation){
      short netevents=step(tun,deadline,pending);
      ctl.read_commands();
      short tunevents=(ready&&outgoing.size()<queue_limit-max_packet-4?POLLIN:0)|(!packets.empty()?POLLOUT:0);
      pollfd fds[]={{socket,netevents,0},{tun,tunevents,0},{STDIN_FILENO,POLLIN,0}};
      check(poll(fds,3,10)>=0||errno==EINTR,"poll");
    }
  }
};
static const char* tls_failure(SSL* ssl){
  // Fixed codes only: never emit certificates, peer text or the TLS error stack.
  switch(SSL_get_verify_result(ssl)){
    case X509_V_OK:return "tls_handshake";
    case X509_V_ERR_HOSTNAME_MISMATCH:return "tls_verify_name";
    case X509_V_ERR_CERT_HAS_EXPIRED:return "tls_verify_expired";
    case X509_V_ERR_CERT_NOT_YET_VALID:return "tls_verify_not_yet_valid";
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:return "tls_verify_untrusted";
    default:return "tls_verify_failed";
  }
}
static void handshake(SSL* ssl,int fd,Control& ctl,Clock::time_point deadline,uint64_t generation){
  while(true){int n=SSL_do_handshake(ssl);if(n==1)break;int e=SSL_get_error(ssl,n);
    if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE)throw std::runtime_error(tls_failure(ssl));
    wait_fd(fd,e==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,ctl,deadline,generation);}
  const uint8_t* proto=nullptr;unsigned n=0;SSL_get0_alpn_selected(ssl,&proto,&n);check(n==2&&std::memcmp(proto,"h2",2)==0,"h2_required");
}
// One bounded reactor owns listener, sessions and TUN. Slow TLS/auth peers do
// not block established tunnels; no per-packet threads, processes or IPC.
static void run_exit(const Config& config,SSL_CTX* context,int listener,int tun,Control& ctl){
  struct Connection {
    Fd fd;
    std::unique_ptr<SSL,decltype(&SSL_free)> ssl{nullptr,SSL_free};
    std::unique_ptr<Session> session;
    Clock::time_point deadline=Clock::now()+std::chrono::seconds(5);
    short interest=POLLIN;
    explicit Connection(int socket):fd(socket){}
  };
  std::vector<std::unique_ptr<Connection>> connections;
  std::map<uint32_t,Session*> owners;
  const std::string no_secret;Bytes pending;
  auto rate_window=Clock::now(),last_error=Clock::now()-std::chrono::seconds(1);
  unsigned admissions=0;
  uint64_t generation=ctl.generation;
  while(!ctl.stop&&!interrupted){
    ctl.read_commands();if(ctl.stop)break;
    if(!ctl.uplink||generation!=ctl.generation){connections.clear();owners.clear();generation=ctl.generation;}
    if(!ctl.uplink){pollfd p{STDIN_FILENO,POLLIN,0};poll(&p,1,50);continue;}
    auto now=Clock::now();
    if(now-rate_window>=std::chrono::seconds(1)){rate_window=now;admissions=0;}
    // A fixed admission budget bounds unauthenticated SSL allocations/CPU.
    for(unsigned i=0;i<4;i++){
      Fd accepted(accept4(listener,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC));
      if(accepted.n<0){check(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR,"accept");break;}
      size_t unauth=0;for(const auto& c:connections)if(!c->session||!c->session->ready)unauth++;
      if(admissions>=32||unauth>=16||connections.size()>=config.peers.size()+16)continue;
      admissions++;
      auto c=std::make_unique<Connection>(accepted.n);accepted.n=-1;
      int one=1;check(setsockopt(c->fd.n,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one))==0,"tcp_nodelay");
      c->ssl.reset(SSL_new(context));check(c->ssl&&SSL_set_fd(c->ssl.get(),c->fd.n)==1,"tls_socket");
      SSL_set_accept_state(c->ssl.get());SSL_set_mode(c->ssl.get(),SSL_MODE_ENABLE_PARTIAL_WRITE);
      connections.push_back(std::move(c));
      if(owners.empty()&&ctl.state=="listening")ctl.set("handshake");
    }
    for(auto it=connections.begin();it!=connections.end();){
      auto& c=**it;
      try{
        if(!c.session||!c.session->ready)check(Clock::now()<c.deadline,"auth_deadline");
        if(!c.session){
          int result=SSL_do_handshake(c.ssl.get());
          if(result==1){
            const uint8_t* proto=nullptr;unsigned length=0;SSL_get0_alpn_selected(c.ssl.get(),&proto,&length);
            check(length==2&&std::memcmp(proto,"h2",2)==0,"h2_required");
            c.session=std::make_unique<Session>(config,ctl,c.ssl.get(),no_secret);
            auto* session=c.session.get();
            session->claim=[&owners,session](uint32_t address){return owners.emplace(address,session).second;};
            session->init();
          }else{int error=SSL_get_error(c.ssl.get(),result);
            check(error==SSL_ERROR_WANT_READ||error==SSL_ERROR_WANT_WRITE,"tls_handshake");
            c.interest=error==SSL_ERROR_WANT_READ?POLLIN:POLLOUT;
          }
        }
        if(c.session){
          c.interest=c.session->step(tun,c.deadline,pending,true);
          // A per-session budget gives other authenticated peers a turn.
          for(int n=0;n<8&&!c.session->packets.empty();n++){
            auto& packets=c.session->packets;
            auto written=write(tun,packets.data(),packets.front_size());
            if(written<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
            check(written==ssize_t(packets.front_size()),"tun_write");packets.consume(written);ctl.rx++;
          }
        }
        ++it;
      }catch(const std::exception& error){
        if(c.session){auto owner=owners.find(c.session->peer_address);
          if(owner!=owners.end()&&owner->second==c.session.get())owners.erase(owner);}
        // Untrusted sessions cannot flood the bounded control channel.
        if(Clock::now()-last_error>=std::chrono::milliseconds(250)){
          ctl.set(Session::callback_error(error.what()));last_error=Clock::now();
        }
        it=connections.erase(it);
      }
    }
    std::array<uint8_t,65536> buffer{};
    for(unsigned i=0;i<64;i++){
      auto n=read(tun,buffer.data(),buffer.size());
      if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
      check(n>0,"tun_read");
      if(!ipv4(buffer.data(),n)){ctl.dropped++;continue;}
      uint32_t address;std::memcpy(&address,buffer.data()+16,4);auto found=owners.find(address);
      if(found==owners.end()||!found->second->ready){ctl.dropped++;continue;}
      auto* session=found->second;
      // A slow recipient cannot stop reading the shared TUN for everyone.
      if(session->outgoing.size()+size_t(n)+4>queue_limit){ctl.dropped++;continue;}
      session->enqueue(buffer.data(),n);
    }
    const auto state=!owners.empty()?"ready":connections.empty()?"listening":"handshake";
    if(ctl.state!=state)ctl.set(state);
    bool tun_write=false;
    std::vector<pollfd> fds={{listener,POLLIN,0},{STDIN_FILENO,POLLIN,0}};
    for(const auto& c:connections){
      short interest=c->interest;
      // TUN dispatch happened after step(): arm output in this tick, otherwise
      // every reply waits for the polling timeout before H2 serialization.
      if(c->session&&(!c->session->outgoing.empty()||!c->session->network.empty()))interest|=POLLOUT;
      fds.push_back({c->fd.n,interest,0});tun_write|=c->session&&!c->session->packets.empty();
    }
    fds.push_back({tun,short(POLLIN|(tun_write?POLLOUT:0)),0});
    check(poll(fds.data(),fds.size(),10)>=0||errno==EINTR,"poll");
  }
}
int main(int argc,char** argv){
  signal(SIGPIPE,SIG_IGN);signal(SIGTERM,on_signal);signal(SIGINT,on_signal);
  try{
    if(argc==2&&std::string(argv[1])=="--capabilities"){
      std::cout<<json({{"version",1},{"engine","clean-vpn-native-m1"},{"transport","boring-tls"},
        {"roles",{"client","exit"}},{"mode","ipv4-packets"},{"alpn",{"h2"}},
        {"dns","native-udp-tcp-fixed-upstreams"},{"multi_peer",true},{"max_peers",32},{"browser_profiles",false},
        {"packet_ipc",false},{"provisioning","external-control-plane"}}).dump()<<"\n";return 0;
    }
    bool validate=argc==3&&std::string(argv[1])=="--check-config";
    check(validate||((argc==3||argc==5)&&std::string(argv[1])=="--config"),"usage_config");int test=-1;
    if(argc==5){check(std::string(argv[3])=="--test-packet-fd","usage_fixture");test=std::stoi(argv[4]);check(test>2,"fixture_fd");}
    Config c(json::parse(file(argv[2],16384)));std::string secret;
    if(c.client){secret=file(c.secret_path,32,true);check(secret.size()==32,"secret_length");}
    std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_method()),SSL_CTX_free);check(bool(ctx),"tls_context");
    check(SSL_CTX_set_min_proto_version(ctx.get(),TLS1_3_VERSION)==1&&SSL_CTX_set_max_proto_version(ctx.get(),TLS1_3_VERSION)==1,"tls_version");
    SSL_CTX_set_options(ctx.get(),SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx.get(),SSL_SESS_CACHE_OFF);
    if(c.client){
      SSL_CTX_set_verify(ctx.get(),SSL_VERIFY_PEER,nullptr);check(SSL_CTX_load_verify_locations(ctx.get(),c.ca.c_str(),nullptr)==1,"ca_load");
      const uint8_t ap[]={2,'h','2'};check(SSL_CTX_set_alpn_protos(ctx.get(),ap,sizeof(ap))==0,"alpn");
    } else {
      check(SSL_CTX_use_certificate_chain_file(ctx.get(),c.cert.c_str())==1&&SSL_CTX_use_PrivateKey_file(ctx.get(),c.key.c_str(),SSL_FILETYPE_PEM)==1&&SSL_CTX_check_private_key(ctx.get())==1,"server_key");
      SSL_CTX_set_alpn_select_cb(ctx.get(),alpn,nullptr);
    }
    if(validate){
      OPENSSL_cleanse(secret.data(),secret.size());
      std::cout<<json({{"valid",true},{"role",c.client?"client":"exit"},{"peers",c.client?1:c.peers.size()}}).dump()<<"\n";return 0;
    }
    nonblock(STDIN_FILENO);nonblock(STDOUT_FILENO);Control ctl;
    Fd tun(packet_fd(c,test));
    std::unique_ptr<DnsRelay> dns;
    if(c.dns)dns=std::make_unique<DnsRelay>(c.tun,ctl.dns_ready,ctl.dns_failed,&ctl.dns_idle,&ctl.dns_demand,c.peer_ipv4);
    Fd listener;
    if(!c.client){
      listener.n=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);check(listener.n>=0,"listen_socket");int one=1;setsockopt(listener.n,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
      auto addr=endpoint(c);check(bind(listener.n,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0&&listen(listener.n,8)==0,"listen_bind");
    }
    ctl.set(c.client?"idle":"listening");
    if(!c.client){run_exit(c,ctx.get(),listener.n,tun.n,ctl);ctl.set("stopped");return 0;}
    bool demand_wait=false;Bytes pending;
    while(!ctl.stop&&!interrupted){
      ctl.read_commands();if(ctl.stop)break;
      if(!ctl.uplink){pollfd p{STDIN_FILENO,POLLIN,0};poll(&p,1,100);continue;}
      if(demand_wait){
        ctl.set("idle_wait");auto generation=ctl.generation;
        while(!ctl.stop&&!interrupted&&ctl.uplink&&ctl.generation==generation){
          ctl.read_commands();if(ctl.stop||!ctl.uplink||ctl.generation!=generation)break;
          if(ctl.dns_demand.exchange(false)){demand_wait=false;break;}
          std::array<uint8_t,65536> packet{};ssize_t n=read(tun.n,packet.data(),packet.size());
          if(n>0){
            if(ipv4(packet.data(),n)){pending.assign(packet.data(),packet.data()+n);demand_wait=false;break;}
            ctl.dropped++;
          }
          pollfd p[]={{STDIN_FILENO,POLLIN,0},{tun.n,POLLIN,0}};poll(p,2,25);
        }
        if(demand_wait||ctl.stop||interrupted)continue;
      }
      Fd socket_fd;
      bool authenticated=false;
      try{
        auto deadline=Clock::now()+std::chrono::seconds(10);auto generation=ctl.generation;
        socket_fd.n=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);check(socket_fd.n>=0,"connect_socket");auto addr=endpoint(c);
        ctl.set("connecting");int rc=connect(socket_fd.n,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
        if(rc<0){check(errno==EINPROGRESS,"connect");wait_fd(socket_fd.n,POLLOUT,ctl,Clock::now()+std::chrono::seconds(3),generation);int err=0;socklen_t size=sizeof(err);check(getsockopt(socket_fd.n,SOL_SOCKET,SO_ERROR,&err,&size)==0&&err==0,"connect");}
        int no_delay=1;
        check(setsockopt(socket_fd.n,IPPROTO_TCP,TCP_NODELAY,&no_delay,sizeof(no_delay))==0,"tcp_nodelay");
        std::unique_ptr<SSL,decltype(&SSL_free)> ssl(SSL_new(ctx.get()),SSL_free);check(bool(ssl)&&SSL_set_fd(ssl.get(),socket_fd.n)==1,"tls_socket");
        SSL_set_mode(ssl.get(),SSL_MODE_ENABLE_PARTIAL_WRITE);
          SSL_set_connect_state(ssl.get());
          check(SSL_set_tlsext_host_name(ssl.get(),c.sni.c_str())==1,"tls_sni");
          auto* verify=SSL_get0_param(ssl.get());
          // Old clean-vpn provisioning could issue CN=clean-vpn without SAN.
          // Preserve that one legacy identity; DNS SAN still takes precedence.
          // All other names retain SAN-only verification. CA/time checks remain.
          X509_VERIFY_PARAM_set_hostflags(verify,c.name=="clean-vpn"?0:X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
          check(X509_VERIFY_PARAM_set1_host(verify,c.name.data(),c.name.size())==1,"tls_identity");
        ctl.set("handshake");handshake(ssl.get(),socket_fd.n,ctl,deadline,generation);
        Session s(c,ctl,ssl.get(),secret);
        try{s.run(socket_fd.n,tun.n,deadline,generation,pending);}
        catch(...){authenticated=s.ready;throw;}
      }catch(const std::exception& e){
        // Only fixed internal error codes, never input headers, keys or payload.
        ctl.set(e.what());
        const std::string reason=e.what();
        demand_wait=authenticated&&(reason=="h2_peer_end_stream"||reason=="h2_goaway_no_error"||reason=="h2_stream_closed");
      }
      if(socket_fd.n>=0){close(socket_fd.n);socket_fd.n=-1;}
      if(!pending.empty()){pending.clear();ctl.dropped++;}
      if(demand_wait)continue; // Keep kernel backlog: the first valid packet wakes us.
      // Bounded best-effort drain of disconnected kernel backlog. Session
      // queues are always destroyed; a continuous producer cannot stall stop.
      std::array<uint8_t,65536> discard{};
      for(int i=0;i<256&&read(tun.n,discard.data(),discard.size())>0;i++)ctl.dropped++;
      auto retry=Clock::now()+std::chrono::milliseconds(250);
      while(!ctl.stop&&!interrupted&&Clock::now()<retry){ctl.read_commands();pollfd p{STDIN_FILENO,POLLIN,0};poll(&p,1,25);}
    }
    OPENSSL_cleanse(secret.data(),secret.size());ctl.set(ctl.dns_failed?"dns_failed":"stopped");return ctl.dns_failed?1:0;
  }catch(...){std::cerr<<"clean-vpn-engine: configuration or startup refused\n";return 1;}
}
