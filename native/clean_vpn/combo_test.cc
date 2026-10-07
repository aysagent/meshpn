#include "combo.hpp"
#include <openssl/ssl.h>
#include <future>
#include <iostream>
using namespace cvpn;
namespace tr=cvpn::transparent;
static void need(bool b){if(!b)throw std::runtime_error("combo_test_failed");}
template<class F> static void rejects(F f){bool failed=false;try{f();}catch(...){failed=true;}need(failed);}
static Bytes hello(const std::string& name) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));need(bool(ctx));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));need(bool(ssl));
  BIO* in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());need(in&&out);
  BIO_set_mem_eof_return(in,-1);SSL_set_bio(ssl.get(),in,out);SSL_set_connect_state(ssl.get());
  need(SSL_set_tlsext_host_name(ssl.get(),name.c_str())==1);
  int rc=SSL_do_handshake(ssl.get());need(rc<0&&SSL_get_error(ssl.get(),rc)==SSL_ERROR_WANT_READ);
  Bytes bytes(16384);rc=BIO_read(out,bytes.data(),bytes.size());need(rc>0);bytes.resize(rc);return bytes;
}
template<class F> static void until(F f){
  const auto end=tr::monotonic_ms()+2000;
  while(!f()){need(tr::monotonic_ms()<end);std::this_thread::sleep_for(std::chrono::milliseconds(5));}
}
static int listener(tr::Destination& dst){
  tr::RelaySocket s(socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));need(s.fd>=0);
  dst={{127,0,0,1},0};auto a=tr::socket_address(dst);need(bind(s.fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0);
  socklen_t n=sizeof(a);need(getsockname(s.fd,reinterpret_cast<sockaddr*>(&a),&n)==0);dst.port=ntohs(a.sin_port);
  need(listen(s.fd,32)==0);int fd=s.fd;s.fd=-1;return fd;
}
static int connect_to(tr::Destination dst){
  tr::RelaySocket s(socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));need(s.fd>=0);
  timeval timeout{2,0};need(setsockopt(s.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
  const auto a=tr::socket_address(dst);need(connect(s.fd,reinterpret_cast<const sockaddr*>(&a),sizeof(a))==0);
  const int fd=s.fd;s.fd=-1;return fd;
}
static void dispatch(){
  tr::Destination address,destination;tr::RelaySocket origin(listener(destination));
  tr::Digest key{};key.fill(42);tr::SniAuthorization auth(key,"relay.example");
  tr::RelayLimits limits;limits.hello_ms=500;
  auto exit=std::make_unique<combo::Exit>(listener(address),auth,"relay.example",tr::DestinationPolicy({destination}),
    std::make_shared<tr::ReplayWindow>(),limits);
  auto send=[](int fd,const Bytes& b){need(::send(fd,b.data(),b.size(),MSG_NOSIGNAL)==ssize_t(b.size()));};
  const auto plain=hello("localhost"),wire=auth.seal(tr::parse(plain),destination,tr::wall_seconds());
  // An authenticated relay opens the chosen origin once and restores exact CH.
  {
    tr::RelaySocket client(connect_to(address));send(client.fd,wire);tr::RelaySocket accepted;
    until([&]{accepted.fd=accept4(origin.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);return accepted.fd>=0;});
    Bytes got;until([&]{uint8_t b[16384];auto n=recv(accepted.fd,b,sizeof(b),0);if(n>0)got.insert(got.end(),b,b+n);return got.size()>=plain.size();});
    need(got==plain);
  }
  auto deny=[&](const Bytes& bad){
    tr::RelaySocket client(connect_to(address));send(client.fd,bad);uint8_t byte;
    const auto n=recv(client.fd,&byte,1,0);need(n==0||(n<0&&errno==ECONNRESET));
    need(exit->take_boring()<0);
    tr::RelaySocket unexpected(accept4(origin.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC));need(unexpected.fd<0&&errno==EAGAIN);
  };
  deny(wire); // replay never goes to boring
  deny(hello("n1.bad.relay.example"));deny(hello("other.relay.example"));
  deny(hello("relay.example.evil"));deny(Bytes{'G','E','T',' ','/'});
  auto changed=wire;changed[11]^=1;deny(changed);
  tr::Digest wrong=key;wrong[0]^=1;tr::SniAuthorization bad(wrong,"relay.example");
  deny(bad.seal(tr::parse(plain),destination,tr::wall_seconds()));
  need(exit->boring_selected==0 && !exit->broken);
  // A slow hello must not serialize admission for another complete hello.
  {
    tr::RelaySocket stalled(connect_to(address)),valid(connect_to(address));send(stalled.fd,Bytes{22});
    auto b=hello("relay.example");send(valid.fd,b);tr::RelaySocket dispatched;
    until([&]{dispatched.fd=exit->take_boring();return dispatched.fd>=0;});
    Bytes got(b.size());need(recv(dispatched.fd,got.data(),got.size(),0)==ssize_t(got.size())&&got==b);
  }
  until([&]{return exit->pending()==0;});
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  std::vector<std::unique_ptr<tr::RelaySocket>> slow;
  for(int i=0;i<16;++i)slow.push_back(std::make_unique<tr::RelaySocket>(connect_to(address)));
  until([&]{return exit->pending()==16;});
  {tr::RelaySocket excess(connect_to(address));uint8_t b;need(recv(excess.fd,&b,1,0)==0);}
  need(exit->dropped>0);
  const auto start=tr::monotonic_ms();exit.reset();need(tr::monotonic_ms()-start<1000);
  std::cout<<"native combo dispatch: relay replay/wrong-key/tamper never downgrade, bounded admission, no HOL, cancelled stop PASS\n";
}
int main(){try{
  const auto boring=hello("relay.example"), relay=hello("n1.invalid.relay.example");
  need(combo::classify(tr::parse(boring),"RELAY.example")==combo::Branch::boring);
  need(combo::classify(tr::parse(relay),"relay.example")==combo::Branch::transparent);
  need(combo::classify(tr::parse(hello("other.relay.example")),"relay.example")==combo::Branch::transparent);
  for(const auto& name:{"relay.example.evil","evilrelay.example","elsewhere.example"})
    rejects([&]{combo::classify(tr::parse(hello(name)),"relay.example");});
  // Incremental peek neither consumes nor duplicates CH/coalesced tail.
  for(const auto& bytes:{boring,relay}) {
    int pair[2];need(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
    tr::RelaySocket a(pair[0]),b(pair[1]);std::atomic<bool> stop{false};
    auto result=std::async(std::launch::async,[&]{return combo::peek(b.fd,"relay.example",tr::monotonic_ms()+1000,stop);});
    need(send(a.fd,bytes.data(),2,MSG_NOSIGNAL)==2);
    need(result.wait_for(std::chrono::milliseconds(30))==std::future_status::timeout);
    for(size_t at=2;at<bytes.size();at+=7){const auto n=std::min(size_t(7),bytes.size()-at);need(send(a.fd,bytes.data()+at,n,MSG_NOSIGNAL)==ssize_t(n));}
    const Bytes tail={23,3,3,0,3,42,43,44};need(send(a.fd,tail.data(),tail.size(),MSG_NOSIGNAL)==ssize_t(tail.size()));
    need(result.get()==combo::classify(tr::parse(bytes),"relay.example"));
    Bytes expected=bytes;expected.insert(expected.end(),tail.begin(),tail.end());Bytes got(expected.size());
    need(recv(b.fd,got.data(),got.size(),0)==ssize_t(got.size())&&got==expected);
  }
  for(const Bytes& bad:{Bytes{'G','E','T',' ','/'},Bytes{22,3,3,255,255},Bytes{22,3,3}}){
    int pair[2];need(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
    tr::RelaySocket a(pair[0]),b(pair[1]);std::atomic<bool> stop{false};
    need(send(a.fd,bad.data(),bad.size(),MSG_NOSIGNAL)==ssize_t(bad.size()));
    rejects([&]{combo::peek(b.fd,"relay.example",tr::monotonic_ms()+40,stop);});
    stop=true;rejects([&]{combo::peek(b.fd,"relay.example",tr::monotonic_ms()+1000,stop);});
  }
  dispatch();
  std::cout<<"native combo classification, fragmented non-consuming peek, coalesced tail, timeout/cancel PASS\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
