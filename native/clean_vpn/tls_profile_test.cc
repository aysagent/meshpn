#include "tls_profile.hpp"
#include <fstream>
#include <iostream>
using namespace cvpn;
int main(int argc,char** argv) {
  try {
    if(argc!=2)return 2;
    profile::json j;std::ifstream(argv[1])>>j; profile::Profile p(j);
    std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_method()),SSL_CTX_free);
    SSL_CTX_set_options(ctx.get(),SSL_OP_NO_TICKET); SSL_CTX_set_session_cache_mode(ctx.get(),SSL_SESS_CACHE_OFF); p.context(ctx.get());
    Bytes first;
    for(int i=0;i<4;i++) {
      std::unique_ptr<SSL,decltype(&SSL_free)> ssl(SSL_new(ctx.get()),SSL_free);
      SSL_set_connect_state(ssl.get()); SSL_set_tlsext_host_name(ssl.get(),"localhost");
      auto wire=p.first_flight(ssl.get());
      auto h=transparent::parse(wire);
      if(i)transparent::require(!std::equal(h.payload.begin()+6,h.payload.begin()+38,first.begin()+6),"random_reused");
      first=h.payload;
      auto bad=p;bad.ciphers[0]=4866;bool rejected=false;
      try {bad.verify(wire);}catch(...){rejected=true;}
      transparent::require(rejected,"mismatch_accepted");
      // Bounds of the independent prewire decoder under corrupt lengths and
      // extension bytes. Dynamic contents may legitimately remain acceptable.
      for(size_t at=0;at<wire.size();at++) {
        auto broken=wire;broken[at]^=0xff;
        try {p.verify(broken);}catch(const std::exception&){}
      }
    }
    std::cout<<"native TLS profile fresh random and prewire mismatch PASS\n";
    return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
