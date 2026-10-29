#include "profile_capture.h"
#include "profile_client.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
using Bytes=std::vector<uint8_t>;
static meshpn_hello_capture_t feed(const Bytes&wire,size_t chunk){
 meshpn_hello_capture_t s{};int r=0;
 for(size_t i=0;i<wire.size()&&r==0;i+=chunk)r=meshpn_hello_capture_feed(&s,wire.data()+i,std::min(chunk,wire.size()-i));
 assert(r==1);assert(meshpn_hello_capture_feed(&s,nullptr,0)==1);return s;
}
int main(int argc,char**argv){
 assert(argc==3);std::ifstream f(argv[1],std::ios::binary);Bytes wire((std::istreambuf_iterator<char>(f)),{});
 auto s=feed(wire,wire.size());
 for(size_t chunk: {size_t(1),size_t(2),size_t(5),size_t(127),size_t(512)}){
  auto split=feed(wire,chunk);assert(split.length==s.length&&!memcmp(split.hello,s.hello,s.length));
 }
 // Reassemble a ClientHello split across TLS records, including its length header.
 Bytes records;for(size_t i=0;i<s.length;){size_t n=std::min(i?size_t(1000):size_t(2),s.length-i);
  records.insert(records.end(),{22,3,1,uint8_t(n>>8),uint8_t(n)});records.insert(records.end(),s.hello+i,s.hello+i+n);i+=n;}
 auto split=feed(records,1);assert(split.length==s.length&&!memcmp(split.hello,s.hello,s.length));
 for(size_t i=0;i<wire.size();i++){meshpn_hello_capture_t t{};assert(meshpn_hello_capture_feed(&t,wire.data(),i)==0);}
 for(auto bad:std::vector<Bytes>{{23,3,1,0,4,1,0,0,0},{22,3,1,0,0},{22,3,1,0x40,1},{22,3,1,0,4,2,0,0,40},{22,3,1,0,4,1,0xff,0xff,0xff},{22,3,1,0,4,1,0,0,0}}){
  meshpn_hello_capture_t t{};assert(meshpn_hello_capture_feed(&t,bad.data(),bad.size())==-1);assert(meshpn_hello_capture_feed(&t,wire.data(),wire.size())==-1);
 }
 Bytes tooMany;for(unsigned i=0;i<17;i++)tooMany.insert(tooMany.end(),{22,3,1,0,1,i==0?uint8_t(1):i==2?uint8_t(0x10):uint8_t(0)});
 {meshpn_hello_capture_t t{};assert(meshpn_hello_capture_feed(&t,tooMany.data(),tooMany.size())==-1);}
 meshpn_tls_profile_t p{},q{};const char*reason=nullptr;
 assert(meshpn_profile_from_hello(s.hello,s.length,argv[2],"Browser",&p,&reason));assert(!reason);
 assert(meshpn_profile_from_hello(s.hello,s.length,argv[2],"Renamed",&q,&reason));assert(!strcmp(p.id,q.id));
 assert(!meshpn_profile_from_hello(s.hello,s.length,"wrong.local","Browser",&q,&reason));
 assert(!meshpn_profile_from_hello(s.hello,s.length,argv[2],"bad\nname",&q,&reason));
 for(size_t i=0;i<s.length;i++)assert(!meshpn_profile_from_hello(s.hello,i,argv[2],"Browser",&q,&reason));
 meshvpn_profile_check_t check{};assert(meshpn_profile_preview(&p,&check));
 fprintf(stderr,"Captured %s JA3=%s JA4=%s; fragmented/hostile wire checks passed\n",p.id,p.ja3,p.ja4);
 bssl::UniquePtr<SSL_CTX>ctx(meshvpn_profiled_context(true,&p));assert(ctx);bssl::UniquePtr<SSL>ssl(SSL_new(ctx.get()));assert(ssl);
 assert(meshvpn_profiled_connection(ssl.get(),&p));assert(SSL_set_tlsext_host_name(ssl.get(),"exit.meshpn.test"));
 BIO*in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());assert(in&&out);SSL_set_bio(ssl.get(),in,out);SSL_set_connect_state(ssl.get());
 meshvpn_profile_gate_state gate;meshvpn_profiled_gate_install(ssl.get(),&gate,&p);SSL_do_handshake(ssl.get());assert(gate.accepted);
 char*b=nullptr;long n=BIO_get_mem_data(out,&b);assert(n>0);assert(fwrite(b,1,n,stdout)==size_t(n));
}
