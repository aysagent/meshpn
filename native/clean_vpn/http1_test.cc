#include "http1.hpp"
#include <iostream>
using namespace cvpn;
static void check(bool b){if(!b)throw std::runtime_error("test assertion");}
static Bytes packet(size_t n){Bytes p(n);p[0]=0x45;p[2]=n>>8;p[3]=n;p[8]=64;p[9]=17;uint32_t s=0;for(size_t i=0;i<20;i+=2)s+=(uint16_t(p[i])<<8)|p[i+1];while(s>>16)s=(s&65535)+(s>>16);p[10]=(~s)>>8;p[11]=~s;return p;}
static std::string header(bool response=false){return std::string(response?"HTTP/1.1 200 OK\r\n":"POST /clean-vpn HTTP/1.1\r\nHost: vpn.test\r\n")+"Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Clean-Vpn-Protocol: h1-v1\r\n\r\n";}
static void rejected(const std::string& input){bool failed=false;try{http1::Parser p(false);p.feed(reinterpret_cast<const uint8_t*>(input.data()),input.size(),[](auto&){},[](auto*,size_t){},[](){});}catch(...){failed=true;}check(failed);}
int main(){
 for(bool response:{false,true})for(size_t size:{20,1400,65535})for(size_t split:{1,2,13,16384,65536}){
  auto p=packet(size),f=frame(p.data(),p.size());std::string h=header(response);Bytes wire(h.begin(),h.end());
  // Packet framing can be split independently of HTTP chunks and TLS records.
  for(size_t at=0;at<f.size();){auto n=std::min<size_t>(17,f.size()-at);auto c=http1::chunk(f.data()+at,n);wire.insert(wire.end(),c.begin(),c.end());at+=n;}
  std::array<uint8_t,8> nonce{1,2,3,4,5,6,7,8};for(bool pong:{false,true}){auto c=http1::control(pong,nonce);wire.insert(wire.end(),c.begin(),c.end());}
  const std::string end="0\r\n\r\n";wire.insert(wire.end(),end.begin(),end.end());
  http1::Parser parser(response);http1::Records records;unsigned heads=0,packets=0,controls=0,ends=0;
  for(size_t at=0;at<wire.size();){auto n=std::min(split,wire.size()-at);parser.feed(wire.data()+at,n,[&](auto& fields){check(fields.at("x-clean-vpn-protocol")=="h1-v1");heads++;},[&](auto* b,size_t len){check(heads==1);records.feed(b,len,[&](Bytes got){check(got==p);packets++;},[&](bool pong,auto& v){check(v==nonce&&pong==(controls==1));controls++;});},[&](){check(records.idle());ends++;});at+=n;}
  check(heads==1&&packets==1&&controls==2&&ends==1);
 }
 for(const std::string field:{"Content-Length: 0","Transfer-Encoding: chunked","transfer-encoding: identity"," Transfer-Encoding: chunked","Host : vpn.test","Upgrade: websocket","Expect: 100-continue","Trailer: Authorization","Content-Encoding: gzip","Connection: close"}){
  auto h=header();h.insert(h.size()-2,field+"\r\n");rejected(h);
 }
 for(const std::string body:{"+a\r\n","100001\r\n","FFFFFFFFFFFFFFFFFFFFFFFF\r\n","1\nx\r\n","1\r\nx\n","0\r\nAuthorization: x\r\n\r\n","0\r\n\r\nPOST /clean-vpn HTTP/1.1\r\n"})rejected(header()+body);
 rejected("POST /clean-vpn HTTP/1.1\r\nX: "+std::string(8192,'a'));
 auto bad=header();bad.replace(0,4,"GET");rejected(bad);
 for(uint32_t size:{2U,19U,65536U,0xffffffffU}){uint8_t b[]={uint8_t(size>>24),uint8_t(size>>16),uint8_t(size>>8),uint8_t(size)};bool failed=false;try{http1::Records r;r.feed(b,4,[](Bytes){},[](bool,auto&){});}catch(...){failed=true;}check(failed);}
 // Bounded, ignored chunk extensions cannot inject header fields.
 http1::Parser parser(false);auto text=header()+"1;ignored=value\r\nx\r\n0\r\n\r\n";size_t count=0;parser.feed(reinterpret_cast<const uint8_t*>(text.data()),text.size(),[](auto&){},[&](auto*,size_t n){count+=n;},[](){});check(count==1);
 std::cout<<"HTTP/1.1 parser, fragmentation, framing and rejection PASS\n";
}
