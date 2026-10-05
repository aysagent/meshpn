#include "dns_wire.hpp"
#include <iostream>
using namespace cvpn;
int main(){
  Bytes q={0x12,0x34,1,0,0,1,0,0,0,0,0,0,4,'T','e','s','t',0,0,1,0,1};
  auto parsed=dns::parse(q,true);dns::need(parsed.type==1&&parsed.question_end==q.size());
  auto answer=dns::failure(q,3);dns::need(dns::response(answer,q).rcode==3);
  auto rejected=[](auto action){bool failed=false;try{action();}catch(...){failed=true;}dns::need(failed);};
  auto wrong=answer;wrong[1]^=1;rejected([&]{dns::response(wrong,q);});
  wrong=answer;wrong[13]='x';rejected([&]{dns::response(wrong,q);});
  for(size_t i=0;i<q.size();i++)rejected([&]{dns::parse(Bytes(q.begin(),q.begin()+i),true);});
  auto opt=q;dns::put16(opt,10,1);opt.insert(opt.end(),{0,0,41,0x10,0,0,0,0x80,0,0,0});
  dns::need(dns::parse(opt,true).udp_size==4096);auto badvers=opt;badvers[badvers.size()-5]=1;
  dns::need(dns::parse(badvers,true).edns_version==1);dns::need(dns::parse(dns::failure(badvers,16)).rcode==16);
  auto tc=dns::failure(opt,0,true);dns::need(dns::response(tc,opt).flags&0x0200);
  uint32_t rng=7;
  for(int i=0;i<30000;i++){
    auto b=opt;for(int k=0;k<3;k++){rng=rng*1664525+1013904223;b[rng%b.size()]=rng>>24;}
    try{dns::parse(b,true);dns::parse(b);}catch(const std::runtime_error&){}
  }
  std::cout<<"DNS envelope, EDNS, truncation, 30000 malformed mutations PASS\n";
}
