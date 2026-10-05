#pragma once
#include "protocol.hpp"
#include <set>
#include <string>
namespace cvpn::dns {
inline void need(bool value){if(!value)throw std::runtime_error("dns_wire");}
inline uint16_t u16(const Bytes& b,size_t p){need(p+2<=b.size());return (uint16_t(b[p])<<8)|b[p+1];}
inline void put16(Bytes& b,size_t p,uint16_t n){b.at(p)=n>>8;b.at(p+1)=n;}
struct Name { std::string key; size_t end; bool compressed=false; };
inline Name name(const Bytes& b,size_t start){
  Name result{"",0,false};size_t at=start,size=1;std::set<size_t> visited;
  for(int steps=0;steps<128;steps++){
    need(at<b.size()&&visited.insert(at).second);unsigned n=b[at++];
    if((n&192)==192){need(at<b.size());size_t target=((n&63)<<8)|b[at++];need(target>=12&&target<at-2);if(!result.end)result.end=at;result.compressed=true;at=target;continue;}
    need(n<=63&&at+n<=b.size());if(!n){if(!result.end)result.end=at;return result;}
    size+=n+1;need(size<=255);result.key+=char(n);
    for(unsigned i=0;i<n;i++){auto c=b[at++];result.key+=char(c>='A'&&c<='Z'?c+32:c);}
  }
  throw std::runtime_error("dns_name");
}
struct Message {
  uint16_t id,flags,type,klass,rcode;size_t question_end,udp_size=512;
  Name question;bool edns=false;uint8_t edns_version=0,extended=0;uint16_t edns_flags=0;
  unsigned answers,authority,additional;bool only_opt=true;
};
inline Message parse(const Bytes& b,bool query=false){
  need(b.size()>=12&&b.size()<=65535);Message m{};m.id=u16(b,0);m.flags=u16(b,2);
  need(!(m.flags&0x7840)&&u16(b,4)==1);m.question=name(b,12);m.type=u16(b,m.question.end);m.klass=u16(b,m.question.end+2);m.question_end=m.question.end+4;
  const std::set<unsigned> excluded={0,41,249,250,251,252,253,254,255,65535};need(!excluded.count(m.type)&&m.klass==1);
  m.answers=u16(b,6);m.authority=u16(b,8);m.additional=u16(b,10);need(m.answers+m.authority+m.additional<=128);
  size_t at=m.question_end;
  for(int section=0;section<3;section++)for(unsigned i=0;i<u16(b,6+2*section);i++){
    auto rr=name(b,at);at=rr.end;need(at+10<=b.size());auto type=u16(b,at),klass=u16(b,at+2),len=u16(b,at+8);size_t ttl=at+4;at+=10;need(at+len<=b.size());
    if(type==1)need(len==4);
    if(type==28)need(len==16);
    if(type==41){
      need(section==2&&!m.edns&&rr.key.empty()&&!rr.compressed);m.edns=true;m.extended=b[ttl];m.edns_version=b[ttl+1];m.edns_flags=u16(b,ttl+2);m.udp_size=std::min(4096,std::max(512,int(klass)));
      size_t opt=at;while(opt<at+len){need(opt+4<=at+len);opt+=4+u16(b,opt+2);need(opt<=at+len);}
    }else m.only_opt=false;
    at+=len;
  }
  need(at==b.size());m.rcode=(m.flags&15)|(m.extended<<4);
  if(query)need(!(m.flags&~0x0130)&&!m.answers&&!m.authority&&m.only_opt&&!m.question.compressed&&(!m.edns||!m.extended));
  return m;
}
inline Message response(const Bytes& answer,const Bytes& query){
  auto q=parse(query,true),r=parse(answer);need((r.flags&0x8000)&&r.id==q.id&&r.question.key==q.question.key&&r.type==q.type&&r.klass==q.klass&&(!r.edns||(q.edns&&!r.edns_version)));return r;
}
inline Bytes failure(const Bytes& query,unsigned rcode=2,bool truncated=false){
  auto q=parse(query,true);need(rcode<=4095&&(rcode<16||q.edns));Bytes b(query.begin(),query.begin()+q.question_end);
  put16(b,2,0x8080|(q.flags&0x0110)|(rcode&15)|(truncated?0x0200:0));std::fill(b.begin()+6,b.begin()+12,0);
  if(q.edns){put16(b,10,1);size_t p=b.size();b.resize(p+11);put16(b,p+1,41);put16(b,p+3,q.udp_size);b[p+5]=rcode>>4;put16(b,p+7,q.edns_flags&0x8000);}
  return b;
}
}
