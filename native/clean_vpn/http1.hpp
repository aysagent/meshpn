#pragma once
// Direct TLS endpoint, one streaming POST and one streaming response per
// connection. No proxy, upgrades, pipelining, compression or ambiguous lengths.
#include "protocol.hpp"
#include <array>
#include <map>
#include <string>
#include <cstdio>

namespace cvpn::http1 {
inline void require(bool ok,const char* code){if(!ok)throw std::runtime_error(code);}
inline std::string lower(std::string s){for(char& c:s)if(c>='A'&&c<='Z')c+=32;return s;}
inline bool token_char(unsigned char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||std::strchr("!#$%&'*+-.^_`|~",c);}
using Headers=std::map<std::string,std::string>;
class Parser {
 enum class State { headers,size,body,cr,lf,trailers,done } state_=State::headers;
 std::string line_;Headers headers_;bool first_=true,client_;size_t total_=0,remaining_=0,trailer_bytes_=0;
 void header_line(){
  if(first_){first_=false;
   if(client_){require(line_=="HTTP/1.1 200 OK"||line_=="HTTP/1.1 409 Conflict","vpn_response_rejected");headers_[":status"]=line_.substr(9,3);}
   else{require(line_=="POST /clean-vpn HTTP/1.1","request_invalid");headers_[":method"]="POST";headers_[":path"]="/clean-vpn";headers_[":scheme"]="https";}
   return;
  }
  const auto colon=line_.find(':');require(colon!=std::string::npos&&colon>0,"h1_headers_invalid");
  auto name=lower(line_.substr(0,colon));for(unsigned char c:name)require(c&&token_char(c),"h1_headers_invalid");
  auto value=line_.substr(colon+1);while(!value.empty()&&(value.front()==' '||value.front()=='\t'))value.erase(0,1);
  while(!value.empty()&&(value.back()==' '||value.back()=='\t'))value.pop_back();
  for(unsigned char c:value)require(c=='\t'||(c>=32&&c<=126),"h1_headers_invalid");
  require(headers_.size()<32,"headers_limit");require(headers_.emplace(name,value).second,"duplicate_header");
 }
 void validate(){
  require(!headers_.count("content-length")&&lower(headers_["transfer-encoding"])=="chunked","h1_framing_invalid");
  require(!headers_.count("upgrade")&&!headers_.count("expect")&&!headers_.count("trailer")&&!headers_.count("content-encoding"),"h1_framing_invalid");
  require(!headers_.count("connection")||lower(headers_["connection"])=="keep-alive","h1_framing_invalid");
  require(headers_["x-clean-vpn-protocol"]=="h1-v1"&&headers_["content-type"]=="application/octet-stream","h1_protocol_invalid");
  if(!client_){require(!headers_["host"].empty()&&headers_["host"].size()<=259,"h1_host_invalid");for(unsigned char c:headers_["host"])require((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c==':',"h1_host_invalid");}
 }
public:
 explicit Parser(bool client):client_(client){}
 template<class H,class B,class E> void feed(const uint8_t* p,size_t n,H on_headers,B on_body,E on_end){
  while(n){
   require(state_!=State::done,"h1_extra_message");
   if(state_==State::body){const size_t take=std::min(n,remaining_);on_body(p,take);p+=take;n-=take;remaining_-=take;if(!remaining_)state_=State::cr;continue;}
   const char c=char(*p++);--n;
   if(state_==State::cr){require(c=='\r',"h1_chunk_invalid");state_=State::lf;continue;}
   if(state_==State::lf){require(c=='\n',"h1_chunk_invalid");state_=State::size;continue;}
   line_+=c;
   if(state_==State::headers){require(++total_<=8192,"headers_limit");}
   else if(state_==State::trailers)require(++trailer_bytes_<=8192,"headers_limit");
   else require(line_.size()<=256,"h1_chunk_invalid");
   if(c!='\n')continue;
   require(line_.size()>=2&&line_[line_.size()-2]=='\r',"h1_headers_invalid");line_.resize(line_.size()-2);
   if(state_==State::headers){
    if(line_.empty()){require(!first_,"h1_headers_invalid");validate();on_headers(headers_);headers_.clear();state_=State::size;}
    else header_line();
   }else if(state_==State::size){
    const auto semi=line_.find(';');const auto digits=line_.substr(0,semi);require(!digits.empty()&&digits.size()<=8,"h1_chunk_invalid");size_t size=0;
    for(char h:digits){const int v=h>='0'&&h<='9'?h-'0':h>='a'&&h<='f'?h-'a'+10:h>='A'&&h<='F'?h-'A'+10:-1;require(v>=0,"h1_chunk_invalid");size=size*16+v;require(size<=queue_limit,"h1_chunk_limit");}
    if(semi!=std::string::npos)for(size_t i=semi+1;i<line_.size();i++)require(line_[i]=='\t'||(line_[i]>=32&&line_[i]<=126),"h1_chunk_invalid");
    remaining_=size;state_=size?State::body:State::trailers;
   }else{
    // Trailer fields never alter the authenticated header section. This
    // application profile deliberately allows only an empty trailer section.
    require(line_.empty(),"h1_trailers_forbidden");state_=State::done;on_end();
   }
   line_.clear();
  }
 }
};
inline Bytes chunk(const uint8_t* p,size_t n){require(n>0&&n<=queue_limit,"h1_chunk_limit");char size[32];const int l=std::snprintf(size,sizeof(size),"%zx\r\n",n);Bytes b(size,size+l);b.insert(b.end(),p,p+n);b.push_back('\r');b.push_back('\n');return b;}
inline Bytes control(bool pong,const std::array<uint8_t,8>& nonce){Bytes b(12);b[3]=pong?1:0;std::copy(nonce.begin(),nonce.end(),b.begin()+4);return chunk(b.data(),b.size());}
// h1-v1 retains IPv4 length framing, reserving lengths 0/1 for ping/pong
// followed by an eight-byte nonce. Record boundaries need not be chunk boundaries.
class Records {
 Bytes bytes_;size_t need_=4;uint32_t length_=0;
public:
 bool idle()const{return bytes_.empty();}
 template<class P,class C> void feed(const uint8_t* p,size_t n,P packet,C control){
  while(n){const size_t take=std::min(n,need_-bytes_.size());bytes_.insert(bytes_.end(),p,p+take);p+=take;n-=take;
   if(bytes_.size()!=need_)continue;
   if(need_==4){length_=(uint32_t(bytes_[0])<<24)|(uint32_t(bytes_[1])<<16)|(uint32_t(bytes_[2])<<8)|bytes_[3];require(length_<=1||(length_>=20&&length_<=max_packet),"invalid_frame_length");need_=4+(length_<=1?8:length_);}
   else{if(length_<=1){std::array<uint8_t,8> nonce{};std::copy(bytes_.begin()+4,bytes_.end(),nonce.begin());control(length_==1,nonce);}
    else{require(ipv4(bytes_.data()+4,length_),"invalid_ipv4");packet(Bytes(bytes_.begin()+4,bytes_.end()));}bytes_.clear();need_=4;}
  }
 }
};
}
