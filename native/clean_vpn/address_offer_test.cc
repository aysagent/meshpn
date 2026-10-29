#include "address_offer.hpp"
#include <iostream>
#include <vector>
using namespace cvpn::address_offer;
template<class F>void rejected(F f){bool refused=false;try{f();}catch(const std::exception&){refused=true;}require(refused,"expected_rejection");}
int main(){try{
 Key key{};Binding exporter{};for(size_t i=0;i<32;++i){key[i]=uint8_t(i);exporter[i]=uint8_t(i+32);}
 const Address ip{10,99,0,37};
 // Independent Python stdlib hmac/sha256 vectors, not encode/verify roundtrip only.
 const std::string discovery="v1:10.99.0.37:a79c6f69a4b35b5ed6b4743157083276f11a95e5aceb2b7eece5e3421a814b4c";
 const std::string session="v1:10.99.0.37:4067ac9442051447cf05272961820e34765450f3e80c655b8a08481fe9c4658e";
 require(encode(ip,key,exporter,Purpose::Discovery)==discovery,"discovery_vector");
 require(encode(ip,key,exporter,Purpose::Session)==session,"session_vector");
 require(verify(discovery,key,exporter,Purpose::Discovery)==ip,"discovery_verify");
 require(verify(session,key,exporter,Purpose::Session)==ip,"session_verify");
 rejected([&]{verify(discovery,key,exporter,Purpose::Session);});
 rejected([&]{verify(session,key,exporter,Purpose::Discovery);});
 for(size_t i=0;i<32;++i){auto wrong_key=key;wrong_key[i]^=1;rejected([&]{verify(session,wrong_key,exporter,Purpose::Session);});
  auto wrong_binding=exporter;wrong_binding[i]^=1;rejected([&]{verify(session,key,wrong_binding,Purpose::Session);});}
 for(size_t i=0;i<session.size();++i){auto mutated=session;mutated[i]^=1;rejected([&]{verify(mutated,key,exporter,Purpose::Session);});}
 for(size_t n=0;n<session.size();++n)rejected([&]{verify(std::string_view(session).substr(0,n),key,exporter,Purpose::Session);});
 for(const std::string& suffix:std::vector<std::string>{" ","\n",":","0",std::string(10000,'a')})rejected([&]{verify(session+suffix,key,exporter,Purpose::Session);});
 for(const std::string bad:{"10.99.0.0","10.99.0.1","10.99.0.255","10.99.0.256","10.99.0.999","10.99.0.02","10.99.0.+2","10.99.0.-2","10.99.1.2","127.0.0.1","010.99.0.2","10.99.0.2 ","10.99.0.2\n",""})
  rejected([&]{parse_address(bad);});
 for(unsigned last=2;last<=254;++last){Address address{10,99,0,uint8_t(last)};for(auto purpose:{Purpose::Discovery,Purpose::Session})
  require(verify(encode(address,key,exporter,purpose),key,exporter,purpose)==address,"allowed_pool_roundtrip");}
 rejected([&]{encode(Address{10,99,0,1},key,exporter,Purpose::Session);});
 rejected([&]{encode(ip,key,exporter,Purpose(3));});
 std::cout<<"native address offer PASS: independent vectors, binding/purpose/key/address mutations, canonical pool\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}}
