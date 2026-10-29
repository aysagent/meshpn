#pragma once
// Wire primitive only. The engine/owner must still enforce the lifecycle gates
// documented in clean-vpn-native-address-assignment.md before enabling it.
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

namespace cvpn::address_offer {
using Key=std::array<uint8_t,32>;
using Binding=std::array<uint8_t,32>;
using Address=std::array<uint8_t,4>;
enum class Purpose : uint8_t { Discovery=1, Session=2 };
inline void require(bool ok,const char* code){if(!ok)throw std::runtime_error(code);}
inline void validate(Address ip){require(ip[0]==10&&ip[1]==99&&ip[2]==0&&ip[3]>=2&&ip[3]<=254,"address_offer_ipv4");}
inline std::string address_text(Address ip){validate(ip);return "10.99.0."+std::to_string(ip[3]);}
inline Address parse_address(std::string_view text){
  constexpr std::string_view prefix="10.99.0.";
  require(text.size()>=prefix.size()+1&&text.size()<=prefix.size()+3&&text.substr(0,prefix.size())==prefix,"address_offer_ipv4");
  const auto suffix=text.substr(prefix.size());require(suffix[0]!='0',"address_offer_ipv4");
  unsigned last=0;for(char c:suffix){require(c>='0'&&c<='9',"address_offer_ipv4");last=last*10+unsigned(c-'0');}
  require(last>=2&&last<=254,"address_offer_ipv4");return {10,99,0,uint8_t(last)};
}
inline std::array<uint8_t,32> proof(Address ip,const Key& key,const Binding& exporter,Purpose purpose){
  validate(ip);require(purpose==Purpose::Discovery||purpose==Purpose::Session,"address_offer_purpose");
  constexpr char domain[]="clean-vpn-address-offer-v1";
  // Include the NUL delimiter, then fixed-width purpose/exporter/address.
  std::array<uint8_t,sizeof(domain)+1+32+4> message{};
  std::memcpy(message.data(),domain,sizeof(domain));message[sizeof(domain)]=uint8_t(purpose);
  std::memcpy(message.data()+sizeof(domain)+1,exporter.data(),exporter.size());
  std::memcpy(message.data()+sizeof(domain)+1+exporter.size(),ip.data(),ip.size());
  std::array<uint8_t,32> mac{};unsigned size=0;
  require(HMAC(EVP_sha256(),key.data(),key.size(),message.data(),message.size(),mac.data(),&size)&&size==mac.size(),"address_offer_hmac");return mac;
}
inline std::string encode(Address authenticated_peer,const Key& key,const Binding& exporter,Purpose purpose){
  auto mac=proof(authenticated_peer,key,exporter,purpose);constexpr char digits[]="0123456789abcdef";
  std::string result="v1:"+address_text(authenticated_peer)+":";result.reserve(result.size()+64);
  for(auto b:mac){result+=digits[b>>4];result+=digits[b&15];}OPENSSL_cleanse(mac.data(),mac.size());return result;
}
inline Address verify(std::string_view value,const Key& key,const Binding& exporter,Purpose purpose){
  require(value.size()>=77&&value.size()<=79&&value.substr(0,3)=="v1:","address_offer_format");
  const auto colon=value.find(':',3);require(colon!=std::string_view::npos&&value.size()-colon-1==64,"address_offer_format");
  const auto ip=parse_address(value.substr(3,colon-3));
  std::array<uint8_t,32> provided{};
  const auto nibble=[](char c)->uint8_t{require((c>='0'&&c<='9')||(c>='a'&&c<='f'),"address_offer_format");return uint8_t(c<='9'?c-'0':c-'a'+10);};
  for(size_t i=0;i<provided.size();++i)provided[i]=uint8_t((nibble(value[colon+1+2*i])<<4)|nibble(value[colon+2+2*i]));
  auto expected=proof(ip,key,exporter,purpose);const bool equal=CRYPTO_memcmp(expected.data(),provided.data(),expected.size())==0;
  OPENSSL_cleanse(expected.data(),expected.size());OPENSSL_cleanse(provided.data(),provided.size());
  require(equal,"address_offer_auth");return ip;
}
} // namespace cvpn::address_offer
