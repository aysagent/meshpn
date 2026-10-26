#pragma once
#include "http2_alps_adapter.h"
#include <openssl/ssl.h>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <set>

namespace cvpn::http2_alps {
inline void require(bool ok) { if(!ok)throw std::runtime_error("h2_alps_invalid"); }
inline std::vector<nghttp2_settings_entry> server_settings() {
  return {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,1},
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,1048576},
    {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,8192}};
}
inline std::vector<uint8_t> encode(const std::vector<nghttp2_settings_entry>& settings) {
  require(settings.size()<=6);
  std::vector<uint8_t> out={0,0,uint8_t(settings.size()*6),NGHTTP2_SETTINGS,0,0,0,0,0};
  for(const auto& s:settings) {
    out.push_back(s.settings_id>>8);out.push_back(s.settings_id);
    for(int shift=24;shift>=0;shift-=8)out.push_back(s.value>>shift);
  }
  return out;
}
// Deliberately bounded subset: zero bytes, or one non-ACK SETTINGS frame,
// at most six distinct standard IDs. No ACCEPT_CH, unknown frames or replay.
inline std::vector<nghttp2_settings_entry> parse(const uint8_t* p,size_t n) {
  if(!n)return {};
  require(n>=9 && n<=45 && p[0]==0 && p[1]==0 && p[2]==n-9 && (n-9)%6==0 &&
    p[3]==NGHTTP2_SETTINGS && p[4]==0 && p[5]==0 && p[6]==0 && p[7]==0 && p[8]==0);
  std::vector<nghttp2_settings_entry> out;std::set<int> seen;
  for(size_t i=9;i<n;i+=6) {
    int id=(int(p[i])<<8)|p[i+1];
    uint32_t value=(uint32_t(p[i+2])<<24)|(uint32_t(p[i+3])<<16)|(uint32_t(p[i+4])<<8)|p[i+5];
    require(seen.insert(id).second);
    switch(id) {
      case 1: require(value<=65536);break;
      case 2: require(value==0);break;
      case 3: break;
      case 4: require(value<=0x7fffffff);break;
      case 5: require(value>=16384 && value<=16777215);break;
      case 6: break;
      default: require(false);
    }
    out.push_back({id,value});
  }
  return out;
}
inline void server_connection(SSL* ssl) {
  const auto bytes=encode(server_settings());
  SSL_set_alps_use_new_codepoint(ssl,1);
  require(SSL_add_application_settings(ssl,reinterpret_cast<const uint8_t*>("h2"),2,bytes.data(),bytes.size())==1);
}
} // namespace cvpn::http2_alps
