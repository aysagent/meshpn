#pragma once
#ifndef CVPN_TEST_PACKET_FD
#error Test-only decrypted HTTP2 wire observer
#endif
#include "http2_alps.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <array>
#include <unistd.h>
#include <cerrno>
namespace cvpn::http2_alps_fixture {
inline void record(const char* kind,bool client,const uint8_t* p,size_t n) {
  if(!std::getenv("CVPN_TEST_H2_OBSERVER"))return;
  // Only bounded ALPS SETTINGS / wire SETTINGS / WINDOW_UPDATE, never headers,
  // exporter tokens, application payload, key material or arbitrary debug data.
  if(n>96)return;
  std::string hex;for(size_t i=0;i<n;i++){hex+="0123456789abcdef"[p[i]>>4];hex+="0123456789abcdef"[p[i]&15];}
  // Several fixture processes share the observer pipe. Emit one bounded write
  // so stdio fragments cannot interleave across clients.
  const auto line=std::string("fixture_h2 {\"kind\":\"")+kind+"\",\"receiver\":\""+
    (client?"client":"exit")+"\",\"hex\":\""+hex+"\"}\n";
  ssize_t sent;do{sent=write(STDERR_FILENO,line.data(),line.size());}while(sent<0&&errno==EINTR);
  http2_alps::require(sent==ssize_t(line.size()));
}
inline void server_connection(SSL* ssl) {
  auto bytes=http2_alps::encode(http2_alps::server_settings());
  if(const char* mode=std::getenv("CVPN_TEST_ALPS")) {
    if(!std::strcmp(mode,"ack"))bytes[4]=1;
    if(!std::strcmp(mode,"stream"))bytes[8]=1;
    if(!std::strcmp(mode,"truncated"))bytes.pop_back();
    if(!std::strcmp(mode,"extra-frame"))bytes.insert(bytes.end(),9,0);
    if(!std::strcmp(mode,"window"))bytes[17]=0x80;
    if(!std::strcmp(mode,"unknown"))bytes[10]=8;
    if(!std::strcmp(mode,"duplicate")){bytes[21]=0;bytes[22]=3;}
  }
  SSL_set_alps_use_new_codepoint(ssl,1);
  http2_alps::require(SSL_add_application_settings(ssl,reinterpret_cast<const uint8_t*>("h2"),2,bytes.data(),bytes.size())==1);
}
inline bool client_connection(SSL* ssl) {
  if(!std::getenv("CVPN_TEST_ALPS_CLIENT"))return false;
  const auto bytes=http2_alps::encode(http2_alps::server_settings());
  http2_alps::require(SSL_add_application_settings(ssl,reinterpret_cast<const uint8_t*>("h2"),2,bytes.data(),bytes.size())==1);
  return true;
}
struct Observer {
  bool client,done=false;size_t magic,used=0,wanted=9,frames=0;std::array<uint8_t,105> buffer{};
  explicit Observer(bool c):client(c),magic(c?0:24){}
  void feed(const uint8_t* p,size_t n) {
    if(!std::getenv("CVPN_TEST_H2_OBSERVER")||done)return;
    for(size_t i=0;i<n && !done;i++) {
      if(magic){magic--;continue;}
      buffer[used++]=p[i];if(used!=wanted)continue;
      if(wanted==9) {
        size_t length=(size_t(buffer[0])<<16)|(size_t(buffer[1])<<8)|buffer[2];
        // Stop at the first non-settings/window frame (usually HEADERS).
        if((buffer[3]!=4 && buffer[3]!=8)||length>96||++frames>8){done=true;break;}
        wanted+=length;if(length)continue;
      }
      record("wire",client,buffer.data(),used);used=0;wanted=9;
    }
  }
};
}
