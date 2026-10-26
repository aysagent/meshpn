#pragma once
#ifndef CVPN_TEST_PACKET_FD
#error Test-only signature fixture
#endif
#include <openssl/ssl.h>
#include <openssl/mldsa.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
namespace cvpn::signature_fixture {
inline ssl_private_key_result_t corrupt(SSL*,uint8_t* out,size_t* length,size_t max,
    uint16_t algorithm,const uint8_t*,size_t) {
  size_t size=algorithm==SSL_SIGN_ML_DSA_44?MLDSA44_SIGNATURE_BYTES:
    algorithm==SSL_SIGN_ML_DSA_65?MLDSA65_SIGNATURE_BYTES:
    algorithm==SSL_SIGN_ML_DSA_87?MLDSA87_SIGNATURE_BYTES:0;
  if(!size||size>max)return ssl_private_key_failure;
  std::memset(out,0,size);*length=size;return ssl_private_key_success;
}
inline void message(int write,int,int type,const void* data,size_t length,SSL*,void*) {
  const auto* b=static_cast<const uint8_t*>(data);
  if(write&&type==22&&length>=6&&b[0]==15)
    std::fprintf(stderr,"fixture_certificate_verify_sent=%u\n",unsigned(b[4])*256+b[5]);
}
inline bool enable(SSL_CTX* ctx) {
  const char* mode=std::getenv("CVPN_TEST_SIGNATURE");if(!mode)return true;
  if(std::strcmp(mode,"observe")&&std::strcmp(mode,"corrupt"))return false;
  // One message callback per context. Combining with compression observation
  // would hide evidence, so refuse this test setup explicitly.
  if(std::getenv("CVPN_TEST_CERT_COMPRESSION"))return false;
  SSL_CTX_set_msg_callback(ctx,message);
  if(!std::strcmp(mode,"corrupt")) {
    static const SSL_PRIVATE_KEY_METHOD method={corrupt,nullptr,nullptr};
    SSL_CTX_set_private_key_method(ctx,&method);
  }
  return true;
}
inline void accepted(SSL* ssl) {
  if(std::getenv("CVPN_TEST_SIGNATURE"))
    std::fprintf(stderr,"fixture_peer_signature_verified=%u\n",SSL_get_peer_signature_algorithm(ssl));
}
}
