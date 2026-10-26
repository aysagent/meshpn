#pragma once
#ifndef CVPN_TEST_PACKET_FD
#error Test-only certificate compression server fixture
#endif
#include <brotli/encode.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
namespace cvpn::certificate_compression_fixture {
inline int compress(SSL*,CBB* out,const uint8_t* input,size_t length) noexcept {
  try {
    const char* mode=std::getenv("CVPN_TEST_CERT_COMPRESSION");
    std::vector<uint8_t> plain(input,input+length);
    if(!std::strcmp(mode,"wrong-size"))plain.push_back(0);
    size_t size=BrotliEncoderMaxCompressedSize(plain.size());std::vector<uint8_t> wire(size);
    if(!BrotliEncoderCompress(4,22,BROTLI_MODE_GENERIC,plain.size(),plain.data(),&size,wire.data()))return 0;
    wire.resize(size);
    if(!std::strcmp(mode,"truncated"))wire.pop_back();
    if(!std::strcmp(mode,"trailing"))wire.push_back(0);
    if(!std::strcmp(mode,"garbage"))wire.assign(1,0xff);
    return CBB_add_bytes(out,wire.data(),wire.size());
  }catch(...){return 0;}
}
inline void message(int write,int,int type,const void* data,size_t length,SSL*,void*) {
  if(write && type==22 && length && static_cast<const uint8_t*>(data)[0]==25)
    std::fputs("fixture_compressed_certificate_sent\n",stderr);
}
inline bool enable(SSL_CTX* ctx) {
  const char* mode=std::getenv("CVPN_TEST_CERT_COMPRESSION");if(!mode)return true;
  SSL_CTX_set_msg_callback(ctx,message);
  return SSL_CTX_add_cert_compression_alg(ctx,2,compress,nullptr)==1;
}
}
