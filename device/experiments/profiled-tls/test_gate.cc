#include "meshvpn_profiled_tls.h"
#include "cert_decode.h"
#include <brotli/encode.h>
#include <openssl/pool.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <fstream>
#include <iterator>
int main(int argc,char**argv){
 SSL_CTX*ctx=SSL_CTX_new(TLS_client_method());assert(ctx);
 SSL*s=SSL_new(ctx);assert(s);
 const uint16_t duplicates[]={5,5},unknown[]={0x1234};
 assert(!SSL_set_meshpn_extension_order(s,duplicates,2));
 assert(!SSL_set_meshpn_extension_order(s,unknown,0));
 assert(SSL_set_meshpn_extension_order(s,unknown,1));
 BIO*in=BIO_new(BIO_s_mem()),*wire=BIO_new(BIO_s_mem());assert(in&&wire);
 SSL_set_bio(s,in,wire);SSL_set_connect_state(s);
 int handshake=SSL_do_handshake(s);
 assert(handshake!=1&&SSL_get_error(s,handshake)!=SSL_ERROR_WANT_READ&&BIO_pending(wire)==0);
 SSL_free(s);SSL_CTX_free(ctx);
 assert(argc==2);std::ifstream f(argv[1],std::ios::binary);
 std::vector<uint8_t> record((std::istreambuf_iterator<char>(f)),{});
 assert(record.size()>9&&record[0]==22);
 size_t length=size_t(record[6])*65536+size_t(record[7])*256+record[8]+4;
 assert(length+5<=record.size());auto*hello=record.data()+5;
 meshvpn_profile_check_t out;
 assert(meshvpn_profiled_tls_check(hello,length,&out));
 assert(!strcmp(out.ja3,"ed63604b6e93c62437468be3f6b387c3"));
 assert(!strcmp(out.ja4,"t13d1517h2_8daaf6152771_cb7bf5808d99"));
 for(size_t n=0;n<length;n++)assert(!meshvpn_profiled_tls_check(hello,n,&out));
 assert(!meshvpn_profiled_tls_check(nullptr,length,&out));
 assert(!meshvpn_profiled_tls_check(hello,length,nullptr));
 // Random corruptions are allowed to preserve JA when only random/key bytes
 // change, but must never read beyond the bounded input (ASan/UBSan).
 uint32_t state=123456;std::vector<uint8_t> copy(hello,hello+length);
 for(size_t i=0;i<50000;i++){
  state=state*1664525+1013904223;size_t pos=state%length;uint8_t old=copy[pos];
  copy[pos]^=uint8_t((state>>16)|1);meshvpn_profiled_tls_check(copy.data(),copy.size(),&out);copy[pos]=old;
 }
 const uint8_t input[]="certificate compression round trip fixture";
 std::vector<uint8_t> compressed(BrotliEncoderMaxCompressedSize(sizeof(input)));size_t size=compressed.size();
 assert(BrotliEncoderCompress(5,BROTLI_DEFAULT_WINDOW,BROTLI_MODE_GENERIC,sizeof(input),input,&size,compressed.data()));compressed.resize(size);
 CRYPTO_BUFFER*output=nullptr;
 assert(meshpn_cert::decode(nullptr,&output,sizeof(input),compressed.data(),size));
 assert(CRYPTO_BUFFER_len(output)==sizeof(input)&&!memcmp(CRYPTO_BUFFER_data(output),input,sizeof(input)));CRYPTO_BUFFER_free(output);
 for(size_t n=0;n<size;n++){output=nullptr;assert(!meshpn_cert::decode(nullptr,&output,sizeof(input),compressed.data(),n));assert(!output);}
 compressed.push_back(0);assert(!meshpn_cert::decode(nullptr,&output,sizeof(input),compressed.data(),size+1));
 assert(!meshpn_cert::decode(nullptr,&output,sizeof(input)-1,compressed.data(),size));
 assert(!meshpn_cert::decode(nullptr,&output,sizeof(input)+1,compressed.data(),size));
 assert(!meshpn_cert::decode(nullptr,&output,meshpn_cert::certificate_limit+1,compressed.data(),size));
 meshpn_cert::Budget budget;
 assert(!meshpn_cert::alloc(&budget,SIZE_MAX));
 void*p=meshpn_cert::alloc(&budget,meshpn_cert::memory_limit-sizeof(meshpn_cert::Allocation));assert(p);
 assert(!meshpn_cert::alloc(&budget,1));meshpn_cert::release(&budget,p);assert(!budget.live);
 puts("Gate parser: all truncations + 50000 mutations; Brotli roundtrip, malformed stream and budgets passed");
}
