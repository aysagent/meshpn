#pragma once
#include <brotli/decode.h>
#include <openssl/pool.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>
#include <cstddef>
#include <cstdlib>
// Peer-controlled compressed certificates have independent output/decoder caps.
namespace meshpn_cert {
constexpr size_t certificate_limit=64*1024, memory_limit=256*1024, work_limit=1024*1024;
struct Budget {size_t live=0,total=0;};
struct alignas(std::max_align_t) Allocation {size_t size;};
inline void* alloc(void* ctx,size_t size){
 auto& b=*static_cast<Budget*>(ctx);
 if(size>memory_limit-sizeof(Allocation))return nullptr;
 size+=sizeof(Allocation);
 if(size>memory_limit-b.live||size>work_limit-b.total)return nullptr;
 auto* p=static_cast<Allocation*>(OPENSSL_malloc(size));if(!p)return nullptr;
 p->size=size;b.live+=size;b.total+=size;return p+1;
}
inline void release(void* ctx,void* p){if(!p)return;auto* a=static_cast<Allocation*>(p)-1;static_cast<Budget*>(ctx)->live-=a->size;OPENSSL_free(a);}
inline int decode(SSL*,CRYPTO_BUFFER**out,size_t expected,const uint8_t*input,size_t length){
 *out=nullptr;
 if(!expected||expected>certificate_limit||!length||length>certificate_limit)return 0;
 Budget b;
 auto* state=BrotliDecoderCreateInstance(alloc,release,&b);if(!state)return 0;
 uint8_t* bytes=nullptr;auto* buffer=CRYPTO_BUFFER_alloc(&bytes,expected);
 if(!buffer){BrotliDecoderDestroyInstance(state);return 0;}
 size_t in=length,remaining=expected,total=0;auto* src=input;auto* dst=bytes;
 auto result=BrotliDecoderDecompressStream(state,&in,&src,&remaining,&dst,&total);
 BrotliDecoderDestroyInstance(state);
 if(result!=BROTLI_DECODER_RESULT_SUCCESS||in||remaining||total!=expected||b.live){CRYPTO_BUFFER_free(buffer);return 0;}
 *out=buffer;return 1;
}
}
