#pragma once
// RFC 8879 algorithm 2. Decode only, with explicit peer-controlled size and
// allocator budgets. No exception may cross BoringSSL's C callback boundary.
#include <brotli/decode.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <cstddef>
#include <cstdlib>

namespace cvpn::certificate_compression {
constexpr size_t certificate_limit = 128 * 1024;
constexpr size_t memory_limit = 4 * 1024 * 1024;
constexpr size_t allocation_limit = 16 * 1024 * 1024;
struct Budget { size_t live=0, total=0; };
struct alignas(std::max_align_t) Allocation { size_t bytes; };
inline void* allocate(void* opaque, size_t bytes) noexcept {
  auto& b=*static_cast<Budget*>(opaque);
  if(bytes>memory_limit-sizeof(Allocation))return nullptr;
  const auto charged=bytes+sizeof(Allocation);
  if(charged>memory_limit-b.live || charged>allocation_limit-b.total)return nullptr;
  auto* p=static_cast<Allocation*>(std::malloc(charged));if(!p)return nullptr;
  p->bytes=charged;b.live+=charged;b.total+=charged;return p+1;
}
inline void release(void* opaque, void* pointer) noexcept {
  if(!pointer)return;
  auto* p=static_cast<Allocation*>(pointer)-1;
  static_cast<Budget*>(opaque)->live-=p->bytes;std::free(p);
}
inline int decompress(SSL*, CRYPTO_BUFFER** out, size_t expected,
                      const uint8_t* input, size_t length) noexcept {
  *out=nullptr;
  if(!expected || expected>certificate_limit || !length || length>certificate_limit)return 0;
  Budget budget;
  auto* state=BrotliDecoderCreateInstance(allocate,release,&budget);if(!state)return 0;
  uint8_t* output=nullptr;auto* buffer=CRYPTO_BUFFER_alloc(&output,expected);
  if(!buffer){BrotliDecoderDestroyInstance(state);return 0;}
  size_t available_in=length,available_out=expected,total_out=0;
  auto* next_in=input;auto* next_out=output;
  const auto result=BrotliDecoderDecompressStream(state,&available_in,&next_in,&available_out,&next_out,&total_out);
  BrotliDecoderDestroyInstance(state);
  // Reject trailing/concatenated streams, truncation, over/under-sized output.
  if(result!=BROTLI_DECODER_RESULT_SUCCESS || available_in || available_out || total_out!=expected || budget.live) {
    CRYPTO_BUFFER_free(buffer);return 0;
  }
  *out=buffer;return 1;
}
inline bool enable(SSL_CTX* ctx) {
  return SSL_CTX_add_cert_compression_alg(ctx,2,nullptr,decompress)==1;
}
} // namespace cvpn::certificate_compression
