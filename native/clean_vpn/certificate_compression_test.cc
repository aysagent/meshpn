#include "certificate_compression.hpp"
#include <brotli/encode.h>
#include <openssl/pool.h>
#include <vector>
#include <iostream>
#include <cstring>
#include <stdexcept>
namespace cc=cvpn::certificate_compression;
static void need(bool ok){if(!ok)throw std::runtime_error("compression_test");}
int main(){try {
  for(size_t length:{size_t(1),size_t(4096),cc::certificate_limit}) {
    std::vector<uint8_t> plain(length);for(size_t i=0;i<length;i++)plain[i]=uint8_t(i*31);
    size_t size=BrotliEncoderMaxCompressedSize(length);std::vector<uint8_t> wire(size);
    need(BrotliEncoderCompress(4,22,BROTLI_MODE_GENERIC,length,plain.data(),&size,wire.data()));wire.resize(size);
    CRYPTO_BUFFER* out=nullptr;
    need(cc::decompress(nullptr,&out,length,wire.data(),wire.size())==1);
    need(CRYPTO_BUFFER_len(out)==length && std::memcmp(CRYPTO_BUFFER_data(out),plain.data(),length)==0);CRYPTO_BUFFER_free(out);
    for(size_t wrong:{size_t(0),length+1,cc::certificate_limit+1}) {
      need(cc::decompress(nullptr,&out,wrong,wire.data(),wire.size())==0 && out==nullptr);
    }
    if(length>1)need(cc::decompress(nullptr,&out,length-1,wire.data(),wire.size())==0 && out==nullptr);
    for(size_t cut=0;cut<wire.size();cut++)need(cc::decompress(nullptr,&out,length,wire.data(),cut)==0 && out==nullptr);
    auto trailing=wire;trailing.push_back(0);need(cc::decompress(nullptr,&out,length,trailing.data(),trailing.size())==0);
    auto concatenated=wire;concatenated.insert(concatenated.end(),wire.begin(),wire.end());
    need(cc::decompress(nullptr,&out,length,concatenated.data(),concatenated.size())==0);
    for(size_t i=0;i<wire.size();i++){auto mutated=wire;mutated[i]^=255;cc::decompress(nullptr,&out,length,mutated.data(),mutated.size());CRYPTO_BUFFER_free(out);}
  }
  CRYPTO_BUFFER* out=nullptr;uint8_t byte=0;
  need(cc::decompress(nullptr,&out,1,&byte,cc::certificate_limit+1)==0);
  cc::Budget budget;need(cc::allocate(&budget,cc::memory_limit)==nullptr);
  auto* allocation=cc::allocate(&budget,cc::memory_limit-sizeof(cc::Allocation));need(allocation!=nullptr);
  need(cc::allocate(&budget,1)==nullptr);cc::release(&budget,allocation);need(budget.live==0);
  budget.total=cc::allocation_limit;need(cc::allocate(&budget,1)==nullptr);
  std::cout<<"bounded Brotli, exact lengths, truncation, trailing streams, allocator budgets and mutation PASS\n";
  return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
