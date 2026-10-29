#include "esp_heap_caps.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
// All BoringSSL allocations (including decoder calls via OPENSSL_malloc) use
// PSRAM. A missing/exhausted PSRAM pool fails closed, never drains Wi-Fi DMA RAM.
namespace {
constexpr size_t limit=1024*1024;
struct alignas(std::max_align_t) Header {size_t charged;};
std::atomic<size_t> live{0};
}
extern "C" void* OPENSSL_memory_alloc(size_t size){
 if(size>limit-sizeof(Header))return nullptr;
 size_t charged=size+sizeof(Header),before=live.load();
 do{if(charged>limit-before)return nullptr;}while(!live.compare_exchange_weak(before,before+charged));
 auto*p=static_cast<Header*>(heap_caps_malloc(charged,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
 if(!p){live.fetch_sub(charged);return nullptr;}p->charged=charged;return p+1;
}
extern "C" size_t OPENSSL_memory_get_size(void*p){return (static_cast<Header*>(p)-1)->charged-sizeof(Header);}
extern "C" void OPENSSL_memory_free(void*p){
 if(!p)return;
 auto*h=static_cast<Header*>(p)-1;size_t charged=h->charged;
 volatile uint8_t*data=static_cast<volatile uint8_t*>(p);
 for(size_t i=0;i<charged-sizeof(Header);i++)data[i]=0;
 live.fetch_sub(charged);heap_caps_free(h);
}
