// Host probe only: BoringSSL allocator accounting, not device heap measurements.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
struct alignas(std::max_align_t) Header { size_t n; };
static std::atomic<size_t> current{0},peak{0},largest{0},calls{0};
static void maximum(std::atomic<size_t>&dest,size_t n){size_t old=dest.load();while(n>old&&!dest.compare_exchange_weak(old,n)){};}
extern "C" void* OPENSSL_memory_alloc(size_t n){
 if(n>SIZE_MAX-sizeof(Header))return nullptr;
 auto*p=(Header*)malloc(sizeof(Header)+n);if(!p)return nullptr;
 p->n=n;calls++;maximum(largest,n);maximum(peak,current.fetch_add(n)+n);return p+1;
}
extern "C" size_t OPENSSL_memory_get_size(void*p){return ((Header*)p)[-1].n;}
extern "C" void OPENSSL_memory_free(void*p){
 if(!p)return;auto*h=((Header*)p)-1;const size_t n=h->n;
 volatile unsigned char*q=(volatile unsigned char*)p;for(size_t i=0;i<n;i++)q[i]=0;
 current.fetch_sub(n);free(h);
}
extern "C" void report_heap(){fprintf(stderr,"BSSL_HEAP calls=%zu peak=%zu largest=%zu remaining=%zu\n",calls.load(),peak.load(),largest.load(),current.load());}
