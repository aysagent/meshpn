// Host boundary for the production PSRAM allocator. No device memory claims.
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
struct alignas(std::max_align_t) Header { size_t size; };
static size_t live, peak, calls;
extern "C" void *heap_caps_malloc(size_t size, int caps) {
    if ((caps & 16) && std::getenv("MESHPN_TEST_DMA_ALLOC_FAIL")) return nullptr;
    assert(caps==3 || caps==(8|16|2)); // PSRAM or GCM internal DMA slab
    const char *limit=std::getenv("MESHPN_TEST_ALLOC_FAIL_AFTER");
    if(limit && calls++>=std::strtoull(limit,nullptr,10))return nullptr;
    auto *p=static_cast<Header*>(std::malloc(sizeof(Header)+size));
    if(!p)return nullptr;
    p->size=size;live+=size;if(live>peak)peak=live;return p+1;
}
extern "C" void heap_caps_free(void *ptr) {
    if(!ptr)return;
    auto *p=static_cast<Header*>(ptr)-1;assert(live>=p->size);live-=p->size;std::free(p);
}
extern "C" size_t meshpn_test_heap_live() {return live;}
extern "C" void meshpn_test_heap_report() {std::fprintf(stderr,"PROFILE_HEAP live=%zu peak=%zu\n",live,peak);}
