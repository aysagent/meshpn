#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/queue.h>

#define MEMPOOL_ALIGNED(v) ((v) + 64 - ((v) & 63))
struct mempool_entry { SLIST_ENTRY(mempool_entry) entries; };
struct mempool { SLIST_HEAD(, mempool_entry) head; void *spinlock; uint32_t block_size; };
static struct mempool *buf_mp_g;
static unsigned held, locks;
static void lock(void *p) { assert(p && !held); held++; locks++; }
static void unlock(void *p) { assert(p && held == 1); held--; }
static struct { void (*_h_lock_mempool)(void *); void (*_h_unlock_mempool)(void *); } funcs = { lock, unlock };
static struct { typeof(funcs) *funcs; } g_h = { &funcs };
#include "sdio-cache.inc"
#define ESP_STA_IF 0
#define ESP_AP_IF 1
typedef struct { struct mempool *memp; } transport_channel_t;
static transport_channel_t *chan_arr[2];
#include "transport-cache.inc"

int main(void)
{
    uint32_t count = 99, bytes = 99;
    assert(!meshvpn_hosted_dma_cache_snapshot(&count, &bytes));
    assert(count == 0 && bytes == 0 && !locks);
    struct mempool pool = {.spinlock = &pool, .block_size = 1600};
    SLIST_INIT(&pool.head); buf_mp_g = &pool;
    assert(meshvpn_hosted_dma_cache_snapshot(&count, &bytes));
    assert(count == 0 && bytes == 1664 && locks == 1 && !held);
    struct mempool_entry entries[40];
    for (unsigned i = 0; i < 40; i++) SLIST_INSERT_HEAD(&pool.head, &entries[i], entries);
    assert(meshvpn_hosted_dma_cache_snapshot(&count, &bytes));
    assert(count == 40 && bytes == 1664 && !held);
    for (unsigned i = 0; i < 17; i++) SLIST_REMOVE_HEAD(&pool.head, entries);
    assert(meshvpn_hosted_dma_cache_snapshot(&count, &bytes));
    assert(count == 23 && SLIST_FIRST(&pool.head) == &entries[22] && !held);
    assert(!meshvpn_hosted_transport_dma_cache_snapshot(2, &count, &bytes));
    assert(count == 0 && bytes == 0);
    assert(!meshvpn_hosted_transport_dma_cache_snapshot(0, &count, &bytes));
    transport_channel_t channel = {0}; chan_arr[0] = &channel;
    assert(!meshvpn_hosted_transport_dma_cache_snapshot(0, &count, &bytes));
    channel.memp = &pool;
    assert(meshvpn_hosted_transport_dma_cache_snapshot(0, &count, &bytes));
    assert(count == 23 && bytes == 1664 && !held);
    assert(!meshvpn_hosted_transport_dma_cache_snapshot(1, &count, &bytes));
    assert(count == 0 && bytes == 0);
    puts("Hosted DMA cache snapshot: absent, empty, retained, reused PASS");
}
