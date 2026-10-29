/* Coverage-guided entry point. Exact-sized copies expose overreads to ASan. */
#include "meshvpn_vpn_frame.h"
#include "meshvpn_vpn_stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static bool emit(void *ctx,const uint8_t *p,size_t n){
    (*(unsigned*)ctx)++;assert(n<=MESHVPN_VPN_MTU&&meshvpn_vpn_ipv4_valid(p,n));return true;
}
int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    if(size>4096)return 0;
    uint8_t *p=malloc(size?size:1),*before=malloc(size?size:1);assert(p&&before);
    memcpy(p,data,size);memcpy(before,data,size);
    bool valid=meshvpn_vpn_ipv4_valid(p,size);
    if(meshvpn_vpn_repair_checksums(p,size)){
        assert(valid);memcpy(before,p,size);assert(meshvpn_vpn_repair_checksums(p,size));assert(!memcmp(p,before,size));
    }else assert(!memcmp(p,before,size));
    (void)meshvpn_vpn_clamp_mss(p,size);
    memcpy(p,data,size);bool changed=false;(void)meshvpn_vpn_repair_ethernet_checksums(p,size,&changed);
    uint8_t reply[100];size_t n=meshvpn_vpn_frag_needed(reply,sizeof(reply),data,size,(uint8_t[]){192,168,10,1});
    if(n)assert(n<=sizeof(reply)&&meshvpn_vpn_ipv4_valid(reply,n));
    meshvpn_vpn_rx_stream_t rx={0};unsigned count=0;
    for(size_t pos=0;pos<size;){
        size_t part=1+data[pos]%97;if(part>size-pos)part=size-pos;
        if(!meshvpn_vpn_rx_feed(&rx,data+pos,part,100+pos,emit,&count))break;
        pos+=part;
    }
    meshvpn_vpn_tx_batch_t batch={0};
    if(meshvpn_vpn_tx_append(&batch,data,size)){
        size_t accepted=0;unsigned packets=0;
        while(batch.used<batch.length){size_t part=1+(size?data[batch.used%size]:0);if(part>batch.length-batch.used)part=batch.length-batch.used;
            size_t bytes=0;unsigned frames=0;assert(meshvpn_vpn_tx_advance(&batch,part,&frames,&bytes));accepted+=bytes;packets+=frames;}
        assert(packets==1&&accepted==size);
    }
    free(before);free(p);return 0;
}
