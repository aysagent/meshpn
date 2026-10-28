/* Seeded packet mutations under ASan/UBSan; independent checksum invariants.
 * This is not a model of radio or tunnel performance. */
#include "meshvpn_vpn_frame.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t random_state = 0x7352a1b9;
static uint32_t next(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    return random_state ^= random_state << 5;
}
static unsigned sum(const uint8_t *p, size_t n, unsigned initial) {
    for (size_t i=0; i<n; i++) initial += (unsigned)p[i] << (i%2 ? 0 : 8);
    while (initial >> 16) initial = (initial & 65535) + (initial >> 16);
    return initial;
}
static void put(uint8_t *p, unsigned n) { p[0]=n>>8; p[1]=n; }
static bool emitted(void *context, const uint8_t *packet, size_t n) {
    assert(meshvpn_vpn_ipv4_valid(packet,n));
    (*(unsigned *)context)++;
    return true;
}
static void verify(uint8_t *p, size_t n) {
    uint8_t before[MESHVPN_VPN_MTU], repaired[MESHVPN_VPN_MTU];
    memcpy(before,p,n);
    if (!meshvpn_vpn_repair_checksums(p,n)) {
        assert(!memcmp(before,p,n)); /* rejection must not partly rewrite */
        return;
    }
    unsigned h=(p[0]&15)*4;
    assert(sum(p,h,0)==65535);
    if (!(p[6]&0x3f) && !p[7]) {
        unsigned pseudo=p[9]==1 ? 0 : sum(p+12,8,p[9]+n-h);
        assert(sum(p+h,n-h,pseudo)==65535);
        /* Repair must preserve every byte except checksum fields. */
        unsigned offset=h+(p[9]==6?16:p[9]==17?6:2);
        for (size_t i=0;i<n;i++)
            if(i!=10&&i!=11&&i!=offset&&i!=offset+1)assert(before[i]==p[i]);
    }
    memcpy(repaired,p,n);
    assert(meshvpn_vpn_repair_checksums(p,n)&&!memcmp(repaired,p,n));
    if(meshvpn_vpn_clamp_mss(p,n) && p[9]==6 && !(p[6]&0x3f) && !p[7])
        assert(sum(p+h,n-h,sum(p+12,8,6+n-h))==65535);
}
int main(int argc,char **argv) {
    unsigned iterations=argc>1?(unsigned)strtoul(argv[1],NULL,10):20000;
    assert(iterations>0&&iterations<=10000000);
    for(unsigned round=0;round<iterations;round++) {
        unsigned h=20+4*(next()%11), protocol=(unsigned[]){1,6,17}[next()%3];
        unsigned transport=protocol==6?20+4*(next()%11):8;
        size_t n=h+transport+next()%(MESHVPN_VPN_MTU-h-transport+1);
        uint8_t *p=malloc(n);assert(p);
        for(size_t i=0;i<n;i++)p[i]=next();
        p[0]=0x40|h/4;put(p+2,n);p[6]=0x40;p[7]=0;p[9]=protocol;
        if(protocol==6) {
            p[h+12]=(transport/4)<<4;p[h+13]=2;
            memset(p+h+20,1,transport-20);
            if(transport>=28) {
                unsigned at=h+20+next()%4;
                p[at]=2;p[at+1]=4;put(p+at+2,65535);
            }
        } else if(protocol==17)put(p+h+4,n-h);
        verify(p,n);
        unsigned count=0;meshvpn_vpn_decoder_t decoder={0};
        uint8_t header[4];meshvpn_vpn_frame_header(header,n);
        assert(meshvpn_vpn_decode(&decoder,header,4,emitted,&count));
        for(size_t i=0;i<n;) {
            size_t part=1+next()%97;if(part>n-i)part=n-i;
            assert(meshvpn_vpn_decode(&decoder,p+i,part,emitted,&count));i+=part;
        }
        assert(count==1&&!decoder.header_used&&!decoder.used);
        /* Invalid lengths, option bytes and protocols, with exact allocations
         * so ASan can detect reads outside the caller's actual packet. */
        for(unsigned k=0;k<1+round%4;k++)p[next()%n]^=1u<<(next()%8);
        size_t cut=next()%(n+1);
        uint8_t *small=malloc(cut?cut:1);assert(small);memcpy(small,p,cut);
        verify(small,cut);(void)meshvpn_vpn_clamp_mss(small,cut);
        free(small);free(p);
    }
    printf("Packet properties: %u seeded TCP/UDP/ICMP, MSS, split and mutation cases passed\n",iterations);
}
