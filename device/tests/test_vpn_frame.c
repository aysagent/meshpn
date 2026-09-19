#include "meshvpn_vpn_frame.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned seen;
static bool emit(void *ctx, const uint8_t *p, size_t n)
{ (void)ctx; assert(n == 28 && p[9] == 1); seen++; return true; }
static unsigned sum(const uint8_t *p, size_t n)
{
    unsigned s = 0;
    for (size_t i = 0; i < n; i += 2) s += (p[i] << 8) | (i + 1 < n ? p[i+1] : 0);
    while (s >> 16) s = (s & 65535) + (s >> 16);
    return (~s) & 65535;
}
static unsigned transport_sum(const uint8_t *p, size_t n)
{
    unsigned h=(p[0]&15)*4,l=n-h,s=0;
    for(unsigned i=12;i<20;i+=2)s+=(p[i]<<8)|p[i+1];
    s+=p[9]+l;
    for(size_t i=h;i<n;i+=2)s+=(p[i]<<8)|(i+1<n?p[i+1]:0);
    while(s>>16)s=(s&65535)+(s>>16);
    return (~s)&65535;
}
/* Binary pipe adapter used by the JS test with the actual clean-vpn framer. */
static bool echo(void *ctx, const uint8_t *p, size_t n)
{
    (void)ctx; uint8_t h[4]; meshvpn_vpn_frame_header(h, n);
    return fwrite(h, 1, 4, stdout) == 4 && fwrite(p, 1, n, stdout) == n;
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "pipe")) {
        meshvpn_vpn_decoder_t d = {0}; uint8_t b;
        while (fread(&b, 1, 1, stdin)) if (!meshvpn_vpn_decode(&d, &b, 1, echo, NULL)) return 2;
        return d.header_used ? 3 : 0; /* EOF with unfinished frame is invalid. */
    }
    uint8_t frame[32] = {0,0,0,28,0x45,0,0,28,0,1,0,0,64,1,0,0,10,99,0,2,10,99,0,1,8};
    for (size_t split = 0; split <= sizeof(frame); split++) {
        meshvpn_vpn_decoder_t d = {0}; seen = 0;
        assert(meshvpn_vpn_decode(&d, frame, split, emit, NULL));
        assert(meshvpn_vpn_decode(&d, frame + split, sizeof(frame) - split, emit, NULL));
        assert(seen == 1 && !d.header_used);
    }
    uint8_t combined[96]; for (int i=0; i<3; i++) memcpy(combined+i*32, frame, 32);
    meshvpn_vpn_decoder_t d = {0}; seen = 0;
    assert(meshvpn_vpn_decode(&d, combined, sizeof(combined), emit, NULL) && seen == 3);
    unsigned bad[] = {0,1,19,1401,65535,0xffffffff};
    for (unsigned i=0; i<sizeof(bad)/sizeof(*bad); i++) {
        memset(&d, 0, sizeof(d)); uint8_t h[4]; meshvpn_vpn_frame_header(h, bad[i]);
        assert(!meshvpn_vpn_decode(&d, h, 4, emit, NULL));
    }
    uint8_t ip[4]; uint16_t port;
    assert(meshvpn_vpn_endpoint("192.0.2.1:8765", ip, &port) && port == 8765 && ip[3] == 1);
    const char *invalid[] = {"", "host:80", "127.0.0.1:1", "1.2.3.256:80", "1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4:80x", "224.0.0.1:80", "1.2.3.:80"};
    for (unsigned i=0; i<sizeof(invalid)/sizeof(*invalid); i++) assert(!meshvpn_vpn_endpoint(invalid[i], ip, &port));
    /* MSS on even AND odd checksum boundary; checksum delta must be exact. */
    for (unsigned odd=0; odd<2; odd++) {
        uint8_t p[48] = {0x45,0,0,48}; p[8]=64;p[9]=6;
        p[12]=10;p[15]=2;p[16]=1;p[17]=1;p[18]=1;p[19]=1;
        p[20]=0xc0;p[21]=1;p[22]=0x01;p[23]=0xbb;p[32]=0x70;p[33]=2;
        unsigned off=40+odd; if (odd) p[40]=1;
        p[off]=2; p[off+1]=4; p[off+2]=0x05; p[off+3]=0xb4;
        unsigned c=transport_sum(p,sizeof(p)); p[36]=c>>8; p[37]=c;
        assert(meshvpn_vpn_clamp_mss(p,sizeof(p)));
        assert(p[off+2]==5 && p[off+3]==0x50 && transport_sum(p,sizeof(p))==0);
        /* Simulate checksum-offload/partial metadata: the raw transport must
         * repair both IPv4 and TCP checksums before writing this packet. */
        p[10]=p[11]=p[36]=p[37]=0;
        assert(meshvpn_vpn_repair_checksums(p,sizeof(p)));
        assert(sum(p,20)==0 && transport_sum(p,sizeof(p))==0);
        uint8_t ethernet[14 + sizeof(p)]; memset(ethernet, 0, sizeof(ethernet));
        ethernet[12]=0x08;ethernet[13]=0x00;memcpy(ethernet+14,p,sizeof(p));
        ethernet[24]=ethernet[25]=ethernet[50]=ethernet[51]=0;
        bool changed=false;
        assert(meshvpn_vpn_repair_ethernet_checksums(ethernet,sizeof(ethernet),&changed)&&changed);
        assert(sum(ethernet+14,20)==0&&transport_sum(ethernet+14,sizeof(p))==0);
        assert(meshvpn_vpn_repair_ethernet_checksums(ethernet,sizeof(ethernet),&changed)&&!changed);
        ethernet[12]=0x08;ethernet[13]=0x06;
        assert(!meshvpn_vpn_repair_ethernet_checksums(ethernet,sizeof(ethernet),&changed));
        p[off+1]=255; assert(!meshvpn_vpn_clamp_mss(p,sizeof(p)));
    }
    puts("VPN frame splitting/coalescing, bounds, endpoint and MSS checks passed");
}
