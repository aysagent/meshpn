#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "meshvpn_dns_wire.h"
#include "meshvpn_ip_ranges.h"

static const uint8_t query[] = {
    0x12,0x34,1,0,0,1,0,0,0,0,0,0,
    7,'c','a','p','t','i','v','e',5,'a','p','p','l','e',3,'c','o','m',0,0,1,0,1
};
int main(void)
{
    meshvpn_dns_question_t q;
    assert(meshvpn_dns_question(query,sizeof(query),&q));
    assert(!strcmp(q.name,"captive.apple.com"));
    assert(q.end==sizeof(query)&&q.type==1&&q.klass==1);
    for(size_t n=0;n<sizeof(query);n++) assert(!meshvpn_dns_question(query,n,&q));
    uint8_t malformed[sizeof(query)];memcpy(malformed,query,sizeof(query));
    malformed[12]=0xc0;malformed[13]=12;
    assert(!meshvpn_dns_question(malformed,sizeof(malformed),&q)); /* cyclic compression */
    malformed[12]=64;
    assert(!meshvpn_dns_question(malformed,sizeof(malformed),&q));
    uint8_t answer[512];uint8_t ipbytes[]={192,168,7,1};uint32_t ip;
    memcpy(&ip,ipbytes,4);
    size_t n=meshvpn_dns_reply(query,sizeof(query),answer,sizeof(answer),0,false,ip);
    assert(n==sizeof(query)+16);
    assert(answer[7]==1&&answer[11]==0);
    assert(!memcmp(answer+n-4,ipbytes,4));
    assert(meshvpn_dns_age_ttls(answer,n,10)==20);
    assert(meshvpn_dns_age_ttls(answer,n,20)==0);
    n=meshvpn_dns_reply(query,sizeof(query),answer,sizeof(answer),0,false,ip);
    assert(meshvpn_dns_age_ttls(answer,n-1,0)==0);
    assert(meshvpn_dns_question(answer,n,&q)&&!strcmp(q.name,"captive.apple.com"));
    memcpy(malformed,query,sizeof(query));malformed[sizeof(query)-3]=28;
    n=meshvpn_dns_reply(malformed,sizeof(malformed),answer,sizeof(answer),0,false,ip);
    assert(n==sizeof(query)&&answer[7]==0); /* AAAA NODATA, not silence */
    n=meshvpn_dns_reply(query,sizeof(query),answer,sizeof(answer),2,false,0);
    assert(n==sizeof(query)&&(answer[3]&15)==2);
    n=meshvpn_dns_reply(query,sizeof(query),answer,sizeof(answer),0,true,0);
    assert(n==sizeof(query)&&(answer[2]&2)&&!answer[7]);
    assert(meshvpn_dns_reply(query,sizeof(query),answer,12,0,false,ip)==0);
    const meshvpn_ip_range_t r[]={{0,0},{10,20},{100,200},{0xffffffff,0xffffffff}};
    assert(!meshvpn_ip_ranges_contains(NULL,0,10));
    assert(meshvpn_ip_ranges_contains(r,4,0));
    assert(!meshvpn_ip_ranges_contains(r,4,9));
    assert(meshvpn_ip_ranges_contains(r,4,10));
    assert(meshvpn_ip_ranges_contains(r,4,20));
    assert(!meshvpn_ip_ranges_contains(r,4,21));
    assert(meshvpn_ip_ranges_contains(r,4,0xffffffff));
    puts("DNS wire and IPv4 range tests passed");
}
