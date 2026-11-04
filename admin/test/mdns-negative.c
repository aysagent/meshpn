#include "../mdns-negative.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
 uint8_t q[512]={0};q[5]=1;size_t at=12;
 const uint8_t name[]={3,'M','P','N',5,'l','o','c','a','l',0};
 memcpy(q+at,name,sizeof name);at+=sizeof name;
 q[at++]=0;q[at++]=28;q[at++]=0x80;q[at++]=1;
 assert(mdns_asks_aaaa(q,at,"mpn.local"));assert(!mdns_asks_aaaa(q,at,"other.local"));
 for(size_t n=0;n<at;n++)assert(!mdns_asks_aaaa(q,n,"mpn.local"));
 q[2]=0x80;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[2]=0;
 q[at-3]=1;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[at-3]=28;
 q[at-1]=3;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[at-1]=1;
 q[9]=1;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[9]=0;
 q[7]=1;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[7]=0;
 q[0]=1;assert(!mdns_asks_aaaa(q,at,"mpn.local"));q[0]=0;
 q[5]=2;q[at++]=0xc0;q[at++]=12;q[at++]=0;q[at++]=28;q[at++]=0;q[at++]=1;
 assert(mdns_asks_aaaa(q,at,"mpn.local"));
 q[at-5]=(uint8_t)(at-6);assert(!mdns_asks_aaaa(q,at,"mpn.local")); // pointer to self
 q[at-5]=255;assert(!mdns_asks_aaaa(q,at,"mpn.local"));
 q[12]=64;assert(!mdns_asks_aaaa(q,at,"mpn.local"));
 uint8_t reply[512];size_t n=mdns_nsec(reply,"mpn.local"),offset=12;char decoded[254];
 assert(n&&reply[2]==0x84&&mdns_u16(reply+6)==1);
 assert(mdns_name(reply,n,&offset,decoded)&&!strcmp(decoded,"mpn.local"));
 assert(mdns_u16(reply+offset)==47&&mdns_u16(reply+offset+2)==0x8001);
 assert(reply[offset+7]==120&&mdns_u16(reply+offset+8)==5);
 offset+=10;assert(mdns_name(reply,n,&offset,decoded)&&!strcmp(decoded,"mpn.local"));
 assert(n-offset==3&&reply[offset]==0&&reply[offset+1]==1&&reply[offset+2]==0x40);
 assert(!mdns_asks_aaaa(reply,n,"mpn.local"));
 assert(!mdns_nsec(reply,"bad..local"));
 puts("mDNS negative query bounds and RFC 6762 NSEC wire: passed");
}
