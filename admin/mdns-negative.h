// Bounded DNS wire helpers for our IPv4-only administration alias (RFC 6762 §6.1).
#ifndef MESHPN_MDNS_NEGATIVE_H
#define MESHPN_MDNS_NEGATIVE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static unsigned mdns_u16(const uint8_t *p) { return (unsigned)p[0]*256+p[1]; }
static int mdns_name(const uint8_t *p, size_t n, size_t *offset, char out[254]) {
 size_t at=*offset, end=0, used=0;
 for(unsigned hops=0;hops<128;hops++) {
  if(at>=n)return 0;
  unsigned len=p[at++];
  if((len&0xc0)==0xc0) {
   if(at>=n)return 0;
   size_t target=((len&63)<<8)|p[at++];
   if(!end)end=at;
   // DNS compression may only refer to a prior name, never a cycle/forward pointer.
   if(target<12||target>=at-2)return 0;
   at=target;continue;
  }
  if(len>63||at+len>n)return 0;
  if(!len){out[used]=0;*offset=end?end:at;return 1;}
  if(used){if(used>=253)return 0;out[used++]='.';}
  if(used+len>253)return 0;
  for(unsigned i=0;i<len;i++){unsigned c=p[at++];if(!c||c=='.')return 0;out[used++]=(char)(c>='A'&&c<='Z'?c+32:c);}
 }
 return 0;
}
static int mdns_asks_aaaa(const uint8_t *p,size_t n,const char *host) {
 if(n<12||n>4096||mdns_u16(p)||mdns_u16(p+2)||mdns_u16(p+6)||mdns_u16(p+8)||mdns_u16(p+10))return 0;
 unsigned questions=mdns_u16(p+4);if(!questions||questions>32)return 0;
 size_t at=12;int match=0;
 for(unsigned q=0;q<questions;q++) {
  char name[254];if(!mdns_name(p,n,&at,name)||at+4>n)return 0;
  if(!strcmp(name,host)&&mdns_u16(p+at)==28&&(mdns_u16(p+at+2)&0x7fff)==1)match=1;
  at+=4;
 }
 return at==n&&match;
}
static size_t mdns_nsec(uint8_t out[512],const char *host) {
 memset(out,0,512);out[2]=0x84;out[7]=1;size_t at=12;
 const char *label=host;
 while(*label){const char *dot=strchr(label,'.');size_t len=dot?(size_t)(dot-label):strlen(label);if(!len||len>63||at+len+1>480)return 0;out[at++]=(uint8_t)len;memcpy(out+at,label,len);at+=len;if(!dot)break;label=dot+1;}
 out[at++]=0;
 // NSEC, cache-flush IN, TTL 120, RDLENGTH 5, own name, window 0, A only.
 // Synthesized mDNS NSEC MUST NOT set the NSEC type bit.
 const uint8_t tail[]={0,47,0x80,1,0,0,0,120,0,5,0xc0,12,0,1,0x40};
 memcpy(out+at,tail,sizeof tail);return at+sizeof tail;
}
#endif
