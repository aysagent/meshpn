/* Compiled with the production checksumadjust and generated NAPT ICMP helper. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "meshvpn_vpn_frame.h"
typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef struct { u32_t addr; } ip4_addr_p_t;
struct ip_hdr { u8_t vh,tos; u16_t len,id,frag; u8_t ttl,proto; u16_t sum; ip4_addr_p_t src,dest; };
struct pbuf {u16_t tot_len, split;u8_t head[160],tail[160];};
struct ip_napt_entry {u32_t src,dest;u16_t sport,dport,mport;u8_t proto;};
static struct ip_napt_entry entry;
static unsigned lookups;
#define IPH_HL(h) ((h)->vh&15)
#define IPH_LEN(h) ((h)->len)
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMP 1
#define lwip_ntohs ntohs
#define ERR_OK 0
static unsigned check(const void*data,size_t len){
 const u8_t*b=data;unsigned s=0;
 for(size_t i=0;i<len;i+=2)s+=(b[i]<<8)|(i+1<len?b[i+1]:0);
 while(s>>16)s=(s&65535)+(s>>16);return (~s)&65535;
}
static unsigned inet_chksum(const void*p,size_t n){return check(p,n);}
static unsigned pbuf_copy_partial(struct pbuf*p,void*out,unsigned len,unsigned off){
 if(off>=p->tot_len)return 0;if(len>p->tot_len-off)len=p->tot_len-off;
 for(unsigned i=0;i<len;i++){unsigned a=off+i;((u8_t*)out)[i]=a<p->split?p->head[a]:p->tail[a-p->split];}return len;
}
static int pbuf_take_at(struct pbuf*p,const void*in,unsigned len,unsigned off){
 assert(off+len<=p->tot_len);
 for(unsigned i=0;i<len;i++){unsigned a=off+i;if(a<p->split)p->head[a]=((const u8_t*)in)[i];else p->tail[a-p->split]=((const u8_t*)in)[i];}return 0;
}
static struct ip_napt_entry*ip_napt_find(u8_t proto,u32_t remote,u16_t port,u16_t mapped,u8_t dest){
 lookups++;
 if(!dest)return proto==entry.proto&&remote==entry.src&&port==entry.sport?&entry:NULL;
 return proto==entry.proto&&remote==entry.dest&&port==entry.dport&&mapped==entry.mport?&entry:NULL;
}
#include "napt-checksum.inc"
static void ip_napt_modify_addr(struct ip_hdr*h,ip4_addr_p_t*field,u32_t address){
 checksumadjust((u8_t*)&h->sum,(u8_t*)&field->addr,4,(u8_t*)&address,4);field->addr=address;
}
#include "../scripts/lwip-napt-icmp.inc"
static void run(unsigned proto,unsigned quoted,unsigned split,unsigned type){
 u8_t inner[80]={0x45,0,0,80},outer[160]={0x45};
 inner[8]=64;inner[9]=proto;inet_pton(AF_INET,"10.99.0.2",inner+12);inet_pton(AF_INET,"198.18.0.1",inner+16);
 inner[20]=0x9c;inner[21]=0x40;inner[23]=80;inner[32]=0x50;inner[33]=2;
 if(proto==17){inner[24]=0;inner[25]=60;}
 if(proto==1){inner[20]=8;inner[21]=0;inner[24]=0x9c;inner[25]=0x40;}
 assert(meshvpn_vpn_repair_checksums(inner,sizeof(inner)));
 entry=(struct ip_napt_entry){.proto=proto,.sport=htons(50001),.mport=htons(40000),.dport=proto==1?htons(40000):htons(80)};
 inet_pton(AF_INET,"192.168.10.2",&entry.src);memcpy(&entry.dest,inner+16,4);
 unsigned n=28+quoted;outer[2]=n>>8;outer[3]=n;outer[8]=64;outer[9]=1;
 inet_pton(AF_INET,"198.18.0.254",outer+12);memcpy(outer+16,inner+12,4);
 outer[20]=type;outer[21]=type==3?4:0;outer[26]=5;outer[27]=0;
 memcpy(outer+28,inner,quoted);assert(meshvpn_vpn_repair_checksums(outer,n));
 struct pbuf p={.tot_len=n,.split=split};pbuf_take_at(&p,outer,n,0);
 struct ip_hdr header;memcpy(&header,outer,sizeof(header));
 assert(meshpn_napt_icmp_error(&p,&header));pbuf_copy_partial(&p,outer,n,0);
 assert(!check(outer,20)&&!check(outer+20,n-20));
 assert(!memcmp(outer+16,&entry.src,4)&&!memcmp(outer+40,&entry.src,4));
 assert(!check(outer+28,20));assert(outer[26]==5&&outer[27]==0); // next-hop MTU retained
 assert(!memcmp(outer+28+20+(proto==1?4:0),&entry.sport,2));
 if(proto==17||proto==1||quoted>=38){
  memcpy(inner,outer+28,quoted);u8_t expected[80];memcpy(expected,inner,sizeof(inner));
  assert(meshvpn_vpn_repair_checksums(expected,sizeof(expected)));
  unsigned offset=20+(proto==17?6:proto==1?2:16);
  assert(!memcmp(inner+offset,expected+offset,2));
 }
 // A quote for another remote tuple must not rewrite anything.
 outer[47]^=1;assert(meshvpn_vpn_repair_checksums(outer,n));pbuf_take_at(&p,outer,n,0);
 memcpy(&header,outer,sizeof(header));unsigned before=lookups;
 assert(!meshpn_napt_icmp_error(&p,&header));assert(lookups==before); // inner IP checksum invalid
}
static void outbound(unsigned proto,unsigned quoted,unsigned split,unsigned type,unsigned options){
 unsigned ihl=20+options;u8_t inner[80]={0},outer[160]={0x45};
 inner[0]=0x40|ihl/4;inner[3]=80;inner[8]=64;inner[9]=proto;
 inet_pton(AF_INET,"198.18.0.1",inner+12);inet_pton(AF_INET,"192.168.12.2",inner+16);
 u8_t *l4=inner+ihl;l4[1]=80;l4[2]=0xc3;l4[3]=0x51; // remote80 -> local50001
 l4[12]=0x50;l4[13]=0x10;
 if(proto==17){l4[4]=0;l4[5]=80-ihl;}
 if(proto==1){l4[0]=0;l4[1]=0;l4[4]=0xc3;l4[5]=0x51;}
 assert(meshvpn_vpn_repair_checksums(inner,sizeof(inner)));
 entry=(struct ip_napt_entry){.proto=proto,.sport=htons(50001),.mport=htons(40000),.dport=htons(proto==1?50001:80)};
 memcpy(&entry.src,inner+16,4);memcpy(&entry.dest,inner+12,4);
 unsigned n=28+quoted;outer[2]=n>>8;outer[3]=n;outer[8]=64;outer[9]=1;
 memcpy(outer+12,inner+16,4);memcpy(outer+16,inner+12,4);
 outer[20]=type;outer[21]=type==3?4:0;outer[26]=5;outer[27]=0;
 memcpy(outer+28,inner,quoted);assert(meshvpn_vpn_repair_checksums(outer,n));
 struct pbuf p={.tot_len=n,.split=split};pbuf_take_at(&p,outer,n,0);
 struct ip_hdr header;memcpy(&header,outer,sizeof(header));u32_t external;
 inet_pton(AF_INET,"10.99.0.4",&external);
 // Source lookup alone must not authorize an unrelated remote destination/port.
 entry.dport^=htons(1);assert(!meshpn_napt_icmp_error_map(&p,&header,&external));entry.dport^=htons(1);
 entry.dest^=htonl(1);assert(!meshpn_napt_icmp_error_map(&p,&header,&external));entry.dest^=htonl(1);
 u8_t unchanged[160];pbuf_copy_partial(&p,unchanged,n,0);assert(!memcmp(unchanged,outer,n));
 assert(meshpn_napt_icmp_error_map(&p,&header,&external));pbuf_copy_partial(&p,outer,n,0);
 assert(!check(outer,20)&&!check(outer+20,n-20));
 assert(!memcmp(outer+12,&external,4)&&!memcmp(outer+28+16,&external,4));
 assert(!memcmp(outer+16,&entry.dest,4)&&!check(outer+28,ihl));
 assert(outer[26]==5&&outer[27]==0);
 assert(!memcmp(outer+28+ihl+(proto==1?4:2),&entry.mport,2));
 if(proto==17||proto==1||quoted>=ihl+18){
  memcpy(inner,outer+28,quoted);u8_t expected[80];memcpy(expected,inner,sizeof(inner));
  assert(meshvpn_vpn_repair_checksums(expected,sizeof(expected)));
  unsigned offset=ihl+(proto==17?6:proto==1?2:16);
  assert(!memcmp(inner+offset,expected+offset,2));
 }
 // Truncated ICMP quotations cannot access beyond the first eight L4 bytes.
 p.tot_len=28+ihl+7;header.len=htons(p.tot_len);
 assert(!meshpn_napt_icmp_error_map(&p,&header,&external));
}
int main(void){
 for(unsigned p=0;p<3;p++)for(unsigned q=28;q<=60;q++)for(unsigned split=1;split<28+q;split+=7)
  for(unsigned t=0;t<3;t++)run((unsigned[]){6,17,1}[p],q,split,(unsigned[]){3,11,12}[t]);
 for(unsigned proto=0;proto<3;proto++)for(unsigned options=0;options<=4;options+=4)
  for(unsigned q=28+options;q<=60;q++)for(unsigned split=1;split<28+q;split+=7)
   for(unsigned t=0;t<3;t++)outbound((unsigned[]){6,17,1}[proto],q,split,(unsigned[]){3,11,12}[t],options);
 puts("NAPT ICMP bidirectional: TCP/UDP/echo quotes, port/address/checksum restoration, short/chained packets and MTU preserved");
}
