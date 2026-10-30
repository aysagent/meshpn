#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/inet_chksum.h"
#include "lwip/prot/ip4.h"
#include "lwip/priv/tcp_priv.h"
static u32_t now;
static unsigned outputs, fail_output;
static u32_t last_output_seq;
static ip4_addr_t local, remote;
static bool meshvpn_vpn_tcp_peer(uint32_t *peer,uint16_t *rp,uint16_t *lp)
{*peer=remote.addr;*rp=40000;*lp=50000;return true;}
#include "../recovery.inc"
u32_t sys_now(void) { return now; }
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *a) {
  unsigned char bytes[60];
  struct ip_hdr *ip=(struct ip_hdr *)bytes;
  struct tcp_hdr *tcp;
  (void)n; (void)a;
  assert(pbuf_copy_partial(p,bytes,40,0)==40);
  tcp=(struct tcp_hdr *)(bytes+IPH_HL_BYTES(ip));
  printf("output ms=%u seq=%u len=%u flags=%u\n",now,lwip_ntohl(tcp->seqno),
    (unsigned)(lwip_ntohs(IPH_LEN(ip))-IPH_HL_BYTES(ip)-TCPH_HDRLEN_BYTES(tcp)),TCPH_FLAGS(tcp));
  last_output_seq=lwip_ntohl(tcp->seqno);
  outputs++;
  return fail_output ? ERR_IF : ERR_OK;
}
static err_t setup(struct netif *n) {
  n->output=output; n->mtu=1500; n->name[0]='t'; n->name[1]='s'; return ERR_OK;
}
static void ack(struct netif *n, struct tcp_pcb *pcb, u32_t ackno) {
  struct pbuf *p=pbuf_alloc(PBUF_RAW,40,PBUF_RAM);
  struct ip_hdr *ip=p->payload;
  struct tcp_hdr *tcp=(struct tcp_hdr *)((unsigned char *)p->payload+20);
  memset(p->payload,0,40);
  tcp->src=lwip_htons(40000); tcp->dest=lwip_htons(50000);
  tcp->seqno=lwip_htonl(2000); tcp->ackno=lwip_htonl(ackno);
  TCPH_HDRLEN_FLAGS_SET(tcp,5,TCP_ACK); tcp->wnd=lwip_htons(12000);
  assert(pbuf_remove_header(p,20)==0);
  tcp->chksum=inet_chksum_pseudo(p,IP_PROTO_TCP,20,&remote,&local);
  assert(pbuf_add_header(p,20)==0);
  IPH_VHL_SET(ip,4,5); IPH_LEN_SET(ip,lwip_htons(40));
  IPH_TTL_SET(ip,64); IPH_PROTO_SET(ip,IP_PROTO_TCP);
  ip4_addr_copy(ip->src,remote); ip4_addr_copy(ip->dest,local);
  IPH_CHKSUM_SET(ip,inet_chksum(ip,20));
  printf("inject ms=%u ack=%u\n",now,ackno);
  assert(ip4_input(p,n)==ERR_OK);
  printf("state lastack=%u dupacks=%u infr=%u rtime=%d rto=%d unacked=%u outputs=%u\n",
    pcb->lastack,pcb->dupacks,!!(pcb->flags&TF_INFR),pcb->rtime,pcb->rto,
    pcb->unacked?lwip_ntohl(pcb->unacked->tcphdr->seqno):0,outputs);
}

static struct tcp_pcb *connection(u32_t base) {
  struct tcp_pcb *pcb=tcp_new(); char bytes[644];
  const unsigned lengths[]={641,97,644,97,600,600};
  assert(pcb); memset(bytes,0x5a,sizeof(bytes));
  pcb->state=ESTABLISHED; tcp_nagle_disable(pcb);
  ip_addr_copy_from_ip4(pcb->local_ip,local); ip_addr_copy_from_ip4(pcb->remote_ip,remote);
  pcb->local_port=50000; pcb->remote_port=40000;
  pcb->mss=1460; pcb->snd_wnd=pcb->cwnd=12000; pcb->ssthresh=12000;
  pcb->snd_nxt=pcb->snd_lbb=pcb->lastack=pcb->snd_wl2=base;
  pcb->rcv_nxt=2000; pcb->rcv_wnd=TCP_WND; pcb->rcv_ann_right_edge=2000+TCP_WND;
  pcb->sa=0; pcb->sv=4; pcb->rto=4; pcb->rttest=0;
  TCP_REG(&tcp_active_pcbs,pcb);
  outputs=0; now=0; fail_output=0;
  for(unsigned i=0;i<6;i++) {
    assert(tcp_write(pcb,bytes,lengths[i],TCP_WRITE_FLAG_COPY)==ERR_OK);
    assert(tcp_output(pcb)==ERR_OK);
  }
  assert(outputs==6); pcb->rttest=0;
  return pcb;
}
static void duplicates(struct netif *n,struct tcp_pcb *pcb,u32_t value,unsigned count) {
  for(unsigned i=0;i<count;i++) ack(n,pcb,value);
}
static void run(struct netif *n,u32_t base) {
  struct tcp_pcb *pcb=connection(base);
  u32_t partials[]={base+641,base+738,base+1382};
  duplicates(n,pcb,base,3);
  assert(outputs==7 && (pcb->flags&TF_INFR));
  for(unsigned i=0;i<3;i++) {
    unsigned before=outputs;
    pcb->rttest=0; ack(n,pcb,partials[i]);
#if LWIP_TCP_PARTIAL_ACK_RECOVERY
    assert(outputs==before+1 && last_output_seq==partials[i]);
    assert(pcb->flags&TF_INFR);
#else
    assert(outputs==before && !(pcb->flags&TF_INFR));
    if(i<2) duplicates(n,pcb,partials[i],3);
#endif
  }
  unsigned before=outputs;
  duplicates(n,pcb,partials[2],2);
  assert(outputs==before);
#if LWIP_TCP_PARTIAL_ACK_RECOVERY
  ack(n,pcb,base+2679);
  assert(!(pcb->flags&TF_INFR));
  assert(!pcb->unacked && !pcb->unsent && pcb->snd_buf==TCP_SND_BUF);
  puts("PASS four-gap recovery finished without a timer, including sequence wrap");
#else
  for(unsigned i=1;i<=4;i++) {
    now=i*500; tcp_slowtmr();
    if(i<4) assert(outputs==before);
  }
  assert(outputs>before);
  puts("PASS baseline requires RTO for final gap");
#endif
  tcp_abort(pcb);
}
static void normal_and_single_duplicate(struct netif *n) {
  struct tcp_pcb *pcb=connection(1000);
  ack(n,pcb,1641); assert(outputs==6 && !(pcb->flags&TF_INFR));
  ack(n,pcb,3679); assert(outputs==6 && pcb->snd_buf==TCP_SND_BUF);
  tcp_abort(pcb);
  pcb=connection(1000);
  duplicates(n,pcb,1000,2);
  assert(outputs==6 && !(pcb->flags&TF_INFR));
  ack(n,pcb,3679);
  assert(outputs==6 && pcb->snd_buf==TCP_SND_BUF);
  tcp_abort(pcb);
  puts("PASS reordered data acknowledged before threshold causes no retransmission");
  pcb=connection(1000);
  duplicates(n,pcb,1000,1); assert(outputs==6 && !(pcb->flags&TF_INFR));
  for(unsigned i=0;i<4;i++) tcp_slowtmr();
  assert(outputs>6 && (pcb->flags&TF_RTO));
  tcp_abort(pcb);
  puts("PASS normal ACK and initial single-duplicate RTO behavior preserved");
}
#if LWIP_TCP_PARTIAL_ACK_RECOVERY
static void failed_output_and_timeout(struct netif *n) {
  struct tcp_pcb *pcb=connection(1000);
  duplicates(n,pcb,1000,3);
  fail_output=1; ack(n,pcb,1641);
  assert(pcb->unsent && lwip_ntohl(pcb->unsent->tcphdr->seqno)==1641);
  assert(pcb->snd_buf==TCP_SND_BUF-2038);
  fail_output=0; assert(tcp_output(pcb)==ERR_OK);
  assert(pcb->unacked && lwip_ntohl(pcb->unacked->tcphdr->seqno)==1641);
  for(unsigned i=0;i<4;i++) tcp_slowtmr();
  assert((pcb->flags&TF_RTO) && !(pcb->flags&TF_INFR));
  tcp_abort(pcb);
  puts("PASS failed output retained data and RTO abandoned fast recovery");
}
static void recovery_boundary(struct netif *n) {
  struct tcp_pcb *pcb=connection(1000); char bytes[100]={0};
  duplicates(n,pcb,1000,3);
  assert(meshpn_recovery.recovery_end==3679);
  assert(tcp_write(pcb,bytes,100,TCP_WRITE_FLAG_COPY)==ERR_OK);
  assert(tcp_output(pcb)==ERR_OK);
  assert(pcb->snd_nxt==3779 && meshpn_recovery.recovery_end==3679);
  ack(n,pcb,3679);
  assert(!(pcb->flags&TF_INFR));
  assert(pcb->unacked && pcb->unacked->len==100);
  ack(n,pcb,3779); assert(pcb->snd_buf==TCP_SND_BUF);
  tcp_abort(pcb);
  puts("PASS full recovery uses entry boundary, not later new data");
}
static void partial_timer_and_busy_segment(struct netif *n) {
  struct tcp_pcb *pcb=connection(1000);
  duplicates(n,pcb,1000,3);
  pcb->rtime=2;
  ack(n,pcb,1641);
  assert(pcb->rtime==0 && meshpn_recovery.partial_seen);
  pcb->rtime=2;
  ack(n,pcb,1738);
  assert(pcb->rtime==2);
  tcp_abort(pcb);

  pcb=connection(1000);
  duplicates(n,pcb,1000,3);
  struct pbuf *held=pcb->unacked->next->p;
  pbuf_ref(held);
  unsigned before=outputs;
  ack(n,pcb,1641);
  assert(outputs==before && pcb->unacked->p==held);
  assert(pcb->snd_buf==TCP_SND_BUF-2038);
  pbuf_free(held);
  for(unsigned i=0;i<4;i++) tcp_slowtmr();
  assert(outputs>before && !(pcb->flags&TF_INFR));
  tcp_abort(pcb);
  puts("PASS later partial ACKs preserve timer and busy segments retain RTO fallback");
}
#endif
static void sack_window_and_data(struct netif *n,unsigned payload) {
  struct tcp_pcb *pcb=connection(1000);memset(&meshpn_recovery,0,sizeof(meshpn_recovery));
  pcb->flags|=TF_SACK;
  unsigned rights[]={1738,1738,2382,2479};
  for(unsigned k=0;k<4;k++){
    struct pbuf *p=pbuf_alloc(PBUF_RAW,52+payload,PBUF_RAM);assert(p);
    memset(p->payload,0,52+payload);struct ip_hdr *ip=p->payload;
    struct tcp_hdr *t=(struct tcp_hdr *)((uint8_t*)p->payload+20);
    t->src=lwip_htons(40000);t->dest=lwip_htons(50000);t->seqno=lwip_htonl(pcb->rcv_nxt);
    t->ackno=lwip_htonl(1000);TCPH_HDRLEN_FLAGS_SET(t,8,TCP_ACK);t->wnd=lwip_htons(12001+k);
    uint8_t *o=(uint8_t*)(t+1);o[0]=1;o[1]=1;o[2]=5;o[3]=10;
    uint32_t left=lwip_htonl(1641),right=lwip_htonl(rights[k]);memcpy(o+4,&left,4);memcpy(o+8,&right,4);
    assert(pbuf_remove_header(p,20)==0);t->chksum=inet_chksum_pseudo(p,IP_PROTO_TCP,32+payload,&remote,&local);
    assert(pbuf_add_header(p,20)==0);IPH_VHL_SET(ip,4,5);IPH_LEN_SET(ip,lwip_htons(52+payload));
    IPH_TTL_SET(ip,64);IPH_PROTO_SET(ip,IP_PROTO_TCP);ip4_addr_copy(ip->src,remote);ip4_addr_copy(ip->dest,local);
    IPH_CHKSUM_SET(ip,inet_chksum(ip,20));unsigned before=outputs;assert(ip4_input(p,n)==ERR_OK);
#if LWIP_TCP_PARTIAL_ACK_RECOVERY
    if(k<3)assert(!(pcb->flags&TF_INFR));else assert((pcb->flags&TF_INFR)&&last_output_seq==1000&&outputs>before);
#else
    (void)before;assert(!(pcb->flags&TF_INFR));
#endif
  }
  tcp_abort(pcb);puts("PASS new SACK evidence with changing windows/payload; repeated SACK does not advance threshold");
}
#if MESHPN_EXPERIMENT_BURST
static void put32(uint8_t *p,uint32_t value)
{ value=lwip_htonl(value);memcpy(p,&value,4); }
static void sack_ack(struct netif *n,struct tcp_pcb *pcb,uint32_t left,uint32_t right)
{
  struct pbuf *p=pbuf_alloc(PBUF_RAW,52,PBUF_RAM);assert(p);memset(p->payload,0,52);
  struct ip_hdr *ip=p->payload;struct tcp_hdr *t=(void*)((uint8_t*)p->payload+20);
  t->src=lwip_htons(40000);t->dest=lwip_htons(pcb->local_port);t->seqno=lwip_htonl(pcb->rcv_nxt);
  t->ackno=lwip_htonl(pcb->lastack);TCPH_HDRLEN_FLAGS_SET(t,8,TCP_ACK);t->wnd=lwip_htons(24000);
  uint8_t *o=(void*)(t+1);o[0]=1;o[1]=1;o[2]=5;o[3]=10;put32(o+4,left);put32(o+8,right);
  assert(pbuf_remove_header(p,20)==0);t->chksum=inet_chksum_pseudo(p,6,32,&remote,&local);
  assert(pbuf_add_header(p,20)==0);IPH_VHL_SET(ip,4,5);IPH_LEN_SET(ip,lwip_htons(52));
  IPH_TTL_SET(ip,64);IPH_PROTO_SET(ip,6);ip4_addr_copy(ip->src,remote);ip4_addr_copy(ip->dest,local);
  IPH_CHKSUM_SET(ip,inet_chksum(ip,20));assert(ip4_input(p,n)==ERR_OK);
}
static void burst_recovery(struct netif *n,uint32_t base)
{
  struct tcp_pcb *pcb=connection(base);ack(n,pcb,pcb->snd_nxt);
  base=pcb->snd_nxt;memset(&meshpn_recovery,0,sizeof(meshpn_recovery));memset(&meshpn_burst,0,sizeof(meshpn_burst));
  pcb->flags|=TF_SACK;pcb->mss=600;pcb->cwnd=pcb->snd_wnd=24000;
  char bytes[600]={0};
  for(unsigned i=0;i<24;i++){assert(tcp_write(pcb,bytes,sizeof(bytes),TCP_WRITE_FLAG_COPY)==ERR_OK);assert(tcp_output(pcb)==ERR_OK);}
  unsigned before=outputs,qlen=pcb->snd_queuelen;tcpwnd_size_t free_before=pcb->snd_buf;
  sack_ack(n,pcb,base+3600,base+13200);
  sack_ack(n,pcb,base+3600,base+13800);
  sack_ack(n,pcb,base+3600,base+14400);
  assert(pcb->flags&TF_INFR);
  for(unsigned i=0;i<4;i++)sack_ack(n,pcb,base+3600,base+14400);
  assert(outputs==before+6); /* six gaps repaired before any cumulative ACK/timer */
  assert(pcb->snd_buf==free_before && pcb->snd_queuelen==qlen); /* SACK is advisory */
  assert(meshpn_burst.repairs==6 && pcb->snd_nxt==base+14400);
  before=outputs;for(unsigned i=0;i<4;i++)sack_ack(n,pcb,base+3600,base+14400);
  assert(outputs==before); /* repeated reports must not repeat repair */
  ack(n,pcb,base+14400);assert(!(pcb->flags&TF_INFR) && !pcb->unacked);
  tcp_abort(pcb);puts("PASS six-segment burst repaired without timer; no duplicate repair or premature free");
}
static void burst_bounds(struct netif *n)
{
  struct tcp_pcb *pcb=connection(1000);pcb->flags|=TF_SACK;
  memset(&meshpn_burst,0,sizeof(meshpn_burst));
  uint8_t options[20]={1,1,5,18};put32(options+4,1641);put32(options+8,2382);put32(options+12,1738);put32(options+16,2479);
  for(unsigned split=0;split<=20;split++) {
    meshpn_sack_update(options,split,options+split,20,1000,3679);
    assert(meshpn_burst.count==1 && meshpn_burst.ranges[0].left==1641 && meshpn_burst.ranges[0].right==2479);
  }
  put32(options+16,4000);meshpn_sack_update(options,20,NULL,20,1000,3679);assert(!meshpn_burst.count);
  options[3]=19;meshpn_sack_update(options,20,NULL,20,1000,3679);assert(!meshpn_burst.count);
  meshpn_sack_update(NULL,1,NULL,20,1000,3679);assert(!meshpn_burst.count);
  pcb->flags|=TF_INFR;meshpn_recovery.recovery_end=3679;
  meshpn_burst.count=1;meshpn_burst.ranges[0]=(meshpn_sack_range_t){1641,3679};pcb->mss=600;
  assert(meshvpn_vpn_sack_candidate(pcb,pcb->unacked));
  pcb->cwnd=0;assert(!meshvpn_vpn_sack_candidate(pcb,pcb->unacked));pcb->cwnd=12000;
  pcb->snd_wnd=0;assert(!meshvpn_vpn_sack_candidate(pcb,pcb->unacked));pcb->snd_wnd=12000;
  pcb->local_port++;assert(!meshvpn_vpn_sack_candidate(pcb,pcb->unacked));pcb->local_port--;
  unsigned before=outputs;fail_output=1;assert(tcp_output(pcb)==ERR_OK);assert(outputs==before+1 && !meshpn_burst.repairs);
  fail_output=0;pbuf_ref(pcb->unacked->p);before=outputs;assert(tcp_output(pcb)==ERR_OK);assert(outputs==before);
  pbuf_free(pcb->unacked->p);assert(tcp_output(pcb)==ERR_OK);assert(meshpn_burst.repairs==1);
  meshvpn_vpn_recovery_timeout(pcb);assert(!meshpn_burst.count && !meshpn_burst.repairs && !(pcb->flags&TF_INFR));
  meshpn_burst.count=meshpn_burst.repairs=1;uint32_t old_peer=remote.addr;
  remote.addr^=lwip_htonl(4);ip_addr_copy_from_ip4(pcb->remote_ip,remote);
  assert(meshpn_owned_tcp(pcb) && !meshpn_burst.count && !meshpn_burst.repairs);
  remote.addr=old_peer;ip_addr_copy_from_ip4(pcb->remote_ip,remote);
  tcp_abort(pcb);puts("PASS burst parser, wrap-safe limits, cwnd/window, ownership, failed output, busy pbuf and RTO fallback");
}
#endif
int main(void) {
  struct netif n = {0}; ip4_addr_t mask,gateway;
  lwip_init(); IP4_ADDR(&local,192,168,1,2); IP4_ADDR(&remote,192,168,1,3);
  IP4_ADDR(&mask,255,255,255,0); IP4_ADDR(&gateway,192,168,1,1);
  assert(netif_add(&n,&local,&mask,&gateway,NULL,setup,ip4_input));
  netif_set_default(&n); netif_set_up(&n); netif_set_link_up(&n);
  sack_window_and_data(&n,0);sack_window_and_data(&n,1);
  run(&n,1000); run(&n,0xfffffc00U); normal_and_single_duplicate(&n);
#if LWIP_TCP_PARTIAL_ACK_RECOVERY
  failed_output_and_timeout(&n); recovery_boundary(&n); partial_timer_and_busy_segment(&n);
#endif
#if MESHPN_EXPERIMENT_BURST
  burst_recovery(&n,1000);burst_recovery(&n,0xffffe000U);burst_bounds(&n);
#endif
  return 0;
}
