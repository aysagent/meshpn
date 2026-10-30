/* Opt-in, owned-socket experiment: repair fully missing segments covered by
 * strong SACK evidence, keeping all bytes in lwIP's retransmission queue.
 * This is NOT a complete RFC 6675 sender. Missing/reneged SACK evidence and
 * exhausted fixed storage fall back to NewReno/RTO, never freeing data early.
 * Called exclusively on the lwIP core. Sequence intervals are half-open. */
typedef struct { uint32_t left, right; } meshpn_sack_range_t;
static struct {
    meshpn_sack_range_t ranges[4], repaired[128];
    unsigned count, repairs;
} meshpn_burst;
static void meshpn_burst_reset(void) { memset(&meshpn_burst,0,sizeof(meshpn_burst)); }

static uint32_t meshpn_sack_u32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

static void meshpn_sack_update(const uint8_t *one, unsigned n1, const void *two,
                              unsigned n, uint32_t ack, uint32_t sent)
{
    uint8_t options[40]; meshpn_sack_range_t ranges[4]; unsigned count=0; bool sack_seen=false;
    meshpn_burst.count=0;
    if(n>40 || n1>n || (n1&&!one) || (n>n1&&!two))return;
    if(n1)memcpy(options,one,n1);
    if(n>n1)memcpy(options+n1,two,n-n1);
    for(unsigned at=0;at<n;) {
        unsigned kind=options[at]; if(!kind)break;
        if(kind==1){at++;continue;}
        if(at+1>=n || options[at+1]<2 || options[at+1]>n-at)return;
        unsigned size=options[at+1];
        if(kind==5) {
            if(sack_seen || size<10 || (size-2)%8)return;
            sack_seen=true;
            for(unsigned i=at+2;i<at+size;i+=8) {
                uint32_t l=meshpn_sack_u32(options+i),r=meshpn_sack_u32(options+i+4);
                if(!TCP_SEQ_LT(l,r) || TCP_SEQ_GT(r,sent))return;
                if(TCP_SEQ_LEQ(l,ack))continue; /* DSACK is not loss evidence. */
                if(count==4)return;
                ranges[count++]=(meshpn_sack_range_t){l,r};
            }
        }
        at+=size;
    }
    /* Sorting and merging prevent overlapping reports from inflating evidence. */
    for(unsigned i=1;i<count;i++)for(unsigned j=i;j && TCP_SEQ_LT(ranges[j].left,ranges[j-1].left);j--) {
        meshpn_sack_range_t swap=ranges[j];ranges[j]=ranges[j-1];ranges[j-1]=swap;
    }
    for(unsigned i=0;i<count;i++) {
        unsigned k=meshpn_burst.count;
        if(k && TCP_SEQ_LEQ(ranges[i].left,meshpn_burst.ranges[k-1].right)) {
            if(TCP_SEQ_GT(ranges[i].right,meshpn_burst.ranges[k-1].right))meshpn_burst.ranges[k-1].right=ranges[i].right;
        } else meshpn_burst.ranges[meshpn_burst.count++]=ranges[i];
    }
}
static bool meshpn_range_covers(meshpn_sack_range_t r,uint32_t l,uint32_t end)
{ return TCP_SEQ_LEQ(r.left,l) && TCP_SEQ_GEQ(r.right,end); }
static bool meshpn_sack_repaired(uint32_t l,uint32_t end)
{
    for(unsigned i=0;i<meshpn_burst.repairs;i++)if(meshpn_range_covers(meshpn_burst.repaired[i],l,end))return true;
    return false;
}
static void meshpn_sack_record(const struct tcp_seg *seg)
{
    if(!seg || !seg->len || meshpn_burst.repairs==128)return;
    uint32_t l=lwip_ntohl(seg->tcphdr->seqno),end=l+seg->len;
    if(!meshpn_sack_repaired(l,end))meshpn_burst.repaired[meshpn_burst.repairs++]=(meshpn_sack_range_t){l,end};
}
static bool meshpn_sack_covered(uint32_t l,uint32_t end)
{
    for(unsigned i=0;i<meshpn_burst.count;i++)if(meshpn_range_covers(meshpn_burst.ranges[i],l,end))return true;
    return false;
}
/* Conservative pipe estimate: even lost original data stays counted, plus
 * repaired data a second time, until it is cumulatively ACKed or fully SACKed.
 * Hence this cannot open more credit than RFC 6675 SetPipe would allow. */
static uint32_t meshpn_sack_pipe(struct tcp_pcb *pcb)
{
    uint32_t pipe=0;
    for(unsigned list=0;list<2;list++)for(struct tcp_seg *s=list?pcb->unsent:pcb->unacked;s;s=s->next) {
        uint32_t l=lwip_ntohl(s->tcphdr->seqno),end=l+s->len;
        /* lwIP moves the first fast repair to unsent before calling output.
         * Count that in-flight range too; brand-new unsent data is not pipe. */
        if(TCP_SEQ_GEQ(l,pcb->snd_nxt))continue;
        if(meshpn_sack_covered(l,end))continue;
        pipe+=s->len;
        if(meshpn_sack_repaired(l,end))pipe+=s->len;
    }
    return pipe;
}
int meshvpn_vpn_sack_candidate(struct tcp_pcb *pcb,const struct tcp_seg *seg)
{
    if(!meshpn_owned_tcp(pcb) || pcb->state!=ESTABLISHED || !(pcb->flags&TF_INFR) || !(pcb->flags&TF_SACK) ||
       (pcb->flags&TF_RTO) || !meshpn_burst.count || meshpn_burst.repairs==128 ||
       !seg->len || (TCPH_FLAGS(seg->tcphdr)&(TCP_SYN|TCP_FIN|TCP_RST)))return 0;
    uint32_t l=lwip_ntohl(seg->tcphdr->seqno),end=l+seg->len,higher=0;
    if(TCP_SEQ_LT(l,pcb->lastack) || TCP_SEQ_GT(end,meshpn_recovery.recovery_end) ||
       TCP_SEQ_GT(end,pcb->lastack+pcb->snd_wnd) || meshpn_sack_repaired(l,end))return 0;
    for(unsigned i=0;i<meshpn_burst.count;i++) {
        meshpn_sack_range_t r=meshpn_burst.ranges[i];
        if(TCP_SEQ_LT(r.left,end) && TCP_SEQ_GT(r.right,l))return 0; /* no partial overlaps */
        if(TCP_SEQ_GEQ(r.left,end))higher+=r.right-r.left;
    }
    if(higher<=2U*pcb->mss)return 0;
    uint32_t pipe=meshpn_sack_pipe(pcb);
    return pipe<=pcb->cwnd && seg->len<=pcb->cwnd-pipe;
}
void meshvpn_vpn_sack_sent(struct tcp_pcb *pcb,const struct tcp_seg *seg)
{ if(meshpn_owned_tcp(pcb))meshpn_sack_record(seg); }
void meshvpn_vpn_partial_retransmit(struct tcp_pcb *pcb)
{
    if(!meshpn_owned_tcp(pcb) || !pcb->unacked)return;
    struct tcp_seg *seg=pcb->unacked;
    uint32_t l=lwip_ntohl(seg->tcphdr->seqno);
    if(meshpn_sack_repaired(l,l+seg->len))return;
    if(tcp_rexmit(pcb)==ERR_OK)meshpn_sack_record(seg);
}
