"""Opt-in build-local SACK gap repair, after patch.py + partial.py."""
from pathlib import Path
import sys
p=Path(sys.argv[1]);out=Path(sys.argv[2]);s=p.read_text()
def swap(a,b):
 global s
 if s.count(a)!=1:raise RuntimeError('Unexpected '+p.name+' anchor: '+a)
 s=s.replace(a,b)
if p.name=='tcp_in.c':
 swap('if(meshpn_partial) tcp_rexmit(pcb);','if(meshpn_partial) meshvpn_vpn_partial_retransmit(pcb);')
 swap('extern int meshvpn_vpn_partial_ack(struct tcp_pcb *,u32_t);',
      'extern void meshvpn_vpn_partial_retransmit(struct tcp_pcb *);\nextern int meshvpn_vpn_partial_ack(struct tcp_pcb *,u32_t);')
elif p.name=='tcp_out.c':
 # Bound repairs per output call; normal TCP input completion calls output.
 swap('err_t\ntcp_output(struct tcp_pcb *pcb)', '''static int tcp_output_segment_busy(const struct tcp_seg *);
extern int meshvpn_vpn_sack_candidate(struct tcp_pcb *,const struct tcp_seg *);
extern void meshvpn_vpn_sack_sent(struct tcp_pcb *,const struct tcp_seg *);
static void meshpn_sack_output(struct tcp_pcb *pcb)
{
  unsigned count=0;
  if(pcb->state!=ESTABLISHED || !(pcb->flags&TF_INFR) || !(pcb->flags&TF_SACK) || (pcb->flags&TF_RTO))return;
  for(struct tcp_seg *seg=pcb->unacked;seg && count<2;seg=seg->next) {
    if(!meshvpn_vpn_sack_candidate(pcb,seg) || tcp_output_segment_busy(seg))continue;
    struct netif *netif=tcp_route(pcb,&pcb->local_ip,&pcb->remote_ip);
    if(!netif)return;
    err_t err=tcp_output_segment(seg,pcb,netif);
    pcb->rttest=0; /* retransmitted data is not an RTT sample */
    if(err!=ERR_OK)return; /* original queue/timer remain intact */
    meshvpn_vpn_sack_sent(pcb,seg);
    MIB2_STATS_INC(mib2.tcpretranssegs);
    count++;
  }
}
err_t
tcp_output(struct tcp_pcb *pcb)''')
 swap('  wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);',
      '  meshpn_sack_output(pcb);\n  wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);')
else:raise RuntimeError(p.name)
if not out.exists() or out.read_text()!=s:out.write_text(s)
