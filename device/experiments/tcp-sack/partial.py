from pathlib import Path
import sys
source=Path(sys.argv[1]);out=Path(sys.argv[2]);kind=source.name;s=source.read_text()
def swap(a,b):
 global s
 if s.count(a)!=1:raise RuntimeError('Unexpected '+kind+' anchor: '+a)
 s=s.replace(a,b)
if kind=='tcp_in.c':
 swap('      tcpwnd_size_t acked;','      tcpwnd_size_t acked;\n      int meshpn_partial=meshvpn_vpn_partial_ack(pcb,ackno);')
 swap('      if (pcb->flags & TF_INFR) {','      if ((pcb->flags & TF_INFR) && !meshpn_partial) {')
 swap('      if (pcb->state >= ESTABLISHED) {','      if (!meshpn_partial && pcb->state >= ESTABLISHED) {')
 swap('      } else {\n        pcb->rtime = 0;\n      }','      } else if(meshpn_partial!=2) {\n        pcb->rtime = 0;\n      }')
 swap('      /* End of ACK for new data processing. */','      if(meshpn_partial) tcp_rexmit(pcb);\n      /* End of ACK for new data processing. */')
 swap('static void\ntcp_receive(struct tcp_pcb *pcb)','extern int meshvpn_vpn_partial_ack(struct tcp_pcb *,u32_t);\nstatic void\ntcp_receive(struct tcp_pcb *pcb)')
elif kind=='tcp_out.c':
 swap('      tcp_set_flags(pcb, TF_INFR);','      meshvpn_vpn_recovery_enter(pcb);\n      tcp_set_flags(pcb, TF_INFR);')
 swap('void\ntcp_rexmit_fast(struct tcp_pcb *pcb)','extern void meshvpn_vpn_recovery_enter(struct tcp_pcb *);\nvoid\ntcp_rexmit_fast(struct tcp_pcb *pcb)')
elif kind=='tcp.c':
 swap('          if ((tcp_rexmit_rto_prepare(pcb) == ERR_OK) || ((pcb->unacked == NULL) && (pcb->unsent != NULL))) {','          if ((tcp_rexmit_rto_prepare(pcb) == ERR_OK) || ((pcb->unacked == NULL) && (pcb->unsent != NULL))) {\n            meshvpn_vpn_recovery_timeout(pcb);')
 swap('void\ntcp_slowtmr(void)','extern void meshvpn_vpn_recovery_timeout(struct tcp_pcb *);\nvoid\ntcp_slowtmr(void)')
else:raise RuntimeError(kind)
out.parent.mkdir(parents=True,exist_ok=True)
if not out.exists() or out.read_text()!=s:out.write_text(s)
