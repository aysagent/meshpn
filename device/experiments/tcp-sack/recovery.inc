#include "evidence.h"
static struct {
    uint32_t peer, ack, right, recovery_end;
    uint16_t remote, local;
    bool partial_seen;
} meshpn_recovery;
static bool meshpn_owned_tcp(struct tcp_pcb *pcb)
{
    uint32_t peer; uint16_t remote,local;
    if(!meshvpn_vpn_tcp_peer(&peer,&remote,&local) || !IP_IS_V4(&pcb->remote_ip) ||
       ip_2_ip4(&pcb->remote_ip)->addr!=peer || pcb->local_port!=local || pcb->remote_port!=remote)return false;
    if(meshpn_recovery.peer!=peer || meshpn_recovery.remote!=remote || meshpn_recovery.local!=local){
        memset(&meshpn_recovery,0,sizeof(meshpn_recovery));meshpn_recovery.peer=peer;
        meshpn_recovery.remote=remote;meshpn_recovery.local=local;
    }
    return true;
}
int meshvpn_vpn_sack_dupack(struct tcp_pcb *pcb,const struct tcp_hdr *hdr,
                          unsigned n,unsigned n1,const void *second,u32_t ack,unsigned flags)
{
    if(pcb->state!=ESTABLISHED || !(flags&TCP_ACK) || (flags&(TCP_SYN|TCP_FIN|TCP_RST)) ||
       !(pcb->flags&TF_SACK) || !pcb->unacked || pcb->rtime<0 || ack!=pcb->lastack || !meshpn_owned_tcp(pcb))return 0;
    if(meshpn_recovery.ack!=ack){meshpn_recovery.ack=ack;meshpn_recovery.right=ack;}
    return meshpn_sack_evidence((const uint8_t *)(hdr+1),n1,second,n,ack,pcb->snd_nxt,&meshpn_recovery.right);
}
void meshvpn_vpn_recovery_enter(struct tcp_pcb *pcb)
{
    if(!meshpn_owned_tcp(pcb))return;
    meshpn_recovery.recovery_end=pcb->snd_nxt;meshpn_recovery.partial_seen=false;
}
int meshvpn_vpn_partial_ack(struct tcp_pcb *pcb,u32_t ack)
{
    if(!(pcb->flags&TF_INFR) || !meshpn_owned_tcp(pcb) || !TCP_SEQ_LT(ack,meshpn_recovery.recovery_end))return 0;
    tcpwnd_size_t newly=(tcpwnd_size_t)(ack-pcb->lastack);
    int result=meshpn_recovery.partial_seen?2:1;meshpn_recovery.partial_seen=true;
    pcb->cwnd=pcb->cwnd>newly?pcb->cwnd-newly:0;
    if(newly>=pcb->mss)TCP_WND_INC(pcb->cwnd,pcb->mss);
    pcb->cwnd=LWIP_MAX(pcb->cwnd,pcb->mss);
    return result;
}
void meshvpn_vpn_recovery_timeout(struct tcp_pcb *pcb)
{
    if(meshpn_owned_tcp(pcb))tcp_clear_flags(pcb,TF_INFR);
}
