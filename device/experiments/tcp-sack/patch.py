from pathlib import Path
import sys
src=Path(sys.argv[1]);out=Path(sys.argv[2]);s=src.read_text()
replacements={
'  /* Clause 1 */\n':'  /* Clause 1 */\n',
'    /* Clause 1 */\n':'    /* RFC 5681 permits new SACK information as duplicate-ACK evidence. */\n    const int meshpn_new_sack = meshvpn_vpn_sack_dupack(pcb, tcphdr, tcphdr_optlen, tcphdr_opt1len, tcphdr_opt2, ackno, flags);\n    /* Clause 1 */\n',
'      if (tcplen == 0) {':'      if (tcplen == 0 || meshpn_new_sack) {',
'        if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge) {':'        if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge || meshpn_new_sack) {'}
for a,b in list(replacements.items())[1:]:
 if s.count(a)!=1:raise RuntimeError('Unrecognized tcp_in source anchor: '+a)
 s=s.replace(a,b)
a='static void\ntcp_receive(struct tcp_pcb *pcb)'
if s.count(a)!=1:raise RuntimeError('tcp_receive anchor')
s=s.replace(a,'extern int meshvpn_vpn_sack_dupack(struct tcp_pcb *, const struct tcp_hdr *, unsigned, unsigned, const void *, u32_t, unsigned);\n\n'+a)
out.parent.mkdir(parents=True,exist_ok=True)
if not out.exists() or out.read_text()!=s:out.write_text(s)
