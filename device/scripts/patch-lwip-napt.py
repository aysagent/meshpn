#!/usr/bin/env python3
"""Generate a build-only lwIP NAPT source with safe SYN retransmits and bidirectional ICMP errors.

ESP-IDF 5.4.1 refreshes an existing TCP mapping by calling ip_napt_free().
Once a SYN-ACK has been observed, that helper deliberately emits forged-source
RST packets to both peers.  A normal retransmitted SYN therefore destroys the
connection it is trying to establish.  Preserve an exact destination mapping
without evicting it; genuinely reusing the same source port for another peer
keeps the upstream behaviour.
"""

import argparse
from pathlib import Path


ANCHOR = """  struct ip_napt_entry *t = ip_napt_find(proto, src, sport, 0, 0);
  if (t) {
    t->last = sys_now();
    t->dest = dest;
    t->dport = dport;
"""

REPLACEMENT = """  struct ip_napt_entry *t = ip_napt_find(proto, src, sport, 0, 0);
  if (t && t->dest == dest && t->dport == dport) {
    /* A repeated SYN is a retransmission of this mapping, not an eviction.
     * ip_napt_free() sends RST to both peers after SYN-ACK and must not run. */
    t->last = sys_now();
    return t->mport;
  }
  if (t) {
    t->last = sys_now();
    t->dest = dest;
    t->dport = dport;
"""


def patch(source: str) -> str:
    if source.count(ANCHOR) != 1:
        raise ValueError(
            "Expected exactly one ESP-IDF 5.4.1 ip_napt_add anchor; "
            "re-audit the NAPT patch for this IDF version"
        )
    if source.count("ip_napt_send_rst(t->dest") != 1:
        raise ValueError("Expected ESP-IDF NAPT eviction RST implementation")
    source = source.replace(ANCHOR, REPLACEMENT, 1)
    recv = "void\nip_napt_recv(struct pbuf *p, struct ip_hdr *iphdr)"
    if source.count(recv) != 1:
        raise ValueError("Expected one lwIP NAPT receive implementation")
    helper = Path(__file__).with_name("lwip-napt-icmp.inc").read_text()
    source = source.replace(recv, helper + "\n" + recv, 1)
    anchor = "  if (ip_napt_max == 0) return;"
    if source.count(anchor) != 1:
        raise ValueError("Expected one lwIP NAPT receive guard")
    source = source.replace(anchor, anchor + "\n\n#if LWIP_ICMP\n"
                          "  if (IPH_PROTO(iphdr) == IP_PROTO_ICMP && meshpn_napt_icmp_error(p, iphdr)) return;\n"
                          "#endif", 1)
    forward = "ip_napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp)"
    if source.count(forward) != 1:
        raise ValueError("Expected one lwIP NAPT forwarding implementation")
    start = source.index(forward)
    tail = source[start:]
    anchor = "  if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {"
    if tail.count(anchor) != 1:
        raise ValueError("Expected one forwarding ICMP branch")
    tail = tail.replace(anchor, anchor + """
    u8_t type;
    if (pbuf_copy_partial(p, &type, 1, IPH_HL(iphdr) * 4) != 1) return ERR_VAL;
    if (type == 3 || type == 11 || type == 12) {
      u32_t external = ip_2_ip4(&outp->ip_addr)->addr;
      /* Unmapped/malformed ICMP errors must not leak a LAN source address
       * into the tunnel (native exit rejects it and closes the session). */
      return meshpn_napt_icmp_error_map(p, iphdr, &external) ? ERR_OK : ERR_RTE;
    }
""", 1)
    return source[:start] + tail


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite ESP-IDF")
    result = patch(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != result:
        args.output.write_text(result)


if __name__ == "__main__":
    main()
