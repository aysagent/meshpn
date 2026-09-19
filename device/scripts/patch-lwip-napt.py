#!/usr/bin/env python3
"""Generate a build-only lwIP NAPT source with safe TCP SYN retransmits.

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
    return source.replace(ANCHOR, REPLACEMENT, 1)


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
