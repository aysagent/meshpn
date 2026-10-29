#!/usr/bin/env python3
"""Failure-only hooks in pinned IDF sources; keep SDK ownership/return values."""
import argparse
from pathlib import Path


def patch(source, kind):
    def one(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError('IDF TX source changed; re-audit ' + kind)
        source = source.replace(old, new, 1)
    if kind == 'wlanif':
        one('    struct pbuf *q = p;',
            "    unsigned meshpn_ifx = netif->name[0] == 's' && netif->name[1] == 't' ? 0 :\n"
            "                          netif->name[0] == 'a' && netif->name[1] == 'p' ? 1 : 2;\n"
            '    struct pbuf *q = p;')
        one('        } else {\n            return ERR_MEM;\n',
            '        } else {\n            meshvpn_tx_failure(1, meshpn_ifx, p->tot_len, ERR_MEM);\n            return ERR_MEM;\n')
        one('    /* translate netif_ret to lwip supported return value */',
            '    if (netif_ret != ESP_OK)\n'
            '        meshvpn_tx_failure(netif_ret == ESP_ERR_NO_MEM ? 2 : 3, meshpn_ifx, p->tot_len, netif_ret);\n'
            '    /* translate netif_ret to lwip supported return value */')
    elif kind == 'sockets':
        one('  if (netbuf_alloc(&buf, short_size) == NULL) {\n    err = ERR_MEM;',
            '  if (netbuf_alloc(&buf, short_size) == NULL) {\n'
            '    meshvpn_tx_failure(0, 2, short_size, ERR_MEM);\n    err = ERR_MEM;')
    else:
        raise ValueError('Unknown TX source')
    return 'extern void meshvpn_tx_failure(unsigned, unsigned, unsigned, int);\n' + source


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=['wlanif', 'sockets'])
    p.add_argument('source', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args()
    if a.source.resolve() == a.output.resolve(): p.error('Do not modify SDK sources')
    result = patch(a.source.read_text(), a.kind)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    if not a.output.exists() or a.output.read_text() != result: a.output.write_text(result)
