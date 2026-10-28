#!/usr/bin/env python3
"""Observe pinned IDF wlanif RX ownership branches without changing returns."""
import argparse
from pathlib import Path


def patch(source):
    def one(old, new, count=1):
        nonlocal source
        if source.count(old) != count:
            raise ValueError('IDF wlanif RX changed; re-audit instrumentation/ownership')
        source = source.replace(old, new)
    one('    struct netif * netif = h;\n',
        '    struct netif * netif = h;\n'
        "    unsigned meshpn_ifx = netif->name[0] == 's' && netif->name[1] == 't' ? 0 :\n"
        "                          netif->name[0] == 'a' && netif->name[1] == 'p' ? 1 : 2;\n"
        '    meshvpn_hosted_rx_netif(meshpn_ifx, 0, len);\n'
        '    meshvpn_ap_probe_arp(meshpn_ifx, 0, buffer, len);\n')
    one('    if(unlikely(!buffer || !netif_is_up(netif))) {\n',
        '    if(unlikely(!buffer || !netif_is_up(netif))) {\n'
        '        meshvpn_hosted_rx_netif(meshpn_ifx, 1, len);\n')
    one('    if (p == NULL) {\n', '    if (p == NULL) {\n'
        '        meshvpn_hosted_rx_netif(meshpn_ifx, 2, len);\n', 2)
    one('        pbuf_free(p);\n        return ESP_NETIF_OPTIONAL_RETURN_CODE(ESP_FAIL);',
        '        meshvpn_hosted_rx_netif(meshpn_ifx, 3, len);\n'
        '        pbuf_free(p);\n        return ESP_NETIF_OPTIONAL_RETURN_CODE(ESP_FAIL);')
    one('    return ESP_NETIF_OPTIONAL_RETURN_CODE(ESP_OK);',
        '    meshvpn_hosted_rx_netif(meshpn_ifx, 4, len);\n'
        '    return ESP_NETIF_OPTIONAL_RETURN_CODE(ESP_OK);')
    return ('extern void meshvpn_hosted_rx_netif(unsigned, unsigned, unsigned);\n'
            'extern void meshvpn_ap_probe_arp(unsigned, unsigned, const void *, unsigned);\n' + source)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    if a.source.resolve() == a.output.resolve():
        p.error('Do not modify SDK sources')
    result = patch(a.source.read_text())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    if not a.output.exists() or a.output.read_text() != result:
        a.output.write_text(result)
