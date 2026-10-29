#!/usr/bin/env python3
"""Stage Wi-Fi TX in bounded PSRAM queues, outside lwIP (ESP-Hosted 1.4.7)."""

import argparse
from pathlib import Path


def patch(source: str) -> str:
    anchor = 'transport_channel_t *chan_arr[ESP_MAX_IF];'
    if source.count(anchor) != 1:
        raise ValueError('ESP-Hosted channel table changed; re-audit DMA cache snapshot')
    source = source.replace(anchor, anchor + '''
bool meshvpn_hosted_transport_dma_cache_snapshot(unsigned ifx, uint32_t *cached, uint32_t *bytes)
{
    *cached = 0; *bytes = 0;
#ifdef H_USE_MEMPOOL
    if (ifx > 1) return false;
    transport_channel_t *channel = chan_arr[ifx ? ESP_AP_IF : ESP_STA_IF];
    if (!channel || !channel->memp) return false;
    struct mempool *mp = channel->memp;
    g_h.funcs->_h_lock_mempool(mp->spinlock);
    struct mempool_entry *entry;
    SLIST_FOREACH(entry, &(mp->head), entries) { (*cached)++; }
    *bytes = MEMPOOL_ALIGNED(mp->block_size);
    g_h.funcs->_h_unlock_mempool(mp->spinlock);
    return true;
#else
    (void)ifx;
    return false;
#endif
}
''', 1)
    for interface in ("STA", "AP"):
        old = (f"copy_buff = mempool_alloc(((struct mempool*)chan_arr[ESP_{interface}_IF]->memp), "
               "MAX_TRANSPORT_BUFFER_SIZE, true);\n\tassert(copy_buff);")
        new = old.replace("\tassert(copy_buff);", "\tif (!copy_buff) return ESP_ERR_ESP_NETIF_NO_MEM;")
        if source.count(old) != 1:
            raise ValueError(f"ESP-Hosted {interface} TX source changed; re-audit the memory patch")
        source = source.replace(old, new, 1)
    for ifx, interface, following in ((0, "sta", "ap"), (1, "ap", "serial")):
        name = f"transport_drv_{interface}_tx"
        declaration = f"static esp_err_t {name}(void *h, void *buffer, size_t len)"
        if source.count(declaration) != 1:
            raise ValueError("ESP-Hosted TX callback changed; re-audit ownership")
        source = source.replace(declaration, declaration.replace(name, name + "_direct"), 1)
        next_decl = ("static esp_err_t transport_drv_ap_tx(" if following == "ap"
                     else "esp_err_t transport_drv_serial_tx(")
        if source.count(next_decl) != 1:
            raise ValueError("ESP-Hosted TX callback order changed")
        wrapper = (f"static esp_err_t {name}(void *h, void *buffer, size_t len)\n"
                   "{\n"
                   f"\treturn meshvpn_hosted_tx_submit({ifx}, h, buffer, len, {name}_direct);\n"
                   "}\n\n")
        source = source.replace(next_decl, wrapper + next_decl, 1)
    source = '#include "esp_hosted_config.h"\n#include "meshvpn_hosted_tx.h"\n' + source
    return source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite managed_components")
    result = patch(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != result:
        args.output.write_text(result)


if __name__ == "__main__":
    main()
