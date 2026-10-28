#!/usr/bin/env python3
"""Make repeated start notifications harmless in pinned ESP-IDF 5.5.5 (P4)."""
from pathlib import Path
import argparse


def patch(source):
    anchor = '    ESP_ERROR_CHECK(esp_netif_config_sanity_check(esp_netif));\n\n    ESP_ERROR_CHECK(esp_netif_lwip_add(esp_netif));'
    if source.count(anchor) != 1:
        raise ValueError('esp_netif_start_api changed; re-audit duplicate-start guard')
    guard = '''    /* MeshPN: some Hosted peers repeat STA_START during a scan without
     * STA_STOP. A disconnected STA is registered but not UP, so checking
     * netif_is_up is insufficient. This callback runs in the lwIP thread;
     * list membership is serialized with add/remove. A real STOP removes
     * the entry and the next START must perform the normal initialization. */
    for (struct netif *registered = netif_list; registered; registered = registered->next) {
        if (registered == esp_netif->lwip_netif) {
            ESP_LOGW(TAG, "Ignoring duplicate start for %s", esp_netif->if_key);
            return ESP_OK;
        }
    }
'''
    return source.replace(anchor, anchor.replace('    ESP_ERROR_CHECK(esp_netif_lwip_add(esp_netif));', guard + '\n    ESP_ERROR_CHECK(esp_netif_lwip_add(esp_netif));'))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    if a.source.resolve() == a.output.resolve():
        p.error('Never overwrite SDK source')
    result = patch(a.source.read_text())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    if not a.output.exists() or a.output.read_text() != result:
        a.output.write_text(result)
