#!/usr/bin/env python3
"""Guard repeated/missing Hosted STA starts in pinned ESP-IDF 5.5.5 (P4)."""
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
    source = source.replace(anchor, anchor.replace('    ESP_ERROR_CHECK(esp_netif_lwip_add(esp_netif));', guard + '\n    ESP_ERROR_CHECK(esp_netif_lwip_add(esp_netif));'))
    up_anchor = '''    struct netif *lwip_netif = esp_netif->lwip_netif;

#if CONFIG_LWIP_IPV4
    /* use last obtained ip, or static ip */'''
    if source.count(up_anchor) != 1:
        raise ValueError('esp_netif_up_api changed; re-audit missing-start recovery')
    recovery = '''    /* MeshPN P4: Hosted can emit STA_STOP while applying station config,
     * then CONNECTED without another START. STOP removes the netif and its
     * IGMP allsystems group. UP alone would leave it outside netif_list and
     * mDNS would assert on joining 224.0.0.251. Re-run normal initialization
     * before addresses/DHCP only for our STA, and only if actually absent.
     * Both membership and initialization execute on this same lwIP thread. */
    if (esp_netif->if_key && !strcmp(esp_netif->if_key, "WIFI_STA_DEF")) {
        bool registered = false;
        for (struct netif *n = netif_list; n; n = n->next) {
            if (n == lwip_netif) { registered = true; break; }
        }
        if (!registered) {
            ESP_LOGW(TAG, "Restoring missing START before CONNECTED for %s", esp_netif->if_key);
            esp_err_t err = esp_netif_start_api(msg);
            if (err != ESP_OK) return err;
        }
    }

'''
    return source.replace(up_anchor, up_anchor.replace('#if CONFIG_LWIP_IPV4', recovery + '#if CONFIG_LWIP_IPV4'))


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
