#include "cJSON.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "meshvpn_wifi_diag.h"
#include "meshvpn_wifi_radio.h"
#include "sdkconfig.h"
#if CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE
#include "meshvpn_hosted_tx.h"
#endif

static void number_or_null(cJSON *obj, const char *name, esp_err_t err, double value)
{
    if (err == ESP_OK) cJSON_AddNumberToObject(obj, name, value);
    else cJSON_AddNullToObject(obj, name);
}

void meshvpn_wifi_diagnostics_json(cJSON *wifi)
{
    meshvpn_wifi_tx_diag_t stats[2];
    meshvpn_wifi_tx_snapshot(stats);
    cJSON *tx = cJSON_AddObjectToObject(wifi, "tx");
    cJSON_AddBoolToObject(tx, "available", true);
#if CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE
    cJSON_AddStringToObject(tx, "scope", "Wi-Fi API handoffs; accepted = direct SDIO handoff or staged copy, not RF completion; remote by-ref delegation may also count an inner copy call; use hosted.tx_queue for unique frame counts");
#endif
#ifdef CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM
    cJSON_AddNumberToObject(tx, "static_rx_buffer_count", CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM);
#endif
#ifdef CONFIG_ESP_WIFI_STATIC_TX_BUFFER
    cJSON_AddStringToObject(tx, "buffer_type", "static");
    cJSON_AddNumberToObject(tx, "static_buffer_count", CONFIG_ESP_WIFI_STATIC_TX_BUFFER_NUM);
#else
    cJSON_AddStringToObject(tx, "buffer_type", "dynamic");
    cJSON_AddNumberToObject(tx, "dynamic_buffer_count", CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM);
#endif
#ifdef CONFIG_ESP_WIFI_CACHE_TX_BUFFER_NUM
    cJSON_AddNumberToObject(tx, "cache_buffer_count", CONFIG_ESP_WIFI_CACHE_TX_BUFFER_NUM);
#else
    cJSON_AddNumberToObject(tx, "cache_buffer_count", 0);
#endif
#ifdef CONFIG_ESP_WIFI_AMSDU_TX_ENABLED
    cJSON_AddBoolToObject(tx, "amsdu_enabled", true);
#else
    cJSON_AddBoolToObject(tx, "amsdu_enabled", false);
#endif
#ifdef CONFIG_ESP_WIFI_AMPDU_TX_ENABLED
    cJSON_AddBoolToObject(tx, "ampdu_enabled", true);
    cJSON_AddNumberToObject(tx, "ampdu_ba_window", CONFIG_ESP_WIFI_TX_BA_WIN);
#else
    cJSON_AddBoolToObject(tx, "ampdu_enabled", false);
    cJSON_AddNumberToObject(tx, "ampdu_ba_window", 0);
#endif
#ifdef CONFIG_ESP_WIFI_AMPDU_RX_ENABLED
    cJSON_AddBoolToObject(tx, "ampdu_rx_enabled", true);
    cJSON_AddNumberToObject(tx, "ampdu_rx_ba_window", CONFIG_ESP_WIFI_RX_BA_WIN);
#else
    cJSON_AddBoolToObject(tx, "ampdu_rx_enabled", false);
    cJSON_AddNumberToObject(tx, "ampdu_rx_ba_window", 0);
#endif
#ifdef CONFIG_ESP_WIFI_IRAM_OPT
    cJSON_AddBoolToObject(tx, "iram_opt_enabled", true);
#else
    cJSON_AddBoolToObject(tx, "iram_opt_enabled", false);
#endif
#ifdef CONFIG_ESP_WIFI_EXTRA_IRAM_OPT
    cJSON_AddBoolToObject(tx, "extra_iram_opt_enabled", true);
#else
    cJSON_AddBoolToObject(tx, "extra_iram_opt_enabled", false);
#endif
#ifdef CONFIG_ESP_WIFI_RX_IRAM_OPT
    cJSON_AddBoolToObject(tx, "rx_iram_opt_enabled", true);
#else
    cJSON_AddBoolToObject(tx, "rx_iram_opt_enabled", false);
#endif
#ifdef CONFIG_LWIP_IRAM_OPTIMIZATION
    cJSON_AddBoolToObject(tx, "lwip_iram_opt_enabled", true);
#else
    cJSON_AddBoolToObject(tx, "lwip_iram_opt_enabled", false);
#endif
    for (int i = 0; i < 2; i++) {
        cJSON *s = cJSON_AddObjectToObject(tx, i ? "ap" : "sta");
#define ADD(name) cJSON_AddNumberToObject(s, #name, (double)stats[i].name);
        MESHVPN_WIFI_TX_COUNTERS(ADD)
        ADD(call_max_us)
        ADD(last_error)
#undef ADD
    }
    cJSON *radio = cJSON_AddObjectToObject(wifi, "radio");
    meshvpn_wifi_radio_t sample;
    meshvpn_wifi_radio_snapshot(&sample);
    uint8_t primary = sample.primary;
    wifi_second_chan_t secondary = sample.secondary;
    esp_err_t err = sample.channel_error;
    number_or_null(radio, "primary_channel", err, primary);
    number_or_null(radio, "secondary_channel", err, secondary);
    wifi_ps_type_t ps = sample.ps;
    err = sample.ps_error;
    number_or_null(radio, "power_save", err, ps);
    number_or_null(radio, "max_tx_power_dbm", sample.tx_power_error, sample.max_tx_power / 4.0);
    for (int i = 0; i < 2; i++) {
        wifi_bandwidth_t bw = sample.bandwidth[i];
        err = sample.bandwidth_error[i];
        number_or_null(radio, i ? "ap_bandwidth_mhz" : "sta_bandwidth_mhz",
                       err == ESP_OK && (bw == WIFI_BW_HT20 || bw == WIFI_BW_HT40) ? ESP_OK : ESP_FAIL,
                       bw == WIFI_BW_HT40 ? 40 : 20);
    }
    const wifi_ap_record_t uplink = sample.uplink;
    err = sample.uplink_error;
    cJSON *sta = cJSON_AddObjectToObject(radio, "uplink");
    cJSON_AddBoolToObject(sta, "negotiated_phymode_available", sample.phymode_error == ESP_OK);
    number_or_null(sta, "negotiated_phymode", sample.phymode_error, sample.phymode);
    const char *mode = sample.phymode_error != ESP_OK ? "unavailable" :
        sample.phymode == WIFI_PHY_MODE_HE20 ? "802.11ax HE20" :
        sample.phymode == WIFI_PHY_MODE_HT40 ? "802.11n HT40" :
        sample.phymode == WIFI_PHY_MODE_HT20 ? "802.11n HT20" :
        sample.phymode == WIFI_PHY_MODE_11G ? "802.11g" :
        sample.phymode == WIFI_PHY_MODE_11B ? "802.11b" : "other";
    cJSON_AddStringToObject(sta, "negotiated_phymode_name", mode);
    for (unsigned i = 0; i < 2; i++) {
        cJSON *protocol = cJSON_AddObjectToObject(radio, i ? "ap_protocol" : "sta_protocol");
        cJSON_AddBoolToObject(protocol, "available", sample.protocol_error[i] == ESP_OK);
        number_or_null(protocol, "bitmap", sample.protocol_error[i], sample.protocol[i]);
        const char *names[] = {"802_11b", "802_11g", "802_11n", "802_11ax"};
        const unsigned bits[] = {WIFI_PROTOCOL_11B, WIFI_PROTOCOL_11G, WIFI_PROTOCOL_11N, WIFI_PROTOCOL_11AX};
        for (unsigned j = 0; j < 4; j++) {
            if (sample.protocol_error[i] == ESP_OK)
                cJSON_AddBoolToObject(protocol, names[j], (sample.protocol[i] & bits[j]) != 0);
            else cJSON_AddNullToObject(protocol, names[j]);
        }
        cJSON_AddStringToObject(protocol, "scope", "allowed interface protocols, not negotiated connection mode");
    }
    cJSON_AddBoolToObject(sta, "available", err == ESP_OK);
    if (err == ESP_OK) {
        cJSON_AddNumberToObject(sta, "rssi", uplink.rssi);
        cJSON_AddNumberToObject(sta, "primary_channel", uplink.primary);
        cJSON_AddNumberToObject(sta, "secondary_channel", uplink.second);
        cJSON_AddBoolToObject(sta, "phy_11n", uplink.phy_11n);
        cJSON_AddBoolToObject(sta, "phy_11ax", uplink.phy_11ax);
        int advertised_width = uplink.bandwidth == WIFI_BW_HT20 ? 20 :
            uplink.bandwidth == WIFI_BW_HT40 ? 40 : uplink.bandwidth == WIFI_BW80 ? 80 :
            uplink.bandwidth == WIFI_BW160 || uplink.bandwidth == WIFI_BW80_BW80 ? 160 : 0;
        number_or_null(sta, "advertised_bandwidth_mhz", advertised_width ? ESP_OK : ESP_FAIL, advertised_width);
        cJSON_AddStringToObject(sta, "phy_scope", "AP record capabilities, not measured PHY rate or confirmed per-frame mode");
        cJSON_AddNumberToObject(sta, "channel_width_mhz", uplink.second == WIFI_SECOND_CHAN_NONE ? 20 : 40);
    }
    const wifi_sta_list_t peers = sample.peers;
    err = sample.peers_error;
    cJSON_AddBoolToObject(radio, "clients_available", err == ESP_OK);
    cJSON *clients = cJSON_AddArrayToObject(radio, "clients");
    if (err == ESP_OK) for (int i = 0; i < peers.num && i < ESP_WIFI_MAX_CONN_NUM; i++) {
        const wifi_sta_info_t *p = &peers.sta[i];
        cJSON *client = cJSON_CreateObject();
        cJSON_AddItemToArray(clients, client);
        /* No MAC/SSID in diagnostics exports. Index is snapshot-local, not identity. */
        cJSON_AddNumberToObject(client, "index", i);
        cJSON_AddNumberToObject(client, "rssi", p->rssi);
        cJSON_AddBoolToObject(client, "phy_11b", p->phy_11b);
        cJSON_AddBoolToObject(client, "phy_11g", p->phy_11g);
        cJSON_AddBoolToObject(client, "phy_11n", p->phy_11n);
        cJSON_AddBoolToObject(client, "phy_lr", p->phy_lr);
        cJSON_AddBoolToObject(client, "phy_11ax", p->phy_11ax);
    }
    cJSON_AddBoolToObject(radio, "available", sample.sampled_us != 0);
    cJSON_AddNumberToObject(radio, "sampled_us", (double)sample.sampled_us);
    cJSON_AddNumberToObject(radio, "collection_us", sample.collection_us);
    if (sample.sampled_us) cJSON_AddNumberToObject(radio, "age_ms", (esp_timer_get_time() - sample.sampled_us) / 1000.0);
    else cJSON_AddNullToObject(radio, "age_ms");
    cJSON *errors = cJSON_AddObjectToObject(radio, "errors");
    cJSON_AddNumberToObject(errors, "channel", sample.channel_error);
    cJSON_AddNumberToObject(errors, "power_save", sample.ps_error);
    cJSON_AddNumberToObject(errors, "max_tx_power", sample.tx_power_error);
    cJSON_AddNumberToObject(errors, "sta_bandwidth", sample.bandwidth_error[0]);
    cJSON_AddNumberToObject(errors, "ap_bandwidth", sample.bandwidth_error[1]);
    cJSON_AddNumberToObject(errors, "uplink", sample.uplink_error);
    cJSON_AddNumberToObject(errors, "clients", sample.peers_error);
    cJSON_AddNumberToObject(errors, "negotiated_phymode", sample.phymode_error);
    cJSON_AddNumberToObject(errors, "sta_protocol", sample.protocol_error[0]);
    cJSON_AddNumberToObject(errors, "ap_protocol", sample.protocol_error[1]);
#ifdef CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE
    cJSON *hosted = cJSON_AddObjectToObject(wifi, "hosted");
    cJSON_AddStringToObject(hosted, "transport", "sdio");
    cJSON *firmware = cJSON_AddObjectToObject(hosted, "coprocessor_firmware");
    cJSON_AddBoolToObject(firmware, "attempted", sample.firmware_attempted);
    cJSON_AddBoolToObject(firmware, "available", sample.firmware_error == ESP_OK);
    cJSON_AddNumberToObject(firmware, "error", sample.firmware_error);
    const char *version_fields[] = {"major", "minor", "patch"};
    for (unsigned i = 0; i < 3; i++) number_or_null(firmware, version_fields[i], sample.firmware_error, sample.firmware[i]);
    cJSON_AddNumberToObject(hosted, "configured_clock_khz", CONFIG_ESP_HOSTED_SDIO_CLOCK_FREQ_KHZ);
    cJSON_AddNumberToObject(hosted, "configured_bus_width", CONFIG_ESP_HOSTED_SDIO_BUS_WIDTH);
    cJSON_AddNumberToObject(hosted, "configured_tx_queue", CONFIG_ESP_HOSTED_SDIO_TX_Q_SIZE);
    cJSON_AddNumberToObject(hosted, "configured_rx_queue", CONFIG_ESP_HOSTED_SDIO_RX_Q_SIZE);
    cJSON_AddStringToObject(hosted, "scope", "host configuration; not a throughput measurement");
    meshvpn_hosted_tx_stats_t staged; meshvpn_hosted_tx_snapshot(&staged);
    cJSON *rx_progress = cJSON_AddObjectToObject(hosted, "rx_progress");
    cJSON_AddStringToObject(rx_progress, "scope", "since boot; 10ms IRQ timeout is normal idle polling; poll_data means pending bytes found after timeout, not proof of a lost edge");
#define RX_FIELD(name) cJSON_AddNumberToObject(rx_progress, #name, (double)staged.rx_##name)
    RX_FIELD(interrupts); RX_FIELD(wait_timeouts); RX_FIELD(wait_errors);
    RX_FIELD(poll_data); RX_FIELD(without_new_packet); RX_FIELD(reads); RX_FIELD(bytes);
    RX_FIELD(read_errors); RX_FIELD(pending_max);
#undef RX_FIELD
    if (staged.rx_last_read_us) cJSON_AddNumberToObject(rx_progress, "last_read_age_ms", (esp_timer_get_time() - staged.rx_last_read_us) / 1000.0);
    else cJSON_AddNullToObject(rx_progress, "last_read_age_ms");
    cJSON *rx_netif = cJSON_AddObjectToObject(hosted, "rx_netif");
    cJSON_AddStringToObject(rx_netif, "scope", "since boot; wlanif handoff from Hosted; queued = accepted by lwIP input, not application delivery; drops are down + no_memory + input_rejected; public RX callback return may hide drops");
    const char *rx_names[] = {"calls", "down", "no_memory", "input_rejected", "queued"};
    for (unsigned i = 0; i < 2; i++) {
        cJSON *entry = cJSON_AddObjectToObject(rx_netif, i ? "ap" : "sta");
        for (unsigned j = 0; j < 5; j++) cJSON_AddNumberToObject(entry, rx_names[j], staged.rx_netif[i][j]);
        cJSON_AddNumberToObject(entry, "bytes", staged.rx_netif_bytes[i]);
    }
    cJSON *queues = cJSON_AddObjectToObject(hosted, "tx_queue");
    cJSON_AddBoolToObject(queues, "enabled", staged.enabled);
    cJSON_AddStringToObject(queues, "scope", "since boot; uncontended direct SDIO handoff, congestion staged in owned PSRAM copies; sent includes direct_sent, not RF delivery; residence_us covers released staged copies; losses = full + invalid + not_ready + expired + stale + policy_changed + failed");
    cJSON_AddNumberToObject(queues, "capacity_per_interface", MESHVPN_HOSTED_TX_SLOTS);
    cJSON_AddNumberToObject(queues, "max_age_ms", MESHVPN_HOSTED_TX_MAX_AGE_US / 1000);
    cJSON_AddBoolToObject(queues, "worker_active", staged.worker_active);
    cJSON_AddNumberToObject(queues, "worker_interface", staged.worker_interface);
    cJSON_AddNumberToObject(queues, "worker_age_us", staged.worker_age_us);
    cJSON_AddNumberToObject(queues, "worker_stack_free", staged.worker_stack_free);
    cJSON_AddNumberToObject(queues, "slave_buffer_calls", staged.slave_buffer_calls);
    cJSON_AddNumberToObject(queues, "slave_buffer_unavailable", staged.slave_buffer_unavailable);
    cJSON_AddNumberToObject(queues, "slave_buffer_us", staged.slave_buffer_us);
    cJSON_AddNumberToObject(queues, "slave_buffer_max_us", staged.slave_buffer_max_us);
    cJSON *throttle = cJSON_AddObjectToObject(queues, "throttle");
    cJSON_AddBoolToObject(throttle, "active", staged.throttled);
    cJSON_AddNumberToObject(throttle, "starts", staged.throttle_starts);
    cJSON_AddNumberToObject(throttle, "stops", staged.throttle_stops);
    cJSON_AddNumberToObject(throttle, "total_us", staged.throttle_us);
    cJSON_AddNumberToObject(throttle, "max_us", staged.throttle_max_us);
    cJSON_AddNumberToObject(throttle, "age_us", staged.throttle_age_us);
    for (unsigned i = 0; i < 2; i++) {
        cJSON *q = cJSON_AddObjectToObject(queues, i ? "ap" : "sta");
        meshvpn_hosted_queue_stats_t *v = &staged.queue[i];
#define FIELD(name) cJSON_AddNumberToObject(q, #name, (double)v->name)
        FIELD(submitted); FIELD(enqueued); FIELD(sent); FIELD(full); FIELD(invalid);
        FIELD(not_ready); FIELD(expired); FIELD(stale); FIELD(policy_changed);
        FIELD(failed); FIELD(retries); FIELD(bytes_sent); FIELD(residence_us);
        FIELD(residence_max_us); FIELD(send_us); FIELD(send_max_us);
        FIELD(in_use); FIELD(high_water); FIELD(last_error);
        FIELD(direct_sent);
#undef FIELD
        cJSON_AddBoolToObject(q, "link_up", staged.link_up[i]);
        if (v->last_send_us) cJSON_AddNumberToObject(q, "last_send_age_ms", (esp_timer_get_time() - v->last_send_us) / 1000.0);
        else cJSON_AddNullToObject(q, "last_send_age_ms");
        cJSON_AddNumberToObject(q, "sdio_enqueue_calls", staged.sdio_calls[i]);
        cJSON_AddNumberToObject(q, "sdio_enqueue_full", staged.sdio_full[i]);
        cJSON_AddNumberToObject(q, "sdio_enqueue_us", staged.sdio_enqueue_us[i]);
        cJSON_AddNumberToObject(q, "sdio_enqueue_max_us", staged.sdio_enqueue_max_us[i]);
    }
    meshvpn_sdio_call_t io[4]; meshvpn_wifi_sdio_snapshot(io);
    cJSON *calls = cJSON_AddObjectToObject(hosted, "io");
    cJSON_AddStringToObject(calls, "scope", "since boot; completed host SDIO calls, padded transfer bytes; time includes lock wait and preemption; not RF statistics");
    const char *names[] = {"read_block", "write_block", "read_reg", "write_reg"};
    for (unsigned i = 0; i < 4; i++) {
        cJSON *v = cJSON_AddObjectToObject(calls, names[i]);
        cJSON_AddNumberToObject(v, "calls", (double)io[i].calls);
        cJSON_AddNumberToObject(v, "bytes", (double)io[i].bytes);
        cJSON_AddNumberToObject(v, "failed", (double)io[i].failed);
        cJSON_AddNumberToObject(v, "time_us", (double)io[i].time_us);
        cJSON_AddNumberToObject(v, "max_us", io[i].max_us);
        cJSON_AddNumberToObject(v, "last_error", io[i].last_error);
    }
    meshvpn_sdio_drop_t drops[4]; meshvpn_wifi_sdio_drop_snapshot(drops);
    cJSON *dropped = cJSON_AddObjectToObject(hosted, "rx_drops");
    const char *reasons[] = {"packet_no_memory", "oversize_stream", "malformed_stream", "payload_no_memory"};
    for (unsigned i = 0; i < 4; i++) {
        cJSON *v = cJSON_AddObjectToObject(dropped, reasons[i]);
        cJSON_AddNumberToObject(v, "events", (double)drops[i].events);
        cJSON_AddNumberToObject(v, "bytes", (double)drops[i].bytes);
    }
#endif
}
