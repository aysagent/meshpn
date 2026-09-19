#include <assert.h>
#include <stdio.h>
#include "../components/meshvpn_wifi/meshvpn_wifi_diag.c"

static int64_t now;
static uint64_t duration;
static int result, calls;
static void *expected_buffer, *expected_ref;
static size_t expected_len;
static wifi_interface_t expected_if;
static unsigned lan_egress_calls;
void meshvpn_vpn_lan_egress(void *frame, size_t length, bool usb)
{ assert(frame == expected_buffer && length == expected_len && !usb); lan_egress_calls++; }
int64_t esp_timer_get_time(void) { return now; }
int __real_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len)
{
    assert(ifx == expected_if && buffer == expected_buffer && len == expected_len);
    calls++; now += duration; return result;
}
esp_err_t __real_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *ref)
{
    assert(ref == expected_ref);
    assert(ifx == expected_if && buffer == expected_buffer && len == expected_len);
    calls++; now += duration; return result;
}
int main(void)
{
    char buffer[1], ref[1];
    expected_buffer = buffer; expected_ref = ref; expected_len = 1200;
    const int errors[] = {ESP_OK, ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG, ESP_ERR_WIFI_IF,
        ESP_ERR_WIFI_CONN, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_NOT_STARTED, ESP_ERR_WIFI_STATE,
        ESP_ERR_WIFI_NOT_ASSOC, ESP_ERR_WIFI_TX_DISALLOW, ESP_ERR_WIFI_POST, -987};
    const uint64_t times[] = {100, 101, 1000, 1001, 5000, 5001};
    for (int iface = 0; iface < 2; iface++) for (unsigned i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
        expected_if = iface; result = errors[i]; duration = times[i % 6];
        assert(__wrap_esp_wifi_internal_tx(iface, buffer, 1200) == result);
        assert(__wrap_esp_wifi_internal_tx_by_ref(iface, buffer, 1200, ref) == result);
    }
    meshvpn_wifi_tx_diag_t stats[2]; meshvpn_wifi_tx_snapshot(stats);
    assert(lan_egress_calls == 24);
    for (int i = 0; i < 2; i++) {
        meshvpn_wifi_tx_diag_t *s = &stats[i];
        assert(s->calls == 24 && s->copy_calls == 12 && s->ref_calls == 12);
        assert(s->accepted == 2 && s->bytes_accepted == 2400);
        assert(s->no_mem == 2 && s->invalid_arg == 2 && s->not_ready == 12);
        assert(s->tx_disallow == 2 && s->post_failed == 2 && s->other_error == 2);
        assert(s->call_le_100us == 4 && s->call_100_1000us == 8 && s->call_1_5ms == 8 && s->call_gt_5ms == 4);
        assert(s->call_max_us == 5001 && s->call_us == 48812 && s->last_error == -987);
    }
    expected_if = WIFI_IF_OTHER;
    assert(__wrap_esp_wifi_internal_tx(expected_if, buffer, 1200) == result);
    meshvpn_wifi_tx_snapshot(stats);
    assert(stats[0].calls == 24 && stats[1].calls == 24 && calls == 49);
    puts("Wi-Fi handoff diagnostics: pass-through, timing boundaries, error accounting OK");
}
