#include <assert.h>
#include <stdio.h>
#include "../components/meshvpn_wifi/meshvpn_wifi_radio_config.c"
static unsigned bandwidth_calls, protocol_calls;
static esp_err_t bandwidth_error, protocol_error;
static uint8_t protocol;
const char *esp_err_to_name(esp_err_t e){(void)e;return "test";}
esp_err_t esp_wifi_set_bandwidth(wifi_interface_t i,wifi_bandwidth_t b){
 assert(i==WIFI_IF_STA||i==WIFI_IF_AP);bandwidth_calls++;
 assert(b==(CONFIG_IDF_TARGET_ESP32P4?WIFI_BW_HT20:WIFI_BW_HT40));return bandwidth_error;
}
esp_err_t esp_wifi_set_protocol(wifi_interface_t i,uint8_t p){
 assert(i==WIFI_IF_STA||i==WIFI_IF_AP);protocol_calls++;protocol=p;
 return p&WIFI_PROTOCOL_11AX?protocol_error:ESP_OK;
}
int main(void){
 for(unsigned i=0;i<2;i++){
  assert(meshvpn_wifi_radio_configure(i)==ESP_OK);
  if(CONFIG_IDF_TARGET_ESP32P4)assert(protocol==
    ((CONFIG_MESHVPN_P4_AP_DISABLE_11AX && i==WIFI_IF_AP)?7:71));
 }
 assert(bandwidth_calls==2&&protocol_calls==(CONFIG_IDF_TARGET_ESP32P4?2:0));
 bandwidth_error=ESP_FAIL;assert(meshvpn_wifi_radio_configure(WIFI_IF_STA)==ESP_FAIL);
 bandwidth_error=ESP_OK;
 if(CONFIG_IDF_TARGET_ESP32P4){
  protocol_error=ESP_ERR_NOT_SUPPORTED;assert(meshvpn_wifi_radio_configure(WIFI_IF_AP)==ESP_OK&&protocol==7);
  protocol_error=ESP_ERR_INVALID_ARG;assert(meshvpn_wifi_radio_configure(WIFI_IF_STA)==ESP_OK&&protocol==7);
  protocol_error=ESP_FAIL;assert(meshvpn_wifi_radio_configure(WIFI_IF_STA)==ESP_FAIL);
 }
 puts("Radio configure: C6 HE20/bgnax, explicit legacy fallback, error propagation and native HT40 passed");
}
