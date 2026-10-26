#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../components/meshvpn_wifi/meshvpn_wifi_radio.c"
static int64_t now=1000000;
static unsigned calls,phy_calls,firmware_calls,protocol_calls;
static bool disconnected;
int64_t esp_timer_get_time(void){return now;}
static void call(void){calls++;now+=10;}
esp_err_t esp_wifi_get_channel(uint8_t*p,wifi_second_chan_t*s){call();*p=7;*s=0;return ESP_OK;}
esp_err_t esp_wifi_get_ps(wifi_ps_type_t*p){call();*p=0;return ESP_OK;}
esp_err_t esp_wifi_get_max_tx_power(int8_t*p){call();*p=84;return ESP_OK;}
esp_err_t esp_wifi_get_bandwidth(int i,wifi_bandwidth_t*b){assert(i==0||i==1);call();*b=2;return ESP_OK;}
esp_err_t esp_wifi_get_protocol(int i,uint8_t*p){
 assert(i==0||i==1);assert((uintptr_t)p%2==0);call();protocol_calls++;
 uint16_t value=0xa547;memcpy(p,&value,sizeof(value));return ESP_OK;
}
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t*p){call();if(disconnected)return ESP_ERR_INVALID_STATE;p->rssi=-55;return ESP_OK;}
esp_err_t esp_wifi_ap_get_sta_list(wifi_sta_list_t*p){call();p->num=2;return ESP_OK;}
esp_err_t esp_wifi_sta_get_negotiated_phymode(wifi_phy_mode_t*p){(void)p;call();phy_calls++;return ESP_ERR_NOT_SUPPORTED;}
#if CONFIG_IDF_TARGET_ESP32P4
esp_err_t esp_hosted_get_coprocessor_fwversion(esp_hosted_coprocessor_fwver_t*p){
 call();firmware_calls++;
 *p=TEST_FW_OK==2?(esp_hosted_coprocessor_fwver_t){2,6,6}:
    TEST_FW_OK==3?(esp_hosted_coprocessor_fwver_t){2,6,5}:(esp_hosted_coprocessor_fwver_t){1,4,7};
 return TEST_FW_OK?ESP_OK:ESP_FAIL;
}
#endif
int main(void){
 meshvpn_wifi_radio_t s;meshvpn_wifi_radio_snapshot(&s);
 assert(!s.sampled_us&&s.uplink_error==ESP_ERR_INVALID_STATE&&s.phymode_error==ESP_ERR_INVALID_STATE&&!calls);
#if CONFIG_IDF_TARGET_ESP32P4
 disconnected=true;meshvpn_wifi_radio_sample();meshvpn_wifi_radio_snapshot(&s);
 assert(calls==6&&!firmware_calls&&!protocol_calls&&s.protocol_error[0]==ESP_ERR_NOT_SUPPORTED);
 now+=6000000;disconnected=false;calls=0;
#endif
 int64_t first_started=now;
 meshvpn_wifi_radio_sample();meshvpn_wifi_radio_snapshot(&s);
 bool protocol_safe=!CONFIG_IDF_TARGET_ESP32P4||TEST_FW_OK==2;
 unsigned recurring=protocol_safe?8:6;
 unsigned first_calls=(CONFIG_IDF_TARGET_ESP32P4?recurring+1+(TEST_FW_OK?1:0):9)+1;
 assert(calls==first_calls&&s.sampled_us==first_started+10*first_calls&&s.collection_us==10*first_calls&&s.phymode_error==ESP_ERR_NOT_SUPPORTED);
 assert(!s.tx_power_error&&s.max_tx_power==84);
 if(protocol_safe)assert(s.protocol[0]==71&&s.protocol[1]==71&&protocol_calls==2);
 else assert(!protocol_calls&&s.protocol_error[0]==ESP_ERR_NOT_SUPPORTED&&s.protocol_error[1]==ESP_ERR_NOT_SUPPORTED);
 int8_t rssi;uint8_t channel,clients;
 for(unsigned i=0;i<1000;i++){
  meshvpn_wifi_radio_snapshot(&s);meshvpn_wifi_radio_summary(&rssi,&channel,&clients);
  assert(rssi==-55&&channel==7&&clients==2);
 }
 assert(calls==first_calls);meshvpn_wifi_radio_sample();assert(calls==first_calls); // readers never trigger an RPC
 now+=6000000;disconnected=true;meshvpn_wifi_radio_sample();meshvpn_wifi_radio_snapshot(&s);
 assert(calls==first_calls+recurring&&phy_calls==(CONFIG_IDF_TARGET_ESP32P4?!!TEST_FW_OK:1)&&s.uplink_error==ESP_ERR_INVALID_STATE&&s.uplink.rssi==0);
 meshvpn_wifi_radio_summary(&rssi,NULL,NULL);assert(rssi==0);
 now+=6000000;disconnected=false;meshvpn_wifi_radio_sample();
 assert(calls==first_calls+2*recurring+1&&firmware_calls==(CONFIG_IDF_TARGET_ESP32P4?1:0));
 meshvpn_wifi_radio_summary(&rssi,NULL,NULL);assert(rssi==-55);
 puts("Radio cache: rate-limited collection, zero RPCs from readers, error/age preservation, unsupported PHY and disconnect passed");
}
