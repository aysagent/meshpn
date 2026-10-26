#pragma once
#include "../usb_stubs/esp_netif.h"
#define ESP_ERR_ESP_NETIF_NO_MEM 0x5001
esp_err_t esp_netif_tcpip_exec(esp_err_t (*fn)(void *), void *arg);
