#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef enum { WIFI_IF_STA, WIFI_IF_AP, WIFI_IF_OTHER } wifi_interface_t;
#define ESP_ERR_WIFI_IF 100
#define ESP_ERR_WIFI_CONN 101
#define ESP_ERR_WIFI_NOT_INIT 102
#define ESP_ERR_WIFI_NOT_STARTED 103
#define ESP_ERR_WIFI_STATE 104
#define ESP_ERR_WIFI_NOT_ASSOC 105
#define ESP_ERR_WIFI_TX_DISALLOW 106
#define ESP_ERR_WIFI_POST 107
