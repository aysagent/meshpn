#pragma once
#include <stddef.h>
#include "esp_err.h"
typedef struct { int unused; } esp_netif_t;
typedef struct {
    void *handle;
    esp_err_t (*transmit)(void *, void *, size_t);
    esp_err_t (*transmit_wrap)(void *, void *, size_t, void *);
    void (*driver_free_rx_buffer)(void *, void *);
} esp_netif_driver_ifconfig_t;
esp_err_t esp_netif_set_driver_config(esp_netif_t *, const esp_netif_driver_ifconfig_t *);
