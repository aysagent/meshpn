#include "meshvpn_datapath.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "meshvpn_net.h"
#include "meshvpn_vpn.h"

static const char *TAG = "meshvpn_datapath";

#define MESHVPN_DATAPATH_QUEUE_LEN 64
#define MESHVPN_DATAPATH_MAX_PKT 1500

typedef struct {
    uint16_t len;
    uint8_t data[MESHVPN_DATAPATH_MAX_PKT];
} meshvpn_datapath_item_t;

static QueueHandle_t s_queue;

static void meshvpn_datapath_task(void *arg)
{
    (void)arg;
    meshvpn_datapath_item_t item;

    while (true) {
        if (xQueueReceive(s_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        esp_err_t err = meshvpn_vpn_send_ipv4(item.data, item.len);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "vpn send %u bytes: %s", item.len, esp_err_to_name(err));
        }
    }
}

esp_err_t meshvpn_datapath_init(void)
{
    if (s_queue) {
        return ESP_OK;
    }

    s_queue = xQueueCreate(MESHVPN_DATAPATH_QUEUE_LEN, sizeof(meshvpn_datapath_item_t));
    if (!s_queue) {
        return ESP_ERR_NO_MEM;
    }

    xTaskCreate(meshvpn_datapath_task, "vpn_dp", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "datapath task ready");
    return ESP_OK;
}

esp_err_t meshvpn_datapath_ensure_init(void)
{
    return meshvpn_datapath_init();
}

esp_err_t meshvpn_datapath_submit_ipv4(const uint8_t *pkt, uint16_t len)
{
    if (!s_queue || !pkt || len < 20 || len > MESHVPN_DATAPATH_MAX_PKT) {
        return ESP_ERR_INVALID_ARG;
    }

    meshvpn_datapath_item_t item = { .len = len };
    memcpy(item.data, pkt, len);

    if (xQueueSend(s_queue, &item, 0) != pdTRUE) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
