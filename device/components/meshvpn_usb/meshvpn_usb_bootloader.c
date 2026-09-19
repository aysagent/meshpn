#include "sdkconfig.h"
#include "meshvpn_usb_bootloader.h"

#if CONFIG_IDF_TARGET_ESP32S3 && CONFIG_TINYUSB_CDC_ENABLED
#include "esp_log.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_private/periph_ctrl.h"
#include "esp32s3/rom/efuse.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/usb_serial_jtag_ll.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/usb_serial_jtag_reg.h"
#include "tusb.h"
#include "tusb_cdc_acm.h"
#include "tusb_tasks.h"

static esp_timer_handle_t s_reboot_timer;
static bool s_touch_armed;

static void enter_download_on_shutdown(void)
{
    /* The application owns the shared internal PHY through USB-OTG. ROM
     * downloading uses hardware CDC/JTAG instead. Do not persist TinyUSB's
     * composite NCM descriptors into the ROM console. See Espressif's
     * arduino-esp32 esp32-hal-tinyusb.c, usb_switch_to_cdc_jtag(). */
    periph_module_reset(PERIPH_USB_MODULE);
    periph_module_disable(PERIPH_USB_MODULE);
    /* Normal NCM builds deliberately gate USJ's clock at startup. Restore it
     * before accessing USJ registers (the ROM will subsequently own it). */
    PERIPH_RCC_ATOMIC() {
        usb_serial_jtag_ll_enable_bus_clock(true);
        usb_serial_jtag_ll_reset_register();
    }
    REG_CLR_BIT(RTC_CNTL_USB_CONF_REG,
                RTC_CNTL_SW_HW_USB_PHY_SEL | RTC_CNTL_SW_USB_PHY_SEL | RTC_CNTL_USB_PAD_ENABLE);
    usb_serial_jtag_ll_phy_enable_external(false);
    const usb_serial_jtag_pull_override_vals_t pulls = {.dp_pu = 1};
    usb_serial_jtag_ll_phy_enable_pull_override(&pulls);
    usb_serial_jtag_ll_phy_disable_pull_override();
    usb_serial_jtag_ll_phy_enable_pad(true);
    REG_SET_BIT(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
}

static void reboot_to_download(void *arg)
{
    (void)arg;
    /* Runs in the timer task, never inside a TinyUSB control callback. The
     * delay before this callback lets SET_CONTROL_LINE_STATE finish first. */
    if (esp_register_shutdown_handler(enter_download_on_shutdown) != ESP_OK) return;
    ESP_LOGW("usb_boot", "USB 1200-baud touch: entering ROM download mode");
    tud_disconnect();
    tusb_stop_task();
    vTaskDelay(pdMS_TO_TICKS(200)); /* host must see a real USB disconnect */
    esp_restart();
}

static void line_coding(int itf, cdcacm_event_t *event)
{
    if (itf == 0) s_touch_armed = event->line_coding_changed_data.p_line_coding->bit_rate == 1200;
}

static void line_state(int itf, cdcacm_event_t *event)
{
    if (itf != 0 || !s_touch_armed || event->line_state_changed_data.dtr) return;
    s_touch_armed = false;
    /* One timer also coalesces repeated requests; no worker stack when idle. */
    esp_timer_start_once(s_reboot_timer, 100000);
}

void meshvpn_usb_bootloader_init(void)
{
    if (ets_efuse_download_modes_disabled() ||
        esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_SERIAL_JTAG) ||
        esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE)) {
        ESP_LOGW("usb_boot", "ROM USB download is disabled by eFuse; auto-flash unavailable");
        return;
    }
    const esp_timer_create_args_t args = {.callback = reboot_to_download, .name = "usb_boot"};
    if (esp_timer_create(&args, &s_reboot_timer) != ESP_OK) {
        ESP_LOGW("usb_boot", "Cannot allocate auto-flash timer");
        return;
    }
    tinyusb_cdcacm_register_callback(0, CDC_EVENT_LINE_CODING_CHANGED, line_coding);
    tinyusb_cdcacm_register_callback(0, CDC_EVENT_LINE_STATE_CHANGED, line_state);
}
#else
/* P4 uses its separate USB-UART programming connector, not the HS NCM port. */
void meshvpn_usb_bootloader_init(void) {}
#endif
