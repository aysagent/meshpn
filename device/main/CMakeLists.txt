idf_component_register(
    SRCS "app_main.c" "usb_diag.c"
    INCLUDE_DIRS "."
    REQUIRES meshvpn_board meshvpn_config meshvpn_log meshvpn_wifi meshvpn_usb meshvpn_net
             meshvpn_web meshvpn_routing meshvpn_vpn
             nvs_flash esp_netif esp_event esp_wifi esp_tinyusb tinyusb esp_app_format esp_timer
)

# iot_bridge generates ${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h and forces
# lwIP to include it instead of any project-wide ESP_IDF_LWIP_HOOK_FILENAME.
file(APPEND "${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h"
     "#include \"meshvpn_lwip_hooks.h\"\n")
