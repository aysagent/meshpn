idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS "."
    REQUIRES meshvpn_board meshvpn_config meshvpn_log meshvpn_wifi meshvpn_usb meshvpn_net
             meshvpn_web meshvpn_routing meshvpn_vpn meshvpn_storage meshvpn_datapath
             nvs_flash esp_netif esp_event esp_wifi
)

# iot_bridge generates ${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h and forces
# lwIP to include it instead of any project-wide ESP_IDF_LWIP_HOOK_FILENAME.
file(APPEND "${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h"
     "#include \"meshvpn_lwip_hooks.h\"\n")
