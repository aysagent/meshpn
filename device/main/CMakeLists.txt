idf_component_register(
    SRCS "app_main.c" "usb_diag.c"
    INCLUDE_DIRS "."
    REQUIRES meshvpn_board meshvpn_config meshvpn_log meshvpn_wifi meshvpn_usb meshvpn_net
             meshvpn_web meshvpn_routing meshvpn_vpn
             nvs_flash esp_netif esp_event esp_wifi esp_tinyusb tinyusb esp_app_format esp_timer
)

# iot_bridge generates the hook file on S3. P4 uses project-owned netifs, so
# create the same lwIP hook integration without pulling the S2/S3-only bridge.
if(IDF_TARGET STREQUAL "esp32p4")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/config")
    file(WRITE "${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h"
         "#include \"meshvpn_lwip_hooks.h\"\n")
    target_compile_options(__idf_lwip PRIVATE
        "-DESP_IDF_LWIP_HOOK_FILENAME=\"customer_lwip_hook.h\"")
else()
    file(APPEND "${CMAKE_BINARY_DIR}/config/customer_lwip_hook.h"
         "#include \"meshvpn_lwip_hooks.h\"\n")
endif()
