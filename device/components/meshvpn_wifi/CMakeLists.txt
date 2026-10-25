set(meshvpn_wifi_requires esp_wifi esp_netif esp_event esp_timer meshvpn_config meshvpn_vpn)
if(IDF_TARGET STREQUAL "esp32p4")
    list(APPEND meshvpn_wifi_requires esp_hosted esp_driver_sdmmc)
endif()
idf_component_register(
    SRCS "meshvpn_wifi.c" "meshvpn_wifi_diag.c" "meshvpn_wifi_radio.c" "meshvpn_wifi_radio_config.c"
    INCLUDE_DIRS "include"
    REQUIRES ${meshvpn_wifi_requires}
)
# Cover both ESP-NETIF transmit paths without modifying the IDF checkout.
target_link_libraries(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=esp_wifi_internal_tx" "-Wl,--wrap=esp_wifi_internal_tx_by_ref")
if(IDF_TARGET STREQUAL "esp32p4")
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=hosted_sdio_read_block" "-Wl,--wrap=hosted_sdio_write_block"
        "-Wl,--wrap=hosted_sdio_read_reg" "-Wl,--wrap=hosted_sdio_write_reg")
endif()
