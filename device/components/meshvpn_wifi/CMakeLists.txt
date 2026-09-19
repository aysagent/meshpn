idf_component_register(
    SRCS "meshvpn_wifi.c" "meshvpn_wifi_diag.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_netif esp_event esp_timer meshvpn_config meshvpn_vpn
)
# Cover both ESP-NETIF transmit paths without modifying the IDF checkout.
target_link_libraries(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=esp_wifi_internal_tx" "-Wl,--wrap=esp_wifi_internal_tx_by_ref")
