idf_component_register(
    SRCS "meshvpn_vpn.c" "meshvpn_vpn_frame.c" "meshvpn_vpn_profile.c" "meshvpn_wireguard.c"
    INCLUDE_DIRS "include"
    REQUIRES meshvpn_config lwip esp_netif esp_timer esp_hw_support esp_psram esphome__wireguard mbedtls
)
