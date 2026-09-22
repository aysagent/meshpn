idf_component_register(
    SRCS "meshvpn_vpn.c" "meshvpn_vpn_frame.c" "meshvpn_vpn_stream.c" "meshvpn_vpn_profile.c" "meshvpn_vpn_tls.c" "meshvpn_wireguard.c" "meshvpn_wg_diag.c"
    INCLUDE_DIRS "include"
    REQUIRES meshvpn_config lwip esp_netif esp_timer esp_hw_support esp_psram esp-tls esphome__wireguard mbedtls
)
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=wireguard_encrypt_packet" "-Wl,--wrap=wireguard_decrypt_packet")
