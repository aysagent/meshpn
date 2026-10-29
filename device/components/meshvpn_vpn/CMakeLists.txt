idf_component_register(
    SRCS "meshvpn_vpn_profiles.c" "meshvpn_vpn.c" "meshvpn_vpn_frame.c" "meshvpn_vpn_stream.c" "meshvpn_vpn_profile.c" "meshvpn_vpn_tls.c" "meshvpn_vpn_trust.c" "meshvpn_vpn_client_identity.c" "meshvpn_wireguard.c" "meshvpn_wg_diag.c"
    INCLUDE_DIRS "include"
    REQUIRES meshvpn_profiled_tls meshvpn_config lwip esp_netif esp_timer esp_hw_support esp_psram esp-tls esphome__wireguard mbedtls nvs_flash
    PRIV_REQUIRES bootloader_support
)
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=wireguard_encrypt_packet" "-Wl,--wrap=wireguard_decrypt_packet")

target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
