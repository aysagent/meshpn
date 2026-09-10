idf_component_register(
    SRCS "meshvpn_web.c" "meshvpn_web_tls.c" "meshvpn_cpu.c"
    INCLUDE_DIRS "include" "."
    REQUIRES esp_http_server esp_https_server mbedtls esp_psram spi_flash app_update json meshvpn_board meshvpn_config meshvpn_log meshvpn_net meshvpn_routing meshvpn_usb meshvpn_vpn meshvpn_wifi
)
