idf_component_register(
    SRCS "meshvpn_web.c"
    INCLUDE_DIRS "include" "."
    REQUIRES esp_http_server json meshvpn_board meshvpn_config meshvpn_datapath meshvpn_log meshvpn_net meshvpn_routing meshvpn_usb meshvpn_vpn meshvpn_wifi meshvpn_storage
)
