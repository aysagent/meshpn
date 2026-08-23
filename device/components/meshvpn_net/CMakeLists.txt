idf_component_register(
    SRCS "meshvpn_net.c" "meshvpn_net_hooks.c"
    INCLUDE_DIRS "include"
    REQUIRES iot_bridge esp_netif esp_event meshvpn_usb meshvpn_wifi meshvpn_routing lwip
)
