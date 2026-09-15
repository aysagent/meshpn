set(meshvpn_net_requires
    esp_netif esp_event esp_wifi meshvpn_usb meshvpn_wifi meshvpn_routing lwip mdns
)
if(NOT IDF_TARGET STREQUAL "esp32p4")
    list(APPEND meshvpn_net_requires iot_bridge)
endif()

idf_component_register(
    SRCS "meshvpn_net.c" "meshvpn_net_hooks.c" "meshvpn_net_dhcp.c"
    INCLUDE_DIRS "include"
    REQUIRES ${meshvpn_net_requires}
)
