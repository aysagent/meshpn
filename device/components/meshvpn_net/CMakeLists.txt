set(meshvpn_net_requires
    esp_netif esp_event esp_wifi meshvpn_config meshvpn_usb meshvpn_wifi meshvpn_routing meshvpn_vpn lwip mdns
)
if(NOT IDF_TARGET STREQUAL "esp32p4")
    list(APPEND meshvpn_net_requires iot_bridge)
else()
    set(meshvpn_ap_probe_source "meshvpn_ap_probe.c" "meshvpn_ap_echo.c" "meshvpn_net_bench.c")
endif()

idf_component_register(
    SRCS "meshvpn_net.c" "meshvpn_net_hooks.c" "meshvpn_net_dhcp.c" ${meshvpn_ap_probe_source}
    INCLUDE_DIRS "include"
    REQUIRES ${meshvpn_net_requires}
)
