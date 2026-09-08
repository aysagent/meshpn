idf_component_register(
    SRCS "meshvpn_routing.c" "meshvpn_dns_proxy.c" "meshvpn_dns_wire.c" "meshvpn_ip_ranges.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash lwip esp_netif freertos esp_timer esp_hw_support
)
