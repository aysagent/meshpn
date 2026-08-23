idf_component_register(
    SRCS "meshvpn_routing.c" "meshvpn_dns_proxy.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash lwip esp_netif freertos
)
