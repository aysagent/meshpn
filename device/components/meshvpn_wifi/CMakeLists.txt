idf_component_register(
    SRCS "meshvpn_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_netif esp_event meshvpn_config
)
