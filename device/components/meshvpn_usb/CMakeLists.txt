idf_component_register(
    SRCS "meshvpn_usb.c" "meshvpn_ncm_diag.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif esp_tinyusb tinyusb esp_timer
)
