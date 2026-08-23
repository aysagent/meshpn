idf_component_register(
    SRCS "meshvpn_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif esp_tinyusb tinyusb
)
