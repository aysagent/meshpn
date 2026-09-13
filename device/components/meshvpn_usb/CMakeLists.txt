idf_component_register(
    SRCS "meshvpn_usb.c" "meshvpn_ncm_diag.c" "meshvpn_usb_tx_queue.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif esp_tinyusb tinyusb esp_timer
)
if(CONFIG_MESHVPN_USB_NCM_DOUBLE_BUFFER)
    # Inspect the same built-in FS descriptor iot_bridge passes to TinyUSB.
    idf_component_get_property(usb_wrapper_dir espressif__esp_tinyusb COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${usb_wrapper_dir}/include_private")
endif()
