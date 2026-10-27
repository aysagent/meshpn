idf_component_register(
    SRCS "meshvpn_config.c" "meshvpn_config_web.c" "meshvpn_config_hostname.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash
)
