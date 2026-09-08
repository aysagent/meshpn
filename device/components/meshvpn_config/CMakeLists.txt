idf_component_register(
    SRCS "meshvpn_config.c" "meshvpn_config_web.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash
)
