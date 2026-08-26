idf_component_register(
    SRCS "meshvpn_boringssl.c"
    INCLUDE_DIRS "include"
    REQUIRES json meshvpn_storage meshvpn_config
)
