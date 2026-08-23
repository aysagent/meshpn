idf_component_register(
    SRCS "meshvpn_log.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_common espcoredump esp_system
    PRIV_REQUIRES freertos
)
