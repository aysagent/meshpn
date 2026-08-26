# TLS + HTTP/2 VPN tunnel (phase 2)

set(MBEDTLS_DIR "$ENV{IDF_PATH}/components/mbedtls/mbedtls")

idf_component_register(
    SRCS
        "meshvpn_vpn.c"
        "meshvpn_vpn_tls.c"
        "meshvpn_vpn_bearer.c"
        "meshvpn_vpn_framing.c"
        "meshvpn_vpn_h2.c"
        "meshvpn_vpn_transparent.c"
        "meshvpn_vpn_boring.c"
        "meshvpn_enc_sni.c"
        "meshvpn_tls_ch_rebuild.c"
        "meshvpn_tls_exporter.c"
    INCLUDE_DIRS "include"
        "${MBEDTLS_DIR}/library"
    REQUIRES meshvpn_config meshvpn_storage meshvpn_boringssl esp-tls mbedtls nghttp json lwip freertos
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)
