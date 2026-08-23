# TLS + HTTP/2 VPN tunnel (phase 2 implementation target)

idf_component_register(
    SRCS "meshvpn_vpn.c" "meshvpn_vpn_tls.c"
    INCLUDE_DIRS "include"
    REQUIRES meshvpn_config
)
