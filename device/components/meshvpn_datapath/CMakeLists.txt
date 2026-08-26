idf_component_register(
    SRCS "meshvpn_datapath.c"
    INCLUDE_DIRS "include"
    REQUIRES meshvpn_routing meshvpn_vpn meshvpn_net lwip
)
