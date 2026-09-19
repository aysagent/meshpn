# Apply after project(), when IDF has created the managed component target.
# Do not edit managed_components or globally change lwIP/Wi-Fi optimization:
# the first performance experiment changes only WireGuard's compilation.
option(MESHVPN_WIREGUARD_PERF "Optimize the WireGuard component for speed" ON)
idf_component_get_property(meshvpn_wireguard_lib esphome__wireguard COMPONENT_LIB)
if(MESHVPN_WIREGUARD_PERF)
    # Appended after IDF's -Og/-Os. Keep assertions, debug symbols, authentication
    # and the upstream zeroization code; no fast-math, LTO or protocol changes.
    target_compile_options(${meshvpn_wireguard_lib} PRIVATE -O2)
    message(STATUS "MeshPN WireGuard optimization: -O2 (component only)")
else()
    message(STATUS "MeshPN WireGuard optimization: IDF default (control build)")
endif()
