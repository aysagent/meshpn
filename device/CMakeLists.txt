cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{BOARD} AND NOT "$ENV{BOARD}" STREQUAL "")
    set(MESHVPN_BOARD $ENV{BOARD})
else()
    set(MESHVPN_BOARD "xiao_esp32s3")
endif()

set(MESHVPN_BOARD_TARGET_FILE "${CMAKE_SOURCE_DIR}/boards/${MESHVPN_BOARD}/target")
if(NOT EXISTS "${MESHVPN_BOARD_TARGET_FILE}")
    message(FATAL_ERROR "Unknown board '${MESHVPN_BOARD}' or missing target metadata")
endif()
file(READ "${MESHVPN_BOARD_TARGET_FILE}" MESHVPN_BOARD_TARGET)
string(STRIP "${MESHVPN_BOARD_TARGET}" MESHVPN_BOARD_TARGET)
if(DEFINED IDF_TARGET AND NOT "${IDF_TARGET}" STREQUAL "${MESHVPN_BOARD_TARGET}")
    message(FATAL_ERROR "Board ${MESHVPN_BOARD} requires IDF_TARGET=${MESHVPN_BOARD_TARGET}, got ${IDF_TARGET}")
endif()
set(IDF_TARGET "${MESHVPN_BOARD_TARGET}")

# P4 uses a project-owned bridge implementation because iot_bridge 1.1 only
# supports S2/S3. Keep its compatibility Kconfig out of S3 builds so the
# upstream iot_bridge symbols are each defined exactly once.
if("${MESHVPN_BOARD_TARGET}" STREQUAL "esp32p4")
    list(APPEND EXTRA_COMPONENT_DIRS
        "${CMAKE_SOURCE_DIR}/target_components/esp32p4_bridge_config")
endif()

if(DEFINED ENV{USB_PROFILE} AND NOT "$ENV{USB_PROFILE}" STREQUAL "")
    set(MESHVPN_USB_PROFILE $ENV{USB_PROFILE})
else()
    set(MESHVPN_USB_PROFILE "ncm")
endif()

set(SDKCONFIG_DEFAULTS
    "${CMAKE_SOURCE_DIR}/sdkconfig.defaults"
    "${CMAKE_SOURCE_DIR}/boards/${MESHVPN_BOARD}/sdkconfig.defaults"
    "${CMAKE_SOURCE_DIR}/profiles/usb_${MESHVPN_USB_PROFILE}.defconfig"
)
if("$ENV{USB_DIAGNOSTICS}" STREQUAL "1")
    list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_SOURCE_DIR}/profiles/usb_diagnostics.defconfig")
endif()
if("$ENV{DWC2_TELEMETRY}" STREQUAL "0")
    list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_SOURCE_DIR}/profiles/dwc2_telemetry_off.defconfig")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(DEPENDENCIES_LOCK
    "${CMAKE_SOURCE_DIR}/dependencies.lock.${IDF_TARGET}")
project(meshvpn_device)
include("${CMAKE_SOURCE_DIR}/cmake/wireguard-performance.cmake")
if(CONFIG_MESHVPN_VPN_ENABLE AND NOT CONFIG_LWIP_IP4_REASSEMBLY)
    message(FATAL_ERROR "VPN forwarding requires IPv4 reassembly before NAPT. Regenerate sdkconfig.")
endif()
if(NOT "${IDF_TARGET}" STREQUAL "${MESHVPN_BOARD_TARGET}")
    message(FATAL_ERROR "Resolved IDF target ${IDF_TARGET} does not match board ${MESHVPN_BOARD_TARGET}")
endif()
include("${CMAKE_SOURCE_DIR}/cmake/ncm-telemetry.cmake")
if("$ENV{DWC2_TELEMETRY}" STREQUAL "0" AND CONFIG_MESHVPN_DWC2_TELEMETRY)
    message(FATAL_ERROR "Control build has stale DWC2 telemetry enabled; use a fresh SDKCONFIG.")
endif()

# Refuse stale/unsafe sdkconfig rather than silently exposing the uplink.
if(CONFIG_LWIP_IPV6)
    message(FATAL_ERROR "This firmware currently supports IPv4 only. Regenerate sdkconfig with device/scripts/flash.sh.")
endif()
if(CONFIG_MDNS_PREDEF_NETIF_STA OR CONFIG_MDNS_PREDEF_NETIF_AP OR CONFIG_MDNS_PREDEF_NETIF_ETH)
    message(FATAL_ERROR "mDNS must use only the custom USB netif. Regenerate sdkconfig with device/scripts/flash.sh.")
endif()
if(NOT CONFIG_BRIDGE_STATION_CANCEL_AUTO_CONNECT_WHEN_DISCONNECTED)
    message(FATAL_ERROR "Disable iot_bridge reconnect: the WiFi profile manager owns reconnect.")
endif()
if(CONFIG_BRIDGE_WIFI_PMF_DISABLE)
    message(FATAL_ERROR "Global PMF disable is incompatible with saved WPA3 profiles.")
endif()

if(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    string(LENGTH "${CONFIG_BRIDGE_SOFTAP_SSID}" ap_ssid_length)
    string(LENGTH "${CONFIG_BRIDGE_SOFTAP_PASSWORD}" ap_password_length)
    if(ap_ssid_length LESS 1 OR ap_ssid_length GREATER 32 OR
       (CONFIG_BRIDGE_SOFTAP_SSID_END_WITH_THE_MAC AND ap_ssid_length GREATER 25))
        message(FATAL_ERROR "SoftAP SSID must be 1..32 bytes, or at most 25 with MAC suffix.")
    endif()
    if(ap_password_length LESS 8 OR ap_password_length GREATER 63)
        message(FATAL_ERROR "SoftAP requires a WPA2 password of 8..63 bytes; open AP is not supported.")
    endif()
endif()

idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_SOURCE_DIR}/components/meshvpn_net/include" APPEND)
