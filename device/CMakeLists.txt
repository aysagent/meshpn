cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{BOARD} AND NOT "$ENV{BOARD}" STREQUAL "")
    set(MESHVPN_BOARD $ENV{BOARD})
else()
    set(MESHVPN_BOARD "xiao_esp32s3")
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

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(meshvpn_device)

idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_SOURCE_DIR}/components/meshvpn_net/include" APPEND)
