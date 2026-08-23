if(NOT DEFINED ENV{BOARD})
    set(MESHVPN_BOARD_DIR "xiao_esp32s3")
else()
    set(MESHVPN_BOARD_DIR $ENV{BOARD})
endif()

idf_component_register(
    SRCS "meshvpn_board.c"
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/boards/${MESHVPN_BOARD_DIR}"
    REQUIRES driver
)
