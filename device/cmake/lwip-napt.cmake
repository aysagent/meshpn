# Replace ESP-IDF's NAPT source with a generated build copy.  The checkout in
# IDF_PATH remains untouched, and the generator refuses unknown source layout.
idf_component_get_property(meshvpn_lwip_lib lwip COMPONENT_LIB)
idf_component_get_property(meshvpn_lwip_dir lwip COMPONENT_DIR)
idf_build_get_property(meshvpn_lwip_python PYTHON)
set(meshvpn_napt_original "${meshvpn_lwip_dir}/lwip/src/core/ipv4/ip4_napt.c")
set(meshvpn_napt_generator "${CMAKE_SOURCE_DIR}/scripts/patch-lwip-napt.py")
set(meshvpn_napt_generated "${CMAKE_BINARY_DIR}/meshpn-generated/ip4_napt.c")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${meshvpn_napt_original}" "${meshvpn_napt_generator}")
execute_process(
    COMMAND "${meshvpn_lwip_python}" "${meshvpn_napt_generator}"
            "${meshvpn_napt_original}" "${meshvpn_napt_generated}"
    RESULT_VARIABLE meshvpn_napt_result
    ERROR_VARIABLE meshvpn_napt_error)
if(NOT meshvpn_napt_result EQUAL 0)
    message(FATAL_ERROR "lwIP NAPT patch failed: ${meshvpn_napt_error}")
endif()

get_target_property(meshvpn_lwip_sources ${meshvpn_lwip_lib} SOURCES)
set(meshvpn_lwip_matches 0)
set(meshvpn_lwip_replaced "")
foreach(meshvpn_lwip_source IN LISTS meshvpn_lwip_sources)
    if(meshvpn_lwip_source MATCHES "(^|/)lwip/src/core/ipv4/ip4_napt\\.c$")
        list(APPEND meshvpn_lwip_replaced "${meshvpn_napt_generated}")
        math(EXPR meshvpn_lwip_matches "${meshvpn_lwip_matches}+1")
    else()
        list(APPEND meshvpn_lwip_replaced "${meshvpn_lwip_source}")
    endif()
endforeach()
if(NOT meshvpn_lwip_matches EQUAL 1)
    message(FATAL_ERROR "Expected one lwIP NAPT source, found ${meshvpn_lwip_matches}")
endif()
set_property(TARGET ${meshvpn_lwip_lib} PROPERTY SOURCES "${meshvpn_lwip_replaced}")
message(STATUS "MeshPN: lwIP NAPT TCP retransmit RST fix enabled")
