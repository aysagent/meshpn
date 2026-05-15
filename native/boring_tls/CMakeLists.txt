cmake_minimum_required(VERSION 3.16)
project(boring_tls_helper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Ожидаемый SHA дерева BoringSSL (должен совпадать с GIT_TAG ниже и с патчем).
set(MESHVPN_BORINGSSL_PINNED_SHA "a7481f34712bc056a47ab91015536166b3a6cebb")

# BoringSSL — закреплённый коммит (обновлять осознанно вместе с эталоном Chrome / JA).
# GIT_SHALLOW нельзя: для произвольного SHA shallow clone даёт «reference is not a tree» на Linux/Git.
FetchContent_Declare(
  boringssl
  GIT_REPOSITORY https://github.com/google/boringssl.git
  GIT_TAG        ${MESHVPN_BORINGSSL_PINNED_SHA}
  GIT_SHALLOW    FALSE
)
# Юнит-тесты BoringSSL (ssl_test, crypto_test, …) не нужны для helper и при
# `cmake --build ...` без явной цели попадают в ALL — на VPS с 1–2 ГБ RAM типичен
# OOM killer («c++: fatal error: Killed signal terminated program cc1plus»).
set(BUILD_TESTING OFF CACHE BOOL "BoringSSL unit tests (disable on low-RAM VPS)" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(boringssl)

find_package(Git REQUIRED)
find_program(MESHVPN_PATCH_EXECUTABLE patch REQUIRED)

execute_process(
  COMMAND "${GIT_EXECUTABLE}" -C "${boringssl_SOURCE_DIR}" rev-parse HEAD
  OUTPUT_VARIABLE _meshvpn_bssl_head
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _meshvpn_git_rc)
if(NOT _meshvpn_git_rc EQUAL 0)
  message(FATAL_ERROR "mesh-vpn: не удалось выполнить git rev-parse в ${boringssl_SOURCE_DIR}")
endif()
if(NOT _meshvpn_bssl_head STREQUAL MESHVPN_BORINGSSL_PINNED_SHA)
  message(FATAL_ERROR
    "mesh-vpn: клон BoringSSL имеет HEAD ${_meshvpn_bssl_head}, ожидается ${MESHVPN_BORINGSSL_PINNED_SHA}. "
    "Обновите GIT_TAG и при необходимости патч patches/boringssl-meshvpn-tls13-cipher-order.patch.")
endif()

file(STRINGS "${boringssl_SOURCE_DIR}/ssl/internal.h" _meshvpn_tls13_cipher_marker
  REGEX tls13_client_cipher_order LIMIT_COUNT 1)
if(NOT _meshvpn_tls13_cipher_marker)
  execute_process(
    COMMAND "${MESHVPN_PATCH_EXECUTABLE}" -p0 -i "${CMAKE_CURRENT_SOURCE_DIR}/patches/boringssl-meshvpn-tls13-cipher-order.patch"
    WORKING_DIRECTORY "${boringssl_SOURCE_DIR}"
    RESULT_VARIABLE _meshvpn_patch_rc
    OUTPUT_VARIABLE _meshvpn_patch_out
    ERROR_VARIABLE _meshvpn_patch_err)
  if(NOT _meshvpn_patch_rc EQUAL 0)
    message(FATAL_ERROR
      "mesh-vpn: не удалось применить патч BoringSSL (${MESHVPN_BORINGSSL_PINNED_SHA}). "
      "Обновите patches/boringssl-meshvpn-tls13-cipher-order.patch под текущее дерево или откатите GIT_TAG.\n"
      "patch stdout:\n${_meshvpn_patch_out}\nstderr:\n${_meshvpn_patch_err}")
  endif()
endif()

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(json)

add_executable(boring-tls-helper helper_main.cc)
target_include_directories(boring-tls-helper PRIVATE ${boringssl_SOURCE_DIR}/include)
target_link_libraries(boring-tls-helper PRIVATE ssl crypto)
target_link_libraries(boring-tls-helper PRIVATE nlohmann_json::nlohmann_json)

set_target_properties(boring-tls-helper PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
