cmake_minimum_required(VERSION 3.16)
project(boring_tls_helper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# BoringSSL — закреплённый коммит (обновлять осознанно вместе с эталоном Chrome / JA).
FetchContent_Declare(
  boringssl
  GIT_REPOSITORY https://github.com/google/boringssl.git
  GIT_TAG        a7481f34712bc056a47ab91015536166b3a6cebb
  GIT_SHALLOW    TRUE
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(boringssl)

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
