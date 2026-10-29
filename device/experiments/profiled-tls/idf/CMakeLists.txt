cmake_minimum_required(VERSION 3.16)
# Deliberately separate from the product: never included in its component path.
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(meshpn_tls_feasibility)
