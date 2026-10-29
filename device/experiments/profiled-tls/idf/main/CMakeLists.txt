idf_component_register(SRCS "main.cc" "../../bssl_probe.cc" INCLUDE_DIRS "../.." REQUIRES bssl esp_hw_support bootloader_support)

target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
