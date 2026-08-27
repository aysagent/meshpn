set(MESHVPN_STORAGE_EMBED_FILES "")
if(CONFIG_MESHVPN_STORAGE_EMBED_TEST_CERTS)
    list(APPEND MESHVPN_STORAGE_EMBED_FILES
        "certs/ca.pem"
        "certs/clean-vpn-hmac.key"
        "profiles/browser.json")
endif()

idf_component_register(
    SRCS "meshvpn_storage.c"
    INCLUDE_DIRS "include"
    REQUIRES spiffs vfs
    EMBED_FILES ${MESHVPN_STORAGE_EMBED_FILES}
)
