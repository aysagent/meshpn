#pragma once
#include "esp_err.h"
#include <stdbool.h>
#define MESHVPN_CLIENT_CERT_MAX 8192
#define MESHVPN_CLIENT_KEY_MAX 4096
/* PSRAM allocation, never returned through the diagnostics API. */
typedef struct {
    char certificate[MESHVPN_CLIENT_CERT_MAX+1];
    char private_key[MESHVPN_CLIENT_KEY_MAX+1];
} meshvpn_client_identity_t;
esp_err_t meshvpn_client_identity_load(meshvpn_client_identity_t **identity);
esp_err_t meshvpn_client_identity_save(const char *certificate,const char *private_key);
bool meshvpn_client_identity_configured(void);
bool meshvpn_client_identity_valid(const char *certificate,const char *private_key);
void meshvpn_client_identity_free(meshvpn_client_identity_t *identity);
