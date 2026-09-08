#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef int nvs_handle_t;
#define NVS_READWRITE 1
#define NVS_READONLY 0
esp_err_t nvs_open(const char *ns,int mode,nvs_handle_t *out);
esp_err_t nvs_get_blob(nvs_handle_t nvs,const char *key,void *out,size_t *size);
esp_err_t nvs_set_blob(nvs_handle_t nvs,const char *key,const void *data,size_t size);
esp_err_t nvs_commit(nvs_handle_t nvs);
void nvs_close(nvs_handle_t nvs);
esp_err_t nvs_get_u8(nvs_handle_t nvs,const char *key,uint8_t *value);
esp_err_t nvs_set_u8(nvs_handle_t nvs,const char *key,uint8_t value);
