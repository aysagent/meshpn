#pragma once
#include "profile_model.h"
#define MESHPN_CAPTURE_HELLO_MAX 8192
/* Incremental TLS-record reassembly. Fixed memory, no allocation, no TLS reply. */
typedef struct {
 uint8_t hello[MESHPN_CAPTURE_HELLO_MAX], header[5];
 size_t length, expected, wire_bytes;
 unsigned header_length, remaining, records;
 bool failed;
} meshpn_hello_capture_t;
#ifdef __cplusplus
extern "C" {
#endif
/* 0: incomplete; 1: complete first ClientHello; -1: invalid/limit. */
int meshpn_hello_capture_feed(meshpn_hello_capture_t *s,const uint8_t *bytes,size_t length);
/* Call on the PSRAM worker. Captures structural values, never keys/random/SNI. */
bool meshpn_profile_from_hello(const uint8_t *hello,size_t length,const char *expected_host,
                              const char *name,meshpn_tls_profile_t *out,const char **reason);
#ifdef __cplusplus
}
#endif
