#pragma once
#include <nghttp2/nghttp2.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Fresh sessions only. Private nghttp2 integration, tied to the CMake pin. */
int cvpn_h2_remote_alps(nghttp2_session *, nghttp2_settings_entry *, size_t);
int cvpn_h2_local_alps(nghttp2_session *, nghttp2_settings_entry *, size_t);
#ifdef __cplusplus
}
#endif
