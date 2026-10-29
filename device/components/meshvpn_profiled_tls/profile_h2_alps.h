#pragma once
#include <nghttp2/nghttp2.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Fresh client session only; bounded subset shared with native clean-vpn.
 * Negotiated empty ALPS retains the ordinary first wire SETTINGS requirement.
 * Nonempty ALPS is applied without a synthetic SETTINGS ACK or stream 1 use. */
int meshvpn_h2_apply_alps(nghttp2_session *, const uint8_t *, size_t);
#ifdef __cplusplus
}
#endif
