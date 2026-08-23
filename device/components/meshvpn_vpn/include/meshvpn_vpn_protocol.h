#pragma once

/* clean-vpn --type=tls client constants (phase 2). */

#define MESHVPN_TLS_EXPORTER_LABEL "EXPORTER-clean-vpn-bind"
#define MESHVPN_TLS_EXPORTER_LEN 32
#define MESHVPN_TLS_BEARER_WINDOW_SEC (15 * 60)
#define MESHVPN_TLS_HTTP_PATH "/clean-vpn"
#define MESHVPN_TLS_HMAC_PREFIX "clean-vpn-tls-v2:"
