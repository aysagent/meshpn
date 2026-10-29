#pragma once
#include <openssl/ssl.h>
#include "meshvpn_profiled_tls.h"
SSL_CTX *meshvpn_profiled_context(bool configured);
bool meshvpn_profiled_connection(SSL *ssl);
struct meshvpn_profile_gate_state {
    meshvpn_profile_check_t check{};
    unsigned hellos=0;
    int fd=-1;
    size_t sent_bytes=0;
    bool accepted=false;
};
void meshvpn_profiled_gate_install(SSL *ssl, meshvpn_profile_gate_state *state);
/* fd remains caller-owned. The BIO checks this connection's gate before every
 * write; no TLS/application bytes leave after a mismatched ClientHello. */
bool meshvpn_profiled_attach_fd(SSL *ssl, int fd, meshvpn_profile_gate_state *state);
