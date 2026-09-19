#pragma once
/* The AEAD-only test does not compile WireGuard handshakes or call X25519.
 * crypto.h includes sodium.h for that unrelated macro. Production firmware
 * still uses the actual libsodium component; no AEAD symbols are mocked here. */
