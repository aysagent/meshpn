#include <openssl/base.h>
#include "esp_random.h"
// Probe only: no radio is started. Explicitly enable the internal entropy source
// for this standalone image before BoringSSL is used. Never use this arrangement
// as a substitute for auditing coexistence with the product's Wi-Fi/ADC use.
BSSL_NAMESPACE_BEGIN
void CRYPTO_init_sysrand() {}
void CRYPTO_sysrand(uint8_t *out, size_t n) { esp_fill_random(out,n); }
BSSL_NAMESPACE_END
