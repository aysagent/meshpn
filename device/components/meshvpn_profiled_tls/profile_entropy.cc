#include <openssl/base.h>
#include "esp_random.h"
// Use the SDK hardware RNG, never a deterministic fallback. The standalone lab
// enables bootloader entropy with radio/ADC inactive. A product caller must keep
// the documented entropy source active (e.g. Wi-Fi); this adapter does not toggle
// ADC/clock resources behind other tasks' backs.
BSSL_NAMESPACE_BEGIN
void CRYPTO_init_sysrand() {}
void CRYPTO_sysrand(uint8_t *out, size_t n) { esp_fill_random(out,n); }
BSSL_NAMESPACE_END
