#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/refc/chacha20poly1305.h"

/* Actual pinned dependency, not a replacement crypto implementation. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    size_t n = (size_t)atoi(argv[1]);
    assert(n <= 1500);
    uint8_t key[32], plain[1500], encrypted[1516], inplace[1516], decoded[1500];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    for (size_t i = 0; i < n; i++) plain[i] = (uint8_t)(i * 17 + 3);
    chacha20poly1305_encrypt(encrypted, plain, n, NULL, 0, 7, key);
    memcpy(inplace, plain, n);
    chacha20poly1305_encrypt(inplace, inplace, n, NULL, 0, 7, key);
    assert(!memcmp(inplace, encrypted, n + 16));
    assert(chacha20poly1305_decrypt(decoded, encrypted, n + 16, NULL, 0, 7, key));
    assert(!memcmp(decoded, plain, n));
    assert(chacha20poly1305_decrypt(inplace, inplace, n + 16, NULL, 0, 7, key));
    assert(!memcmp(inplace, plain, n));
    /* Bad tag must fail before releasing plaintext, including empty keepalive. */
    encrypted[n + 15] ^= 1;
    memset(decoded, 0xa5, sizeof(decoded));
    assert(!chacha20poly1305_decrypt(decoded, encrypted, n + 16, NULL, 0, 7, key));
    for (size_t i = 0; i < sizeof(decoded); i++) assert(decoded[i] == 0xa5);
    encrypted[n + 15] ^= 1;
    assert(!chacha20poly1305_decrypt(decoded, encrypted, n + 16, NULL, 0, 8, key));
    assert(!chacha20poly1305_decrypt(decoded, encrypted, 15, NULL, 0, 7, key));
    assert(fwrite(encrypted, 1, n + 16, stdout) == n + 16);
}
