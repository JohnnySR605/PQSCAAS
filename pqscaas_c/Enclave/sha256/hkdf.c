#include "hkdf.h"
#include "sha256.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[32])
{
    uint8_t k[64] = {0};
    if (key_len > 64) {
        sha256_hash(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = SHA256(ipad || data) */
    sha256_ctx_t ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    /* mac = SHA256(opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);
}

void hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len)
{
    /* Extract: PRK = HMAC(salt, ikm) */
    uint8_t prk[32];
    uint8_t zero_salt[32] = {0};
    if (!salt || salt_len == 0) {
        hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }

    /* Expand */
    uint8_t T[32];
    size_t T_len = 0;
    uint8_t counter = 1;
    size_t out_off = 0;
    while (out_off < okm_len) {
        uint8_t block[32 + 256 + 1];
        size_t bl = 0;
        memcpy(block + bl, T, T_len); bl += T_len;
        memcpy(block + bl, info, info_len); bl += info_len;
        block[bl++] = counter;
        hmac_sha256(prk, 32, block, bl, T);
        T_len = 32;

        size_t to_copy = (okm_len - out_off < 32) ? okm_len - out_off : 32;
        memcpy(okm + out_off, T, to_copy);
        out_off += to_copy;
        counter++;
    }
}
