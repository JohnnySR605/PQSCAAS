#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES-256-GCM (encrypt-only used for PQSCAAS Phase 3).
 * Returns 0 on success.
 */
int aes256_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext,
    uint8_t tag[16]);

int aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t iv[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
