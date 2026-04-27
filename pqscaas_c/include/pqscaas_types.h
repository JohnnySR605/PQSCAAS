#ifndef PQSCAAS_TYPES_H
#define PQSCAAS_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ========================================================================
 * ML-KEM-768 Parameters (NIST FIPS 203)
 * ======================================================================== */
#define MLKEM768_PUBLICKEYBYTES  1184
#define MLKEM768_SECRETKEYBYTES  2400
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_SSBYTES          32

/* ========================================================================
 * ML-DSA-65 Parameters (NIST FIPS 204)
 * ======================================================================== */
#define MLDSA65_PUBLICKEYBYTES   1952
#define MLDSA65_SECRETKEYBYTES   4032
#define MLDSA65_SIGBYTES         3309

/* ========================================================================
 * Symmetric primitives
 * ======================================================================== */
#define AES_KEY_SIZE      32   /* AES-256 */
#define AES_GCM_IV_SIZE   12
#define AES_GCM_TAG_SIZE  16
#define SHA256_DIGEST_SIZE 32
#define HKDF_OUTPUT_SIZE  32

/* ========================================================================
 * PQSCAAS Protocol constants
 * ======================================================================== */
#define K_D_SIZE          32   /* Data encryption key */
#define K_MASK_SIZE       32   /* Deferred-binding mask */
#define W_SIZE            32   /* Wrapped key */
#define NONCE_SIZE        16   /* Request nonce */
#define USER_ID_SIZE      32   /* User identifier */

#define BATCH_CAPACITY    50   /* Batch size B */
#define TAU_RHO_NUM       8    /* Utilization threshold numerator (0.8) */
#define TAU_RHO_DEN       10   /* Utilization threshold denominator */

/* ========================================================================
 * Request descriptor (Phase 3→4 client→server)
 * ======================================================================== */
typedef struct pqscaas_descriptor {
    uint8_t  nonce[NONCE_SIZE];
    uint8_t  sender_id[USER_ID_SIZE];
    uint8_t  h_ct[SHA256_DIGEST_SIZE];   /* SHA-256 of ciphertext */
    uint8_t  k_d[K_D_SIZE];              /* Data key (sealed from client) */
    uint32_t ciphertext_len;
    uint64_t timestamp_ns;
} pqscaas_descriptor_t;

/* ========================================================================
 * Signcrypted output (Phase 4 output)
 * ======================================================================== */
typedef struct pqscaas_signcrypted {
    uint8_t c_kem[MLKEM768_CIPHERTEXTBYTES];
    uint8_t wrapped[W_SIZE];
    uint8_t signature[MLDSA65_SIGBYTES];
    uint8_t h_ct[SHA256_DIGEST_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t sender_id[USER_ID_SIZE];
} pqscaas_signcrypted_t;

/* ========================================================================
 * Sealed key blob sizes
 * ======================================================================== */
#define SEALED_KEM_SK_SIZE (MLKEM768_SECRETKEYBYTES + 576)  /* +sgx_sealed_data_t */
#define SEALED_SIG_SK_SIZE (MLDSA65_SECRETKEYBYTES + 576)

/* ========================================================================
 * Return codes
 * ======================================================================== */
#define PQSCAAS_OK                  0
#define PQSCAAS_ERR_INVALID_PARAM  -1
#define PQSCAAS_ERR_CRYPTO         -2
#define PQSCAAS_ERR_SEAL           -3
#define PQSCAAS_ERR_UNSEAL         -4
#define PQSCAAS_ERR_REVOKED        -5
#define PQSCAAS_ERR_BAD_SIGNATURE  -6
#define PQSCAAS_ERR_BAD_HASH       -7

#endif /* PQSCAAS_TYPES_H */
