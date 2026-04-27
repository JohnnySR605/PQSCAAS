#ifndef ML_KEM_768_H
#define ML_KEM_768_H

#include <stdint.h>
#include <stddef.h>
#include "pqscaas_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-KEM-768 (NIST FIPS 203)
 *
 * Reference implementation based on the CRYSTALS-Kyber reference code
 * (pq-crystals.org), adapted for in-enclave execution.
 *
 * All functions return 0 on success, non-zero on error.
 */

int ml_kem_768_keygen(uint8_t pk[MLKEM768_PUBLICKEYBYTES],
                      uint8_t sk[MLKEM768_SECRETKEYBYTES]);

int ml_kem_768_encap(uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                     uint8_t ss[MLKEM768_SSBYTES],
                     const uint8_t pk[MLKEM768_PUBLICKEYBYTES]);

int ml_kem_768_decap(uint8_t ss[MLKEM768_SSBYTES],
                     const uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                     const uint8_t sk[MLKEM768_SECRETKEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
