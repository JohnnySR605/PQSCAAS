#ifndef ML_DSA_65_H
#define ML_DSA_65_H

#include <stdint.h>
#include <stddef.h>
#include "pqscaas_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int ml_dsa_65_keygen(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
                     uint8_t sk[MLDSA65_SECRETKEYBYTES]);

int ml_dsa_65_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t sk[MLDSA65_SECRETKEYBYTES]);

int ml_dsa_65_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t pk[MLDSA65_PUBLICKEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
