/*
 * PQSCAAS Enclave Implementation (Trusted Code)
 * All ECALLs execute inside the SGX enclave with real SGX SDK APIs.
 * Build with SGX_MODE=SIM for simulation mode.
 */

#include "Enclave_t.h"

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>

#include <string.h>
#include <stdlib.h>

#include "pqscaas_types.h"
#include "ml_kem_768.h"
#include "ml_dsa_65.h"
#include "aes_gcm.h"
#include "sha256.h"
#include "hkdf.h"

/* In-enclave state */
static uint8_t (*g_revoked)[USER_ID_SIZE] = nullptr;
static size_t  g_n_revoked = 0;
static size_t  g_cap_revoked = 0;

static int ensure_revoked_capacity(size_t min_cap) {
    if (g_cap_revoked >= min_cap) return 0;
    size_t new_cap = g_cap_revoked ? g_cap_revoked * 2 : 256;
    while (new_cap < min_cap) new_cap *= 2;
    uint8_t (*new_buf)[USER_ID_SIZE] = (uint8_t (*)[USER_ID_SIZE])realloc(g_revoked, new_cap * USER_ID_SIZE);
    if (!new_buf) return -1;
    g_revoked = new_buf;
    g_cap_revoked = new_cap;
    return 0;
}

static uint64_t enclave_time_ns(void) {
    uint64_t t = 0;
    /* OCALL with [out] uint64_t *t — generated stub signature is:
     *   sgx_status_t ocall_get_time_ns(uint64_t *t);
     * SGX edger8r marshalls *t back to the enclave on return.
     * Previous design used a return-value OCALL which was unreliable
     * in SIM mode, returning uninitialised stack memory and producing
     * absurd timing values (e.g. 1.4e14 ns ≈ stack pointer leak). */
    sgx_status_t st = ocall_get_time_ns(&t);
    if (st != SGX_SUCCESS) return 0;
    return t;
}

/* ECALL 1: Phase 2 Key Generation */
int ecall_phase2_keygen(
    const uint8_t *user_id,
    uint8_t *pk_kem,
    uint8_t *pk_sig,
    uint8_t *sealed_sk_kem,
    uint8_t *sealed_sk_sig)
{
    (void)user_id;
    int ret = PQSCAAS_OK;
    uint8_t sk_kem[MLKEM768_SECRETKEYBYTES];
    uint8_t sk_sig[MLDSA65_SECRETKEYBYTES];
    uint32_t sealed_size_kem = 0;
    uint32_t sealed_size_sig = 0;

    if (ml_kem_768_keygen(pk_kem, sk_kem) != 0) {
        return PQSCAAS_ERR_CRYPTO;
    }
    if (ml_dsa_65_keygen(pk_sig, sk_sig) != 0) {
        memset(sk_kem, 0, sizeof(sk_kem));
        return PQSCAAS_ERR_CRYPTO;
    }

    sealed_size_kem = sgx_calc_sealed_data_size(0, MLKEM768_SECRETKEYBYTES);
    sealed_size_sig = sgx_calc_sealed_data_size(0, MLDSA65_SECRETKEYBYTES);

    if (sealed_size_kem == UINT32_MAX || sealed_size_kem > SEALED_KEM_SK_SIZE) {
        ret = PQSCAAS_ERR_SEAL; goto out;
    }
    if (sgx_seal_data(0, nullptr, MLKEM768_SECRETKEYBYTES, sk_kem,
                      sealed_size_kem, (sgx_sealed_data_t *)sealed_sk_kem) != SGX_SUCCESS) {
        ret = PQSCAAS_ERR_SEAL; goto out;
    }
    if (sealed_size_sig == UINT32_MAX || sealed_size_sig > SEALED_SIG_SK_SIZE) {
        ret = PQSCAAS_ERR_SEAL; goto out;
    }
    if (sgx_seal_data(0, nullptr, MLDSA65_SECRETKEYBYTES, sk_sig,
                      sealed_size_sig, (sgx_sealed_data_t *)sealed_sk_sig) != SGX_SUCCESS) {
        ret = PQSCAAS_ERR_SEAL; goto out;
    }

out:
    memset(sk_kem, 0, sizeof(sk_kem));
    memset(sk_sig, 0, sizeof(sk_sig));
    return ret;
}

/* ECALL 2: Phase 4 Single Signcryption */
int ecall_phase4_signcrypt_single(
    const pqscaas_descriptor_t *desc,
    const uint8_t *pk_r_kem,
    const uint8_t *sealed_sk_u_sig,
    pqscaas_signcrypted_t *out_sc)
{
    int ret = PQSCAAS_OK;
    uint8_t sk_u_sig[MLDSA65_SECRETKEYBYTES];
    uint32_t unsealed_len = MLDSA65_SECRETKEYBYTES;
    uint8_t c_kem[MLKEM768_CIPHERTEXTBYTES];
    uint8_t k_shared[MLKEM768_SSBYTES];
    uint8_t k_mask[K_MASK_SIZE];
    uint8_t msg_to_sign[SHA256_DIGEST_SIZE + MLKEM768_CIPHERTEXTBYTES
                        + W_SIZE + NONCE_SIZE + USER_ID_SIZE];
    size_t off = 0;
    size_t sig_len = MLDSA65_SIGBYTES;

    if (sgx_unseal_data((const sgx_sealed_data_t *)sealed_sk_u_sig,
                        nullptr, nullptr, sk_u_sig, &unsealed_len) != SGX_SUCCESS) {
        return PQSCAAS_ERR_UNSEAL;
    }

    if (ml_kem_768_encap(c_kem, k_shared, pk_r_kem) != 0) {
        ret = PQSCAAS_ERR_CRYPTO; goto out;
    }

    hkdf_sha256(k_shared, MLKEM768_SSBYTES,
                desc->h_ct, SHA256_DIGEST_SIZE,
                (const uint8_t *)"K-mask", 6, k_mask, K_MASK_SIZE);

    for (size_t i = 0; i < W_SIZE; i++) {
        out_sc->wrapped[i] = desc->k_d[i] ^ k_mask[i];
    }

    memcpy(msg_to_sign + off, desc->h_ct, SHA256_DIGEST_SIZE); off += SHA256_DIGEST_SIZE;
    memcpy(msg_to_sign + off, c_kem, MLKEM768_CIPHERTEXTBYTES); off += MLKEM768_CIPHERTEXTBYTES;
    memcpy(msg_to_sign + off, out_sc->wrapped, W_SIZE); off += W_SIZE;
    memcpy(msg_to_sign + off, desc->nonce, NONCE_SIZE); off += NONCE_SIZE;
    memcpy(msg_to_sign + off, desc->sender_id, USER_ID_SIZE); off += USER_ID_SIZE;

    if (ml_dsa_65_sign(out_sc->signature, &sig_len, msg_to_sign, off, sk_u_sig) != 0) {
        ret = PQSCAAS_ERR_CRYPTO; goto out;
    }

    memcpy(out_sc->c_kem, c_kem, MLKEM768_CIPHERTEXTBYTES);
    memcpy(out_sc->h_ct, desc->h_ct, SHA256_DIGEST_SIZE);
    memcpy(out_sc->nonce, desc->nonce, NONCE_SIZE);
    memcpy(out_sc->sender_id, desc->sender_id, USER_ID_SIZE);

out:
    memset(sk_u_sig, 0, sizeof(sk_u_sig));
    memset(k_shared, 0, sizeof(k_shared));
    memset(k_mask, 0, sizeof(k_mask));
    return ret;
}

/* ECALL 3: Phase 4 Batch Signcryption */
int ecall_phase4_signcrypt_batch(
    const pqscaas_descriptor_t *descriptors,
    size_t n_desc,
    const uint8_t *pk_r_kem,
    const uint8_t *sealed_sk_u_sig,
    pqscaas_signcrypted_t *out_sc)
{
    if (n_desc == 0) return PQSCAAS_OK;

    int ret = PQSCAAS_OK;
    uint8_t sk_u_sig[MLDSA65_SECRETKEYBYTES];
    uint32_t unsealed_len = MLDSA65_SECRETKEYBYTES;

    if (sgx_unseal_data((const sgx_sealed_data_t *)sealed_sk_u_sig,
                        nullptr, nullptr, sk_u_sig, &unsealed_len) != SGX_SUCCESS) {
        return PQSCAAS_ERR_UNSEAL;
    }

    for (size_t i = 0; i < n_desc; i++) {
        uint8_t c_kem[MLKEM768_CIPHERTEXTBYTES];
        uint8_t k_shared[MLKEM768_SSBYTES];
        uint8_t k_mask[K_MASK_SIZE];
        uint8_t msg_to_sign[SHA256_DIGEST_SIZE + MLKEM768_CIPHERTEXTBYTES
                            + W_SIZE + NONCE_SIZE + USER_ID_SIZE];
        size_t off = 0;
        size_t sig_len = MLDSA65_SIGBYTES;

        if (ml_kem_768_encap(c_kem, k_shared, pk_r_kem) != 0) {
            ret = PQSCAAS_ERR_CRYPTO;
            break;
        }

        hkdf_sha256(k_shared, MLKEM768_SSBYTES,
                    descriptors[i].h_ct, SHA256_DIGEST_SIZE,
                    (const uint8_t *)"K-mask", 6, k_mask, K_MASK_SIZE);

        for (size_t b = 0; b < W_SIZE; b++) {
            out_sc[i].wrapped[b] = descriptors[i].k_d[b] ^ k_mask[b];
        }

        memcpy(msg_to_sign + off, descriptors[i].h_ct, SHA256_DIGEST_SIZE); off += SHA256_DIGEST_SIZE;
        memcpy(msg_to_sign + off, c_kem, MLKEM768_CIPHERTEXTBYTES); off += MLKEM768_CIPHERTEXTBYTES;
        memcpy(msg_to_sign + off, out_sc[i].wrapped, W_SIZE); off += W_SIZE;
        memcpy(msg_to_sign + off, descriptors[i].nonce, NONCE_SIZE); off += NONCE_SIZE;
        memcpy(msg_to_sign + off, descriptors[i].sender_id, USER_ID_SIZE); off += USER_ID_SIZE;

        if (ml_dsa_65_sign(out_sc[i].signature, &sig_len, msg_to_sign, off, sk_u_sig) != 0) {
            ret = PQSCAAS_ERR_CRYPTO;
            break;
        }

        memcpy(out_sc[i].c_kem, c_kem, MLKEM768_CIPHERTEXTBYTES);
        memcpy(out_sc[i].h_ct, descriptors[i].h_ct, SHA256_DIGEST_SIZE);
        memcpy(out_sc[i].nonce, descriptors[i].nonce, NONCE_SIZE);
        memcpy(out_sc[i].sender_id, descriptors[i].sender_id, USER_ID_SIZE);

        memset(k_shared, 0, sizeof(k_shared));
        memset(k_mask, 0, sizeof(k_mask));
    }

    memset(sk_u_sig, 0, sizeof(sk_u_sig));
    return ret;
}

/* ECALL 4: Phase 5 Unsigncryption */
int ecall_phase5_unsigncrypt(
    const pqscaas_signcrypted_t *sc,
    const uint8_t *pk_u_sig,
    const uint8_t *sealed_sk_r_kem,
    uint8_t *k_d_out)
{
    int ret = PQSCAAS_OK;
    uint8_t msg_to_verify[SHA256_DIGEST_SIZE + MLKEM768_CIPHERTEXTBYTES
                          + W_SIZE + NONCE_SIZE + USER_ID_SIZE];
    size_t off = 0;
    uint8_t sk_r_kem[MLKEM768_SECRETKEYBYTES];
    uint32_t unsealed_len = MLKEM768_SECRETKEYBYTES;
    uint8_t k_shared[MLKEM768_SSBYTES];
    uint8_t k_mask[K_MASK_SIZE];

    memcpy(msg_to_verify + off, sc->h_ct, SHA256_DIGEST_SIZE); off += SHA256_DIGEST_SIZE;
    memcpy(msg_to_verify + off, sc->c_kem, MLKEM768_CIPHERTEXTBYTES); off += MLKEM768_CIPHERTEXTBYTES;
    memcpy(msg_to_verify + off, sc->wrapped, W_SIZE); off += W_SIZE;
    memcpy(msg_to_verify + off, sc->nonce, NONCE_SIZE); off += NONCE_SIZE;
    memcpy(msg_to_verify + off, sc->sender_id, USER_ID_SIZE); off += USER_ID_SIZE;

    if (ml_dsa_65_verify(sc->signature, MLDSA65_SIGBYTES,
                         msg_to_verify, off, pk_u_sig) != 0) {
        return PQSCAAS_ERR_BAD_SIGNATURE;
    }

    for (size_t i = 0; i < g_n_revoked; i++) {
        if (memcmp(g_revoked[i], sc->sender_id, USER_ID_SIZE) == 0) {
            return PQSCAAS_ERR_REVOKED;
        }
    }

    if (sgx_unseal_data((const sgx_sealed_data_t *)sealed_sk_r_kem,
                        nullptr, nullptr, sk_r_kem, &unsealed_len) != SGX_SUCCESS) {
        return PQSCAAS_ERR_UNSEAL;
    }

    if (ml_kem_768_decap(k_shared, sc->c_kem, sk_r_kem) != 0) {
        ret = PQSCAAS_ERR_CRYPTO; goto out;
    }

    hkdf_sha256(k_shared, MLKEM768_SSBYTES,
                sc->h_ct, SHA256_DIGEST_SIZE,
                (const uint8_t *)"K-mask", 6, k_mask, K_MASK_SIZE);

    for (size_t i = 0; i < K_D_SIZE; i++) {
        k_d_out[i] = sc->wrapped[i] ^ k_mask[i];
    }

out:
    memset(sk_r_kem, 0, sizeof(sk_r_kem));
    memset(k_shared, 0, sizeof(k_shared));
    memset(k_mask, 0, sizeof(k_mask));
    return ret;
}

/* ECALL 5/6: Revocation */
int ecall_revoke_user(const uint8_t *user_id) {
    if (ensure_revoked_capacity(g_n_revoked + 1) != 0) {
        return PQSCAAS_ERR_CRYPTO;
    }
    memcpy(g_revoked[g_n_revoked], user_id, USER_ID_SIZE);
    g_n_revoked++;
    return PQSCAAS_OK;
}

int ecall_is_revoked(const uint8_t *user_id) {
    for (size_t i = 0; i < g_n_revoked; i++) {
        if (memcmp(g_revoked[i], user_id, USER_ID_SIZE) == 0) return 1;
    }
    return 0;
}

/* ECALL 7: Non-lazy rebinding benchmark */
int ecall_revoke_rebind_all(
    uint32_t n_active_users,
    uint32_t n_revoked,
    uint64_t *elapsed_ns)
{
    (void)n_revoked;
    uint8_t pk_kem[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk_kem[MLKEM768_SECRETKEYBYTES];
    uint8_t pk_sig[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk_sig[MLDSA65_SECRETKEYBYTES];
    uint64_t t0, t1;

    ml_kem_768_keygen(pk_kem, sk_kem);
    ml_dsa_65_keygen(pk_sig, sk_sig);

    t0 = enclave_time_ns();
    for (uint32_t i = 0; i < n_active_users; i++) {
        uint8_t c_kem[MLKEM768_CIPHERTEXTBYTES];
        uint8_t k_shared[MLKEM768_SSBYTES];
        uint8_t h_ct[SHA256_DIGEST_SIZE];
        uint8_t sig[MLDSA65_SIGBYTES];
        size_t slen = sizeof(sig);

        ml_kem_768_encap(c_kem, k_shared, pk_kem);
        sgx_read_rand(h_ct, SHA256_DIGEST_SIZE);
        ml_dsa_65_sign(sig, &slen, c_kem, MLKEM768_CIPHERTEXTBYTES, sk_sig);
    }
    t1 = enclave_time_ns();
    *elapsed_ns = t1 - t0;

    memset(sk_kem, 0, sizeof(sk_kem));
    memset(sk_sig, 0, sizeof(sk_sig));
    return PQSCAAS_OK;
}

/* ECALL 8: Batch keygen */
int ecall_phase2_keygen_batch(uint32_t n_users, uint64_t *elapsed_ns_per_key) {
    uint8_t pk_kem[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk_kem[MLKEM768_SECRETKEYBYTES];
    uint8_t pk_sig[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk_sig[MLDSA65_SECRETKEYBYTES];
    uint64_t t0, t1;

    t0 = enclave_time_ns();
    for (uint32_t i = 0; i < n_users; i++) {
        uint8_t sealed_k[SEALED_KEM_SK_SIZE];
        uint8_t sealed_s[SEALED_SIG_SK_SIZE];

        ml_kem_768_keygen(pk_kem, sk_kem);
        ml_dsa_65_keygen(pk_sig, sk_sig);

        sgx_seal_data(0, nullptr, MLKEM768_SECRETKEYBYTES, sk_kem,
                      sgx_calc_sealed_data_size(0, MLKEM768_SECRETKEYBYTES),
                      (sgx_sealed_data_t *)sealed_k);
        sgx_seal_data(0, nullptr, MLDSA65_SECRETKEYBYTES, sk_sig,
                      sgx_calc_sealed_data_size(0, MLDSA65_SECRETKEYBYTES),
                      (sgx_sealed_data_t *)sealed_s);
    }
    t1 = enclave_time_ns();
    *elapsed_ns_per_key = (t1 - t0) / (n_users ? n_users : 1);

    memset(sk_kem, 0, sizeof(sk_kem));
    memset(sk_sig, 0, sizeof(sk_sig));
    return PQSCAAS_OK;
}

/* ECALL 9: Primitive microbenchmarks */
int ecall_bench_ml_kem_keygen(uint64_t *ns) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
    uint64_t t0 = enclave_time_ns();
    ml_kem_768_keygen(pk, sk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    return PQSCAAS_OK;
}

int ecall_bench_ml_kem_encap(uint64_t *ns) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
    uint8_t c[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM768_SSBYTES];
    uint64_t t0;
    ml_kem_768_keygen(pk, sk);
    t0 = enclave_time_ns();
    ml_kem_768_encap(c, ss, pk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    memset(ss, 0, sizeof(ss));
    return PQSCAAS_OK;
}

int ecall_bench_ml_kem_decap(uint64_t *ns) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES], sk[MLKEM768_SECRETKEYBYTES];
    uint8_t c[MLKEM768_CIPHERTEXTBYTES], ss[MLKEM768_SSBYTES], ss2[MLKEM768_SSBYTES];
    uint64_t t0;
    ml_kem_768_keygen(pk, sk);
    ml_kem_768_encap(c, ss, pk);
    t0 = enclave_time_ns();
    ml_kem_768_decap(ss2, c, sk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    return PQSCAAS_OK;
}

int ecall_bench_ml_dsa_keygen(uint64_t *ns) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES];
    uint64_t t0 = enclave_time_ns();
    ml_dsa_65_keygen(pk, sk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    return PQSCAAS_OK;
}

int ecall_bench_ml_dsa_sign(uint64_t *ns) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES];
    uint8_t msg[256];
    uint8_t sig[MLDSA65_SIGBYTES];
    size_t slen = sizeof(sig);
    uint64_t t0;
    ml_dsa_65_keygen(pk, sk);
    sgx_read_rand(msg, sizeof(msg));
    t0 = enclave_time_ns();
    ml_dsa_65_sign(sig, &slen, msg, sizeof(msg), sk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    return PQSCAAS_OK;
}

int ecall_bench_ml_dsa_verify(uint64_t *ns) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES], sk[MLDSA65_SECRETKEYBYTES];
    uint8_t msg[256];
    uint8_t sig[MLDSA65_SIGBYTES];
    size_t slen = sizeof(sig);
    uint64_t t0;
    ml_dsa_65_keygen(pk, sk);
    sgx_read_rand(msg, sizeof(msg));
    ml_dsa_65_sign(sig, &slen, msg, sizeof(msg), sk);
    t0 = enclave_time_ns();
    ml_dsa_65_verify(sig, slen, msg, sizeof(msg), pk);
    *ns = enclave_time_ns() - t0;
    memset(sk, 0, sizeof(sk));
    return PQSCAAS_OK;
}

int ecall_bench_seal_unseal(uint64_t *seal_ns, uint64_t *unseal_ns) {
    uint8_t data[64];
    uint8_t sealed[256];
    uint8_t recovered[64];
    uint32_t rlen = sizeof(recovered);
    uint64_t t0;

    sgx_read_rand(data, sizeof(data));
    t0 = enclave_time_ns();
    sgx_seal_data(0, nullptr, sizeof(data), data,
                  sgx_calc_sealed_data_size(0, sizeof(data)),
                  (sgx_sealed_data_t *)sealed);
    *seal_ns = enclave_time_ns() - t0;

    t0 = enclave_time_ns();
    sgx_unseal_data((const sgx_sealed_data_t *)sealed,
                    nullptr, nullptr, recovered, &rlen);
    *unseal_ns = enclave_time_ns() - t0;
    return PQSCAAS_OK;
}

int ecall_enclave_init(void) {
    g_n_revoked = 0;
    g_cap_revoked = 0;
    if (g_revoked) { free(g_revoked); g_revoked = nullptr; }
    return PQSCAAS_OK;
}

int ecall_enclave_reset(void) {
    return ecall_enclave_init();
}
