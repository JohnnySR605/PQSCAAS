#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "pqscaas_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_phase2_keygen(const uint8_t* user_id, uint8_t* pk_kem, uint8_t* pk_sig, uint8_t* sealed_sk_kem, uint8_t* sealed_sk_sig);
int ecall_phase4_signcrypt_single(const pqscaas_descriptor_t* desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc);
int ecall_phase4_signcrypt_batch(const pqscaas_descriptor_t* descriptors, size_t n_desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc);
int ecall_phase5_unsigncrypt(const pqscaas_signcrypted_t* sc, const uint8_t* pk_u_sig, const uint8_t* sealed_sk_r_kem, uint8_t* k_d_out);
int ecall_revoke_user(const uint8_t* user_id);
int ecall_is_revoked(const uint8_t* user_id);
int ecall_revoke_rebind_all(uint32_t n_active_users, uint32_t n_revoked, uint64_t* elapsed_ns);
int ecall_phase2_keygen_batch(uint32_t n_users, uint64_t* elapsed_ns_per_key);
int ecall_bench_ml_kem_keygen(uint64_t* ns);
int ecall_bench_ml_kem_encap(uint64_t* ns);
int ecall_bench_ml_kem_decap(uint64_t* ns);
int ecall_bench_ml_dsa_keygen(uint64_t* ns);
int ecall_bench_ml_dsa_sign(uint64_t* ns);
int ecall_bench_ml_dsa_verify(uint64_t* ns);
int ecall_bench_seal_unseal(uint64_t* seal_ns, uint64_t* unseal_ns);
int ecall_enclave_init(void);
int ecall_enclave_reset(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_get_time_ns(uint64_t* t);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
