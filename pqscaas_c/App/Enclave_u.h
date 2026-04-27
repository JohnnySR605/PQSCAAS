#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "pqscaas_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_GET_TIME_NS_DEFINED__
#define OCALL_GET_TIME_NS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time_ns, (uint64_t* t));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_phase2_keygen(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id, uint8_t* pk_kem, uint8_t* pk_sig, uint8_t* sealed_sk_kem, uint8_t* sealed_sk_sig);
sgx_status_t ecall_phase4_signcrypt_single(sgx_enclave_id_t eid, int* retval, const pqscaas_descriptor_t* desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc);
sgx_status_t ecall_phase4_signcrypt_batch(sgx_enclave_id_t eid, int* retval, const pqscaas_descriptor_t* descriptors, size_t n_desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc);
sgx_status_t ecall_phase5_unsigncrypt(sgx_enclave_id_t eid, int* retval, const pqscaas_signcrypted_t* sc, const uint8_t* pk_u_sig, const uint8_t* sealed_sk_r_kem, uint8_t* k_d_out);
sgx_status_t ecall_revoke_user(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id);
sgx_status_t ecall_is_revoked(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id);
sgx_status_t ecall_revoke_rebind_all(sgx_enclave_id_t eid, int* retval, uint32_t n_active_users, uint32_t n_revoked, uint64_t* elapsed_ns);
sgx_status_t ecall_phase2_keygen_batch(sgx_enclave_id_t eid, int* retval, uint32_t n_users, uint64_t* elapsed_ns_per_key);
sgx_status_t ecall_bench_ml_kem_keygen(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_ml_kem_encap(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_ml_kem_decap(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_ml_dsa_keygen(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_ml_dsa_sign(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_ml_dsa_verify(sgx_enclave_id_t eid, int* retval, uint64_t* ns);
sgx_status_t ecall_bench_seal_unseal(sgx_enclave_id_t eid, int* retval, uint64_t* seal_ns, uint64_t* unseal_ns);
sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_enclave_reset(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
