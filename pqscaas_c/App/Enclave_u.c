#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_phase2_keygen_t {
	int ms_retval;
	const uint8_t* ms_user_id;
	uint8_t* ms_pk_kem;
	uint8_t* ms_pk_sig;
	uint8_t* ms_sealed_sk_kem;
	uint8_t* ms_sealed_sk_sig;
} ms_ecall_phase2_keygen_t;

typedef struct ms_ecall_phase4_signcrypt_single_t {
	int ms_retval;
	const pqscaas_descriptor_t* ms_desc;
	const uint8_t* ms_pk_r_kem;
	const uint8_t* ms_sealed_sk_u_sig;
	pqscaas_signcrypted_t* ms_out_sc;
} ms_ecall_phase4_signcrypt_single_t;

typedef struct ms_ecall_phase4_signcrypt_batch_t {
	int ms_retval;
	const pqscaas_descriptor_t* ms_descriptors;
	size_t ms_n_desc;
	const uint8_t* ms_pk_r_kem;
	const uint8_t* ms_sealed_sk_u_sig;
	pqscaas_signcrypted_t* ms_out_sc;
} ms_ecall_phase4_signcrypt_batch_t;

typedef struct ms_ecall_phase5_unsigncrypt_t {
	int ms_retval;
	const pqscaas_signcrypted_t* ms_sc;
	const uint8_t* ms_pk_u_sig;
	const uint8_t* ms_sealed_sk_r_kem;
	uint8_t* ms_k_d_out;
} ms_ecall_phase5_unsigncrypt_t;

typedef struct ms_ecall_revoke_user_t {
	int ms_retval;
	const uint8_t* ms_user_id;
} ms_ecall_revoke_user_t;

typedef struct ms_ecall_is_revoked_t {
	int ms_retval;
	const uint8_t* ms_user_id;
} ms_ecall_is_revoked_t;

typedef struct ms_ecall_revoke_rebind_all_t {
	int ms_retval;
	uint32_t ms_n_active_users;
	uint32_t ms_n_revoked;
	uint64_t* ms_elapsed_ns;
} ms_ecall_revoke_rebind_all_t;

typedef struct ms_ecall_phase2_keygen_batch_t {
	int ms_retval;
	uint32_t ms_n_users;
	uint64_t* ms_elapsed_ns_per_key;
} ms_ecall_phase2_keygen_batch_t;

typedef struct ms_ecall_bench_ml_kem_keygen_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_kem_keygen_t;

typedef struct ms_ecall_bench_ml_kem_encap_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_kem_encap_t;

typedef struct ms_ecall_bench_ml_kem_decap_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_kem_decap_t;

typedef struct ms_ecall_bench_ml_dsa_keygen_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_dsa_keygen_t;

typedef struct ms_ecall_bench_ml_dsa_sign_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_dsa_sign_t;

typedef struct ms_ecall_bench_ml_dsa_verify_t {
	int ms_retval;
	uint64_t* ms_ns;
} ms_ecall_bench_ml_dsa_verify_t;

typedef struct ms_ecall_bench_seal_unseal_t {
	int ms_retval;
	uint64_t* ms_seal_ns;
	uint64_t* ms_unseal_ns;
} ms_ecall_bench_seal_unseal_t;

typedef struct ms_ecall_enclave_init_t {
	int ms_retval;
} ms_ecall_enclave_init_t;

typedef struct ms_ecall_enclave_reset_t {
	int ms_retval;
} ms_ecall_enclave_reset_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_get_time_ns_t {
	uint64_t* ms_t;
} ms_ocall_get_time_ns_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_time_ns(void* pms)
{
	ms_ocall_get_time_ns_t* ms = SGX_CAST(ms_ocall_get_time_ns_t*, pms);
	ocall_get_time_ns(ms->ms_t);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Enclave = {
	7,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_get_time_ns,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_phase2_keygen(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id, uint8_t* pk_kem, uint8_t* pk_sig, uint8_t* sealed_sk_kem, uint8_t* sealed_sk_sig)
{
	sgx_status_t status;
	ms_ecall_phase2_keygen_t ms;
	ms.ms_user_id = user_id;
	ms.ms_pk_kem = pk_kem;
	ms.ms_pk_sig = pk_sig;
	ms.ms_sealed_sk_kem = sealed_sk_kem;
	ms.ms_sealed_sk_sig = sealed_sk_sig;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase4_signcrypt_single(sgx_enclave_id_t eid, int* retval, const pqscaas_descriptor_t* desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc)
{
	sgx_status_t status;
	ms_ecall_phase4_signcrypt_single_t ms;
	ms.ms_desc = desc;
	ms.ms_pk_r_kem = pk_r_kem;
	ms.ms_sealed_sk_u_sig = sealed_sk_u_sig;
	ms.ms_out_sc = out_sc;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase4_signcrypt_batch(sgx_enclave_id_t eid, int* retval, const pqscaas_descriptor_t* descriptors, size_t n_desc, const uint8_t* pk_r_kem, const uint8_t* sealed_sk_u_sig, pqscaas_signcrypted_t* out_sc)
{
	sgx_status_t status;
	ms_ecall_phase4_signcrypt_batch_t ms;
	ms.ms_descriptors = descriptors;
	ms.ms_n_desc = n_desc;
	ms.ms_pk_r_kem = pk_r_kem;
	ms.ms_sealed_sk_u_sig = sealed_sk_u_sig;
	ms.ms_out_sc = out_sc;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase5_unsigncrypt(sgx_enclave_id_t eid, int* retval, const pqscaas_signcrypted_t* sc, const uint8_t* pk_u_sig, const uint8_t* sealed_sk_r_kem, uint8_t* k_d_out)
{
	sgx_status_t status;
	ms_ecall_phase5_unsigncrypt_t ms;
	ms.ms_sc = sc;
	ms.ms_pk_u_sig = pk_u_sig;
	ms.ms_sealed_sk_r_kem = sealed_sk_r_kem;
	ms.ms_k_d_out = k_d_out;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_revoke_user(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id)
{
	sgx_status_t status;
	ms_ecall_revoke_user_t ms;
	ms.ms_user_id = user_id;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_is_revoked(sgx_enclave_id_t eid, int* retval, const uint8_t* user_id)
{
	sgx_status_t status;
	ms_ecall_is_revoked_t ms;
	ms.ms_user_id = user_id;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_revoke_rebind_all(sgx_enclave_id_t eid, int* retval, uint32_t n_active_users, uint32_t n_revoked, uint64_t* elapsed_ns)
{
	sgx_status_t status;
	ms_ecall_revoke_rebind_all_t ms;
	ms.ms_n_active_users = n_active_users;
	ms.ms_n_revoked = n_revoked;
	ms.ms_elapsed_ns = elapsed_ns;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase2_keygen_batch(sgx_enclave_id_t eid, int* retval, uint32_t n_users, uint64_t* elapsed_ns_per_key)
{
	sgx_status_t status;
	ms_ecall_phase2_keygen_batch_t ms;
	ms.ms_n_users = n_users;
	ms.ms_elapsed_ns_per_key = elapsed_ns_per_key;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_kem_keygen(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_kem_keygen_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_kem_encap(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_kem_encap_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_kem_decap(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_kem_decap_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_dsa_keygen(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_dsa_keygen_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_dsa_sign(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_dsa_sign_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_ml_dsa_verify(sgx_enclave_id_t eid, int* retval, uint64_t* ns)
{
	sgx_status_t status;
	ms_ecall_bench_ml_dsa_verify_t ms;
	ms.ms_ns = ns;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_bench_seal_unseal(sgx_enclave_id_t eid, int* retval, uint64_t* seal_ns, uint64_t* unseal_ns)
{
	sgx_status_t status;
	ms_ecall_bench_seal_unseal_t ms;
	ms.ms_seal_ns = seal_ns;
	ms.ms_unseal_ns = unseal_ns;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_enclave_init_t ms;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_reset(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_enclave_reset_t ms;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

