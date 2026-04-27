#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_phase2_keygen(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase2_keygen_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase2_keygen_t* ms = SGX_CAST(ms_ecall_phase2_keygen_t*, pms);
	ms_ecall_phase2_keygen_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase2_keygen_t), ms, sizeof(ms_ecall_phase2_keygen_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_user_id = __in_ms.ms_user_id;
	size_t _len_user_id = 32;
	uint8_t* _in_user_id = NULL;
	uint8_t* _tmp_pk_kem = __in_ms.ms_pk_kem;
	size_t _len_pk_kem = 1184;
	uint8_t* _in_pk_kem = NULL;
	uint8_t* _tmp_pk_sig = __in_ms.ms_pk_sig;
	size_t _len_pk_sig = 1952;
	uint8_t* _in_pk_sig = NULL;
	uint8_t* _tmp_sealed_sk_kem = __in_ms.ms_sealed_sk_kem;
	size_t _len_sealed_sk_kem = 2976;
	uint8_t* _in_sealed_sk_kem = NULL;
	uint8_t* _tmp_sealed_sk_sig = __in_ms.ms_sealed_sk_sig;
	size_t _len_sealed_sk_sig = 4608;
	uint8_t* _in_sealed_sk_sig = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_user_id, _len_user_id);
	CHECK_UNIQUE_POINTER(_tmp_pk_kem, _len_pk_kem);
	CHECK_UNIQUE_POINTER(_tmp_pk_sig, _len_pk_sig);
	CHECK_UNIQUE_POINTER(_tmp_sealed_sk_kem, _len_sealed_sk_kem);
	CHECK_UNIQUE_POINTER(_tmp_sealed_sk_sig, _len_sealed_sk_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_user_id != NULL && _len_user_id != 0) {
		if ( _len_user_id % sizeof(*_tmp_user_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_user_id = (uint8_t*)malloc(_len_user_id);
		if (_in_user_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_user_id, _len_user_id, _tmp_user_id, _len_user_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pk_kem != NULL && _len_pk_kem != 0) {
		if ( _len_pk_kem % sizeof(*_tmp_pk_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pk_kem = (uint8_t*)malloc(_len_pk_kem)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pk_kem, 0, _len_pk_kem);
	}
	if (_tmp_pk_sig != NULL && _len_pk_sig != 0) {
		if ( _len_pk_sig % sizeof(*_tmp_pk_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pk_sig = (uint8_t*)malloc(_len_pk_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pk_sig, 0, _len_pk_sig);
	}
	if (_tmp_sealed_sk_kem != NULL && _len_sealed_sk_kem != 0) {
		if ( _len_sealed_sk_kem % sizeof(*_tmp_sealed_sk_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_sk_kem = (uint8_t*)malloc(_len_sealed_sk_kem)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_sk_kem, 0, _len_sealed_sk_kem);
	}
	if (_tmp_sealed_sk_sig != NULL && _len_sealed_sk_sig != 0) {
		if ( _len_sealed_sk_sig % sizeof(*_tmp_sealed_sk_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_sk_sig = (uint8_t*)malloc(_len_sealed_sk_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_sk_sig, 0, _len_sealed_sk_sig);
	}
	_in_retval = ecall_phase2_keygen((const uint8_t*)_in_user_id, _in_pk_kem, _in_pk_sig, _in_sealed_sk_kem, _in_sealed_sk_sig);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_pk_kem) {
		if (memcpy_verw_s(_tmp_pk_kem, _len_pk_kem, _in_pk_kem, _len_pk_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pk_sig) {
		if (memcpy_verw_s(_tmp_pk_sig, _len_pk_sig, _in_pk_sig, _len_pk_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealed_sk_kem) {
		if (memcpy_verw_s(_tmp_sealed_sk_kem, _len_sealed_sk_kem, _in_sealed_sk_kem, _len_sealed_sk_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealed_sk_sig) {
		if (memcpy_verw_s(_tmp_sealed_sk_sig, _len_sealed_sk_sig, _in_sealed_sk_sig, _len_sealed_sk_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_user_id) free(_in_user_id);
	if (_in_pk_kem) free(_in_pk_kem);
	if (_in_pk_sig) free(_in_pk_sig);
	if (_in_sealed_sk_kem) free(_in_sealed_sk_kem);
	if (_in_sealed_sk_sig) free(_in_sealed_sk_sig);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase4_signcrypt_single(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase4_signcrypt_single_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase4_signcrypt_single_t* ms = SGX_CAST(ms_ecall_phase4_signcrypt_single_t*, pms);
	ms_ecall_phase4_signcrypt_single_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase4_signcrypt_single_t), ms, sizeof(ms_ecall_phase4_signcrypt_single_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const pqscaas_descriptor_t* _tmp_desc = __in_ms.ms_desc;
	size_t _len_desc = sizeof(pqscaas_descriptor_t);
	pqscaas_descriptor_t* _in_desc = NULL;
	const uint8_t* _tmp_pk_r_kem = __in_ms.ms_pk_r_kem;
	size_t _len_pk_r_kem = 1184;
	uint8_t* _in_pk_r_kem = NULL;
	const uint8_t* _tmp_sealed_sk_u_sig = __in_ms.ms_sealed_sk_u_sig;
	size_t _len_sealed_sk_u_sig = 4608;
	uint8_t* _in_sealed_sk_u_sig = NULL;
	pqscaas_signcrypted_t* _tmp_out_sc = __in_ms.ms_out_sc;
	size_t _len_out_sc = sizeof(pqscaas_signcrypted_t);
	pqscaas_signcrypted_t* _in_out_sc = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_desc, _len_desc);
	CHECK_UNIQUE_POINTER(_tmp_pk_r_kem, _len_pk_r_kem);
	CHECK_UNIQUE_POINTER(_tmp_sealed_sk_u_sig, _len_sealed_sk_u_sig);
	CHECK_UNIQUE_POINTER(_tmp_out_sc, _len_out_sc);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_desc != NULL && _len_desc != 0) {
		_in_desc = (pqscaas_descriptor_t*)malloc(_len_desc);
		if (_in_desc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_desc, _len_desc, _tmp_desc, _len_desc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pk_r_kem != NULL && _len_pk_r_kem != 0) {
		if ( _len_pk_r_kem % sizeof(*_tmp_pk_r_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_r_kem = (uint8_t*)malloc(_len_pk_r_kem);
		if (_in_pk_r_kem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_r_kem, _len_pk_r_kem, _tmp_pk_r_kem, _len_pk_r_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_sk_u_sig != NULL && _len_sealed_sk_u_sig != 0) {
		if ( _len_sealed_sk_u_sig % sizeof(*_tmp_sealed_sk_u_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_sk_u_sig = (uint8_t*)malloc(_len_sealed_sk_u_sig);
		if (_in_sealed_sk_u_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_sk_u_sig, _len_sealed_sk_u_sig, _tmp_sealed_sk_u_sig, _len_sealed_sk_u_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_sc != NULL && _len_out_sc != 0) {
		if ((_in_out_sc = (pqscaas_signcrypted_t*)malloc(_len_out_sc)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_sc, 0, _len_out_sc);
	}
	_in_retval = ecall_phase4_signcrypt_single((const pqscaas_descriptor_t*)_in_desc, (const uint8_t*)_in_pk_r_kem, (const uint8_t*)_in_sealed_sk_u_sig, _in_out_sc);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out_sc) {
		if (memcpy_verw_s(_tmp_out_sc, _len_out_sc, _in_out_sc, _len_out_sc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_desc) free(_in_desc);
	if (_in_pk_r_kem) free(_in_pk_r_kem);
	if (_in_sealed_sk_u_sig) free(_in_sealed_sk_u_sig);
	if (_in_out_sc) free(_in_out_sc);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase4_signcrypt_batch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase4_signcrypt_batch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase4_signcrypt_batch_t* ms = SGX_CAST(ms_ecall_phase4_signcrypt_batch_t*, pms);
	ms_ecall_phase4_signcrypt_batch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase4_signcrypt_batch_t), ms, sizeof(ms_ecall_phase4_signcrypt_batch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const pqscaas_descriptor_t* _tmp_descriptors = __in_ms.ms_descriptors;
	size_t _tmp_n_desc = __in_ms.ms_n_desc;
	size_t _len_descriptors = _tmp_n_desc * sizeof(pqscaas_descriptor_t);
	pqscaas_descriptor_t* _in_descriptors = NULL;
	const uint8_t* _tmp_pk_r_kem = __in_ms.ms_pk_r_kem;
	size_t _len_pk_r_kem = 1184;
	uint8_t* _in_pk_r_kem = NULL;
	const uint8_t* _tmp_sealed_sk_u_sig = __in_ms.ms_sealed_sk_u_sig;
	size_t _len_sealed_sk_u_sig = 4608;
	uint8_t* _in_sealed_sk_u_sig = NULL;
	pqscaas_signcrypted_t* _tmp_out_sc = __in_ms.ms_out_sc;
	size_t _len_out_sc = _tmp_n_desc * sizeof(pqscaas_signcrypted_t);
	pqscaas_signcrypted_t* _in_out_sc = NULL;
	int _in_retval;

	if (sizeof(*_tmp_descriptors) != 0 &&
		(size_t)_tmp_n_desc > (SIZE_MAX / sizeof(*_tmp_descriptors))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_out_sc) != 0 &&
		(size_t)_tmp_n_desc > (SIZE_MAX / sizeof(*_tmp_out_sc))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_descriptors, _len_descriptors);
	CHECK_UNIQUE_POINTER(_tmp_pk_r_kem, _len_pk_r_kem);
	CHECK_UNIQUE_POINTER(_tmp_sealed_sk_u_sig, _len_sealed_sk_u_sig);
	CHECK_UNIQUE_POINTER(_tmp_out_sc, _len_out_sc);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_descriptors != NULL && _len_descriptors != 0) {
		_in_descriptors = (pqscaas_descriptor_t*)malloc(_len_descriptors);
		if (_in_descriptors == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_descriptors, _len_descriptors, _tmp_descriptors, _len_descriptors)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pk_r_kem != NULL && _len_pk_r_kem != 0) {
		if ( _len_pk_r_kem % sizeof(*_tmp_pk_r_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_r_kem = (uint8_t*)malloc(_len_pk_r_kem);
		if (_in_pk_r_kem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_r_kem, _len_pk_r_kem, _tmp_pk_r_kem, _len_pk_r_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_sk_u_sig != NULL && _len_sealed_sk_u_sig != 0) {
		if ( _len_sealed_sk_u_sig % sizeof(*_tmp_sealed_sk_u_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_sk_u_sig = (uint8_t*)malloc(_len_sealed_sk_u_sig);
		if (_in_sealed_sk_u_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_sk_u_sig, _len_sealed_sk_u_sig, _tmp_sealed_sk_u_sig, _len_sealed_sk_u_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_sc != NULL && _len_out_sc != 0) {
		if ((_in_out_sc = (pqscaas_signcrypted_t*)malloc(_len_out_sc)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_sc, 0, _len_out_sc);
	}
	_in_retval = ecall_phase4_signcrypt_batch((const pqscaas_descriptor_t*)_in_descriptors, _tmp_n_desc, (const uint8_t*)_in_pk_r_kem, (const uint8_t*)_in_sealed_sk_u_sig, _in_out_sc);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_out_sc) {
		if (memcpy_verw_s(_tmp_out_sc, _len_out_sc, _in_out_sc, _len_out_sc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_descriptors) free(_in_descriptors);
	if (_in_pk_r_kem) free(_in_pk_r_kem);
	if (_in_sealed_sk_u_sig) free(_in_sealed_sk_u_sig);
	if (_in_out_sc) free(_in_out_sc);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase5_unsigncrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase5_unsigncrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase5_unsigncrypt_t* ms = SGX_CAST(ms_ecall_phase5_unsigncrypt_t*, pms);
	ms_ecall_phase5_unsigncrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase5_unsigncrypt_t), ms, sizeof(ms_ecall_phase5_unsigncrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const pqscaas_signcrypted_t* _tmp_sc = __in_ms.ms_sc;
	size_t _len_sc = sizeof(pqscaas_signcrypted_t);
	pqscaas_signcrypted_t* _in_sc = NULL;
	const uint8_t* _tmp_pk_u_sig = __in_ms.ms_pk_u_sig;
	size_t _len_pk_u_sig = 1952;
	uint8_t* _in_pk_u_sig = NULL;
	const uint8_t* _tmp_sealed_sk_r_kem = __in_ms.ms_sealed_sk_r_kem;
	size_t _len_sealed_sk_r_kem = 2976;
	uint8_t* _in_sealed_sk_r_kem = NULL;
	uint8_t* _tmp_k_d_out = __in_ms.ms_k_d_out;
	size_t _len_k_d_out = 32;
	uint8_t* _in_k_d_out = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sc, _len_sc);
	CHECK_UNIQUE_POINTER(_tmp_pk_u_sig, _len_pk_u_sig);
	CHECK_UNIQUE_POINTER(_tmp_sealed_sk_r_kem, _len_sealed_sk_r_kem);
	CHECK_UNIQUE_POINTER(_tmp_k_d_out, _len_k_d_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sc != NULL && _len_sc != 0) {
		_in_sc = (pqscaas_signcrypted_t*)malloc(_len_sc);
		if (_in_sc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sc, _len_sc, _tmp_sc, _len_sc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pk_u_sig != NULL && _len_pk_u_sig != 0) {
		if ( _len_pk_u_sig % sizeof(*_tmp_pk_u_sig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_u_sig = (uint8_t*)malloc(_len_pk_u_sig);
		if (_in_pk_u_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_u_sig, _len_pk_u_sig, _tmp_pk_u_sig, _len_pk_u_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_sk_r_kem != NULL && _len_sealed_sk_r_kem != 0) {
		if ( _len_sealed_sk_r_kem % sizeof(*_tmp_sealed_sk_r_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_sk_r_kem = (uint8_t*)malloc(_len_sealed_sk_r_kem);
		if (_in_sealed_sk_r_kem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_sk_r_kem, _len_sealed_sk_r_kem, _tmp_sealed_sk_r_kem, _len_sealed_sk_r_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_k_d_out != NULL && _len_k_d_out != 0) {
		if ( _len_k_d_out % sizeof(*_tmp_k_d_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_k_d_out = (uint8_t*)malloc(_len_k_d_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_k_d_out, 0, _len_k_d_out);
	}
	_in_retval = ecall_phase5_unsigncrypt((const pqscaas_signcrypted_t*)_in_sc, (const uint8_t*)_in_pk_u_sig, (const uint8_t*)_in_sealed_sk_r_kem, _in_k_d_out);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_k_d_out) {
		if (memcpy_verw_s(_tmp_k_d_out, _len_k_d_out, _in_k_d_out, _len_k_d_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sc) free(_in_sc);
	if (_in_pk_u_sig) free(_in_pk_u_sig);
	if (_in_sealed_sk_r_kem) free(_in_sealed_sk_r_kem);
	if (_in_k_d_out) free(_in_k_d_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_revoke_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_revoke_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_revoke_user_t* ms = SGX_CAST(ms_ecall_revoke_user_t*, pms);
	ms_ecall_revoke_user_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_revoke_user_t), ms, sizeof(ms_ecall_revoke_user_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_user_id = __in_ms.ms_user_id;
	size_t _len_user_id = 32;
	uint8_t* _in_user_id = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_user_id, _len_user_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_user_id != NULL && _len_user_id != 0) {
		if ( _len_user_id % sizeof(*_tmp_user_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_user_id = (uint8_t*)malloc(_len_user_id);
		if (_in_user_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_user_id, _len_user_id, _tmp_user_id, _len_user_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_revoke_user((const uint8_t*)_in_user_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_user_id) free(_in_user_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_is_revoked(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_is_revoked_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_is_revoked_t* ms = SGX_CAST(ms_ecall_is_revoked_t*, pms);
	ms_ecall_is_revoked_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_is_revoked_t), ms, sizeof(ms_ecall_is_revoked_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_user_id = __in_ms.ms_user_id;
	size_t _len_user_id = 32;
	uint8_t* _in_user_id = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_user_id, _len_user_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_user_id != NULL && _len_user_id != 0) {
		if ( _len_user_id % sizeof(*_tmp_user_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_user_id = (uint8_t*)malloc(_len_user_id);
		if (_in_user_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_user_id, _len_user_id, _tmp_user_id, _len_user_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_is_revoked((const uint8_t*)_in_user_id);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_user_id) free(_in_user_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_revoke_rebind_all(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_revoke_rebind_all_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_revoke_rebind_all_t* ms = SGX_CAST(ms_ecall_revoke_rebind_all_t*, pms);
	ms_ecall_revoke_rebind_all_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_revoke_rebind_all_t), ms, sizeof(ms_ecall_revoke_rebind_all_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_elapsed_ns = __in_ms.ms_elapsed_ns;
	size_t _len_elapsed_ns = sizeof(uint64_t);
	uint64_t* _in_elapsed_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_elapsed_ns, _len_elapsed_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_elapsed_ns != NULL && _len_elapsed_ns != 0) {
		if ( _len_elapsed_ns % sizeof(*_tmp_elapsed_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_elapsed_ns = (uint64_t*)malloc(_len_elapsed_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_elapsed_ns, 0, _len_elapsed_ns);
	}
	_in_retval = ecall_revoke_rebind_all(__in_ms.ms_n_active_users, __in_ms.ms_n_revoked, _in_elapsed_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_elapsed_ns) {
		if (memcpy_verw_s(_tmp_elapsed_ns, _len_elapsed_ns, _in_elapsed_ns, _len_elapsed_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_elapsed_ns) free(_in_elapsed_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase2_keygen_batch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase2_keygen_batch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase2_keygen_batch_t* ms = SGX_CAST(ms_ecall_phase2_keygen_batch_t*, pms);
	ms_ecall_phase2_keygen_batch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase2_keygen_batch_t), ms, sizeof(ms_ecall_phase2_keygen_batch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_elapsed_ns_per_key = __in_ms.ms_elapsed_ns_per_key;
	size_t _len_elapsed_ns_per_key = sizeof(uint64_t);
	uint64_t* _in_elapsed_ns_per_key = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_elapsed_ns_per_key, _len_elapsed_ns_per_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_elapsed_ns_per_key != NULL && _len_elapsed_ns_per_key != 0) {
		if ( _len_elapsed_ns_per_key % sizeof(*_tmp_elapsed_ns_per_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_elapsed_ns_per_key = (uint64_t*)malloc(_len_elapsed_ns_per_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_elapsed_ns_per_key, 0, _len_elapsed_ns_per_key);
	}
	_in_retval = ecall_phase2_keygen_batch(__in_ms.ms_n_users, _in_elapsed_ns_per_key);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_elapsed_ns_per_key) {
		if (memcpy_verw_s(_tmp_elapsed_ns_per_key, _len_elapsed_ns_per_key, _in_elapsed_ns_per_key, _len_elapsed_ns_per_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_elapsed_ns_per_key) free(_in_elapsed_ns_per_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_kem_keygen(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_kem_keygen_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_kem_keygen_t* ms = SGX_CAST(ms_ecall_bench_ml_kem_keygen_t*, pms);
	ms_ecall_bench_ml_kem_keygen_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_kem_keygen_t), ms, sizeof(ms_ecall_bench_ml_kem_keygen_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_kem_keygen(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_kem_encap(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_kem_encap_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_kem_encap_t* ms = SGX_CAST(ms_ecall_bench_ml_kem_encap_t*, pms);
	ms_ecall_bench_ml_kem_encap_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_kem_encap_t), ms, sizeof(ms_ecall_bench_ml_kem_encap_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_kem_encap(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_kem_decap(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_kem_decap_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_kem_decap_t* ms = SGX_CAST(ms_ecall_bench_ml_kem_decap_t*, pms);
	ms_ecall_bench_ml_kem_decap_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_kem_decap_t), ms, sizeof(ms_ecall_bench_ml_kem_decap_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_kem_decap(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_dsa_keygen(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_dsa_keygen_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_dsa_keygen_t* ms = SGX_CAST(ms_ecall_bench_ml_dsa_keygen_t*, pms);
	ms_ecall_bench_ml_dsa_keygen_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_dsa_keygen_t), ms, sizeof(ms_ecall_bench_ml_dsa_keygen_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_dsa_keygen(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_dsa_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_dsa_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_dsa_sign_t* ms = SGX_CAST(ms_ecall_bench_ml_dsa_sign_t*, pms);
	ms_ecall_bench_ml_dsa_sign_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_dsa_sign_t), ms, sizeof(ms_ecall_bench_ml_dsa_sign_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_dsa_sign(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_ml_dsa_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_ml_dsa_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_ml_dsa_verify_t* ms = SGX_CAST(ms_ecall_bench_ml_dsa_verify_t*, pms);
	ms_ecall_bench_ml_dsa_verify_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_ml_dsa_verify_t), ms, sizeof(ms_ecall_bench_ml_dsa_verify_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_ns = __in_ms.ms_ns;
	size_t _len_ns = sizeof(uint64_t);
	uint64_t* _in_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ns, _len_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ns != NULL && _len_ns != 0) {
		if ( _len_ns % sizeof(*_tmp_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ns = (uint64_t*)malloc(_len_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ns, 0, _len_ns);
	}
	_in_retval = ecall_bench_ml_dsa_verify(_in_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ns) {
		if (memcpy_verw_s(_tmp_ns, _len_ns, _in_ns, _len_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ns) free(_in_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bench_seal_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bench_seal_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_bench_seal_unseal_t* ms = SGX_CAST(ms_ecall_bench_seal_unseal_t*, pms);
	ms_ecall_bench_seal_unseal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_bench_seal_unseal_t), ms, sizeof(ms_ecall_bench_seal_unseal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_seal_ns = __in_ms.ms_seal_ns;
	size_t _len_seal_ns = sizeof(uint64_t);
	uint64_t* _in_seal_ns = NULL;
	uint64_t* _tmp_unseal_ns = __in_ms.ms_unseal_ns;
	size_t _len_unseal_ns = sizeof(uint64_t);
	uint64_t* _in_unseal_ns = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_seal_ns, _len_seal_ns);
	CHECK_UNIQUE_POINTER(_tmp_unseal_ns, _len_unseal_ns);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal_ns != NULL && _len_seal_ns != 0) {
		if ( _len_seal_ns % sizeof(*_tmp_seal_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_seal_ns = (uint64_t*)malloc(_len_seal_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_seal_ns, 0, _len_seal_ns);
	}
	if (_tmp_unseal_ns != NULL && _len_unseal_ns != 0) {
		if ( _len_unseal_ns % sizeof(*_tmp_unseal_ns) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_unseal_ns = (uint64_t*)malloc(_len_unseal_ns)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unseal_ns, 0, _len_unseal_ns);
	}
	_in_retval = ecall_bench_seal_unseal(_in_seal_ns, _in_unseal_ns);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_seal_ns) {
		if (memcpy_verw_s(_tmp_seal_ns, _len_seal_ns, _in_seal_ns, _len_seal_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_unseal_ns) {
		if (memcpy_verw_s(_tmp_unseal_ns, _len_unseal_ns, _in_unseal_ns, _len_unseal_ns)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_seal_ns) free(_in_seal_ns);
	if (_in_unseal_ns) free(_in_unseal_ns);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_init_t* ms = SGX_CAST(ms_ecall_enclave_init_t*, pms);
	ms_ecall_enclave_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_init_t), ms, sizeof(ms_ecall_enclave_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_enclave_init();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_reset(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_reset_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_reset_t* ms = SGX_CAST(ms_ecall_enclave_reset_t*, pms);
	ms_ecall_enclave_reset_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_reset_t), ms, sizeof(ms_ecall_enclave_reset_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_enclave_reset();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[17];
} g_ecall_table = {
	17,
	{
		{(void*)(uintptr_t)sgx_ecall_phase2_keygen, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase4_signcrypt_single, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase4_signcrypt_batch, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase5_unsigncrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_revoke_user, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_is_revoked, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_revoke_rebind_all, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase2_keygen_batch, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_kem_keygen, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_kem_encap, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_kem_decap, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_dsa_keygen, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_dsa_sign, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_ml_dsa_verify, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_bench_seal_unseal, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_reset, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][17];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time_ns(uint64_t* t)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t = sizeof(uint64_t);

	ms_ocall_get_time_ns_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_ns_t);
	void *__tmp = NULL;

	void *__tmp_t = NULL;

	CHECK_ENCLAVE_POINTER(t, _len_t);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t != NULL) ? _len_t : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_ns_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_ns_t));
	ocalloc_size -= sizeof(ms_ocall_get_time_ns_t);

	if (t != NULL) {
		if (memcpy_verw_s(&ms->ms_t, sizeof(uint64_t*), &__tmp, sizeof(uint64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_t = __tmp;
		if (_len_t % sizeof(*t) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_t, 0, _len_t);
		__tmp = (void *)((size_t)__tmp + _len_t);
		ocalloc_size -= _len_t;
	} else {
		ms->ms_t = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (t) {
			if (memcpy_s((void*)t, _len_t, __tmp_t, _len_t)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

