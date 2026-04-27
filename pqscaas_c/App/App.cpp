/*
 * PQSCAAS Untrusted Application (Normal World)
 *
 * Entry point. Initializes enclave and dispatches to the chosen experiment.
 *
 * Experiments (v4):
 *   1  KeyGen vs # users
 *   2  Phase 4 Signcrypt vs file size
 *   3  Batch Signcrypt vs # requests (with/without timeout)
 *   4  Phase 5 Unsigncrypt vs file size
 *   5  Sequential Unsigncrypt vs N
 *   6  Signcrypt throughput vs workload
 *   7  Unsigncrypt throughput vs workload
 *   8  Throughput vs Request Rate (dynamic elastic)
 *   9  Active Enclaves vs Request Rate
 *   10 Merkle-Root vs CRL revocation
 *   11 Policy Update: deferred binding vs naive re-encryption
 */

#include "App.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

sgx_enclave_id_t g_enclave_id = 0;

int initialize_enclave(const char *enclave_path) {
    sgx_status_t ret = sgx_create_enclave(
        enclave_path,
        SGX_DEBUG_FLAG,
        NULL, NULL,
        &g_enclave_id,
        NULL);

    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "[App] sgx_create_enclave failed: 0x%x\n", ret);
        return -1;
    }
    fprintf(stderr, "[App] Enclave created (eid=%lu)\n", (unsigned long)g_enclave_id);

    int init_ret;
    ecall_enclave_init(g_enclave_id, &init_ret);
    return 0;
}

void destroy_enclave(void) {
    if (g_enclave_id) {
        sgx_destroy_enclave(g_enclave_id);
        g_enclave_id = 0;
    }
}

/* Forward declarations of experiment entry points */
extern "C" int run_exp1();
extern "C" int run_exp2();
extern "C" int run_exp3();
extern "C" int run_exp4();
extern "C" int run_exp5();
extern "C" int run_exp6();
extern "C" int run_exp7();
extern "C" int run_exp8();
extern "C" int run_exp9();
extern "C" int run_exp10();
extern "C" int run_exp11();

#define NUM_EXPERIMENTS 11

static int dispatch(int n) {
    switch (n) {
        case 1:  return run_exp1();
        case 2:  return run_exp2();
        case 3:  return run_exp3();
        case 4:  return run_exp4();
        case 5:  return run_exp5();
        case 6:  return run_exp6();
        case 7:  return run_exp7();
        case 8:  return run_exp8();
        case 9:  return run_exp9();
        case 10: return run_exp10();
        case 11: return run_exp11();
        default: return -1;
    }
}

static int usage(const char *prog) {
    fprintf(stderr, "Usage: %s <exp_num|all>  (1..%d)\n", prog, NUM_EXPERIMENTS);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage(argv[0]);

    const char *enclave_so = std::getenv("ENCLAVE_SO");
    if (!enclave_so) enclave_so = "enclave.signed.so";

    if (initialize_enclave(enclave_so) != 0) return 1;

    std::string exp = argv[1];
    int rc = 0;

    if (exp == "all") {
        for (int i = 1; i <= NUM_EXPERIMENTS; i++) {
            fprintf(stderr, "\n=== Experiment %d ===\n", i);
            rc |= dispatch(i);
        }
    } else {
        int n = std::atoi(argv[1]);
        if (n < 1 || n > NUM_EXPERIMENTS) {
            destroy_enclave();
            return usage(argv[0]);
        }
        rc = dispatch(n);
    }

    destroy_enclave();
    return rc;
}
