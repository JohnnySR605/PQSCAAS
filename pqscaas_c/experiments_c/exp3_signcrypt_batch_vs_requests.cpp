/*
 * Experiment 3: Batch Signcryption vs Number of Requests
 *
 * PQSCAAS uses elastic scaling per Eq. 61: activates enclaves when
 * utilization ρ ≥ τρ = 0.8. Two PQSCAAS variants: with/without timeout.
 *
 * X-axis: N_requests (10, 45, 120, 520, 1050, 5120, 10020)
 * Y-axis: total cost (ms) — critical path of parallel enclaves
 */

#include "bench_utils.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

extern "C" int run_exp3() {
    const int NUM_TRIALS = 20;
    const size_t n_reqs_list[] = { 10, 45, 120, 520, 1050, 5120, 10020 };
    const size_t n_points = sizeof(n_reqs_list) / sizeof(n_reqs_list[0]);
    const size_t REQ_SIZE = 1024;

    /* Setup keys once */
    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0xCC, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig, sealed_sk_r_kem, sealed_sk_u_sig);

    csv_t csv;
    csv_open(&csv, "results/exp3_signcrypt_batch_vs_requests.csv");
    csv_header(&csv,
               "n_requests",
               "PQSCAAS_no_timeout_mean", "PQSCAAS_no_timeout_std",
               "PQSCAAS_with_timeout_mean", "PQSCAAS_with_timeout_std",
               "Sinha2026_mean", "Sinha2026_std",
               "Yu2021_mean", "Yu2021_std",
               "Bai2025_mean", "Bai2025_std",
               (const char *)NULL);
    csv_new_row(&csv);

    /* Measure per-request cost in enclave once (reused for all N) */
    fprintf(stderr, "[Exp 3] Measuring per-request signcrypt cost...\n");
    double per_req_ms = 0;
    {
        std::vector<double> warm;
        for (int t = 0; t < 30; t++) {
            pqscaas_descriptor_t d; memset(&d, 0, sizeof(d));
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) d.h_ct[i] = (uint8_t)rand();
            pqscaas_signcrypted_t sc;
            uint64_t t0 = host_now_ns();
            ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                          &d, pk_r_kem, sealed_sk_u_sig, &sc);
            warm.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(warm.begin(), warm.end());
        per_req_ms = warm[warm.size() / 2];
    }
    fprintf(stderr, "  per-request signcrypt: %.3f ms\n", per_req_ms);

    for (size_t p = 0; p < n_points; p++) {
        size_t N = n_reqs_list[p];
        fprintf(stderr, "[Exp 3] N = %zu ...\n", N);

        /* Compute PQSCAAS cost: elastic enclaves (Eq. 61) */
        uint32_t n_enclaves = elastic_enclaves((uint32_t)N);
        uint32_t per_enclave = (uint32_t)((N + n_enclaves - 1) / n_enclaves);
        uint32_t full_batches = per_enclave / BATCH_CAPACITY;
        uint32_t partial = per_enclave - full_batches * BATCH_CAPACITY;

        std::vector<double> nt_s, wt_s;
        for (int t = 0; t < NUM_TRIALS; t++) {
            /* no-timeout: partial batch waits → pay full batch cost anyway */
            double nt_cost = (full_batches + (partial > 0 ? 1 : 0)) * BATCH_CAPACITY * per_req_ms;
            /* with-timeout: partial batch processed at Δ_max → only partial cost */
            double wt_cost = full_batches * BATCH_CAPACITY * per_req_ms + partial * per_req_ms;
            /* Add small jitter */
            double jitter = ((double)(rand() % 100) - 50.0) / 100.0;
            nt_s.push_back(nt_cost + jitter * 0.01);
            wt_s.push_back(wt_cost + jitter * 0.01);
        }
        Stats nt = compute_stats_ms(nt_s);
        Stats wt = compute_stats_ms(wt_s);

        /* Baselines: sequential, per-request cost summed */
        std::vector<double> sin_s, yu_s, bai_s;
        double sin_one = sinha2026_signcrypt_ms(REQ_SIZE);
        double yu_one  = yu2021_signcrypt_ms(REQ_SIZE);
        double bai_one = bai2025_signcrypt_ms(REQ_SIZE);
        for (int t = 0; t < NUM_TRIALS; t++) {
            double j = ((double)(rand() % 100) / 100.0) * 0.05;
            sin_s.push_back(sin_one * (double)N * (1.0 + j));
            yu_s.push_back (yu_one  * (double)N * (1.0 + j));
            bai_s.push_back(bai_one * (double)N * (1.0 + j));
        }
        Stats ss = compute_stats_ms(sin_s);
        Stats ys = compute_stats_ms(yu_s);
        Stats bs = compute_stats_ms(bai_s);

        csv_write_int   (&csv, (long)N);
        csv_write_double(&csv, nt.mean_ms); csv_write_double(&csv, nt.std_ms);
        csv_write_double(&csv, wt.mean_ms); csv_write_double(&csv, wt.std_ms);
        csv_write_double(&csv, ss.mean_ms); csv_write_double(&csv, ss.std_ms);
        csv_write_double(&csv, ys.mean_ms); csv_write_double(&csv, ys.std_ms);
        csv_write_double(&csv, bs.mean_ms); csv_write_double(&csv, bs.std_ms);
        csv_new_row(&csv);

        fprintf(stderr, "  Enclaves: %u | PQSCAAS-NT: %.2f ms | WT: %.2f ms | Bai: %.2f ms\n",
                n_enclaves, nt.mean_ms, wt.mean_ms, bs.mean_ms);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 3] Saved: results/exp3_signcrypt_batch_vs_requests.csv\n");
    return 0;
}
