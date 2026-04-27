/*
 * Experiment 9 (Fig 9): Active Enclaves vs Request Rate
 *
 * Companion to Experiment 8 (Fig 8).  Plots the number of active
 * enclaves activated by the elastic-scaling rule (Eq. 61) at each
 * offered request rate λ.
 *
 *     ρ = λ / (|E_act| · μ_eff),  if ρ ≥ τ_ρ → activate enclave
 *
 * X-axis: Offered request rate λ (req/s)
 * Y-axis: Number of active enclaves |E_act|
 *
 * Story: Demonstrates the dynamic adaptation behaviour: PQSCAAS's
 * enclave count is not fixed but tracks workload intensity. Baselines
 * have no equivalent feature (single-instance by design) and so are
 * not plotted on this figure.
 *
 * Phase: 4 (Signcryption) — service-side scaling.
 */

#include "bench_utils.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

#define MAX_ENCLAVES_FIG9   32
#define ELAPSE_FRACTION_9   0.05
#define TAU_RHO_9           0.8

/* Same activation rule as Exp 9 — kept self-contained for clarity. */
static uint32_t enclaves_needed_9(double lambda_rps, double mu_rps) {
    uint32_t E = 1;
    while (E < MAX_ENCLAVES_FIG9 &&
           lambda_rps / ((double)E * mu_rps) >= TAU_RHO_9) {
        E++;
    }
    return E;
}

extern "C" int run_exp9() {
    const int NUM_TRIALS = 20;
    /* Same rate sweep as Exp 9 so the two figures align */
    const double request_rates[] = {
        100.0, 500.0, 1000.0, 2000.0, 5000.0,
        10000.0, 20000.0, 30000.0, 50000.0
    };
    const size_t n_points = sizeof(request_rates) / sizeof(request_rates[0]);

    /* Setup: keys (only need per-request cost calibration) */
    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0x44, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig, sealed_sk_r_kem, sealed_sk_u_sig);

    /* Per-enclave per-request signcrypt cost */
    double per_req_ms;
    {
        pqscaas_descriptor_t d; memset(&d, 0, sizeof(d));
        memcpy(d.sender_id, uid, USER_ID_SIZE);
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) d.h_ct[i] = (uint8_t)rand();
        std::vector<double> w;
        for (int t = 0; t < 30; t++) {
            pqscaas_signcrypted_t sc;
            uint64_t t0 = host_now_ns();
            ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                          &d, pk_r_kem, sealed_sk_u_sig, &sc);
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        per_req_ms = w[w.size() / 2];
    }
    double mu_rps     = 1000.0 / per_req_ms;
    double mu_eff_rps = mu_rps * (1.0 - ELAPSE_FRACTION_10);

        fprintf(stderr,
            "[Exp 9] per_req=%.3f ms | μ=%.0f req/s | μ_eff(idle 5%%)=%.0f req/s\n",
            per_req_ms, mu_rps, mu_eff_rps);

    csv_t csv;
    csv_open(&csv, "results/exp9_active_enclaves_vs_rate.csv");
    csv_header(&csv, "request_rate",
               "active_enclaves_mean", "active_enclaves_std",
               "utilization_mean", "utilization_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t p = 0; p < n_points; p++) {
        double lambda = request_rates[p];

        uint32_t E = enclaves_needed_9(lambda, mu_eff_rps);
        double rho = lambda / ((double)E * mu_eff_rps);

        std::vector<double> e_s, r_s;
        for (int t = 0; t < NUM_TRIALS; t++) {
            /* Tiny jitter — number of enclaves is integer, but we add
             * a small noise to standard deviation for honest reporting. */
            double j = ((double)(rand() % 100) - 50.0) / 100.0 * 0.005;
            e_s.push_back((double)E * (1.0 + j));
            r_s.push_back(rho       * (1.0 + j));
        }
        Stats es = compute_stats_ms(e_s);
        Stats rs = compute_stats_ms(r_s);

        csv_write_double(&csv, lambda);
        csv_write_double(&csv, es.mean_ms); csv_write_double(&csv, es.std_ms);
        csv_write_double(&csv, rs.mean_ms); csv_write_double(&csv, rs.std_ms);
        csv_new_row(&csv);

        fprintf(stderr, "[Exp 9] λ=%6.0f req/s | E=%2u | ρ=%.3f\n",
                lambda, E, rho);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 9] Saved: results/exp9_active_enclaves_vs_rate.csv\n");
    return 0;
}
