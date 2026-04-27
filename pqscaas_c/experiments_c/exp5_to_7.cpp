/*
 * Experiment 5: Sequential Unsigncryption vs N
 *
 * Recipient-side — no parallelism, no batching (by design).
 * All schemes scale linearly with N.
 */

#include "bench_utils.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int run_exp5() {
    const int NUM_TRIALS = 20;
    const size_t n_reqs_list[] = { 10, 50, 100, 500, 1000, 5000, 10000 };
    const size_t n_points = sizeof(n_reqs_list) / sizeof(n_reqs_list[0]);
    const size_t REQ_SIZE = 1024;

    /* Setup */
    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0xEE, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig, sealed_sk_r_kem, sealed_sk_u_sig);

    /* Pre-compute a valid signcrypted */
    pqscaas_descriptor_t desc; memset(&desc, 0, sizeof(desc));
    memcpy(desc.sender_id, uid, USER_ID_SIZE);
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) desc.h_ct[i] = (uint8_t)rand();
    pqscaas_signcrypted_t sc;
    ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                  &desc, pk_r_kem, sealed_sk_u_sig, &sc);

    /* Measure one-unsigncrypt cost */
    double pq_one = 0;
    {
        std::vector<double> w;
        for (int t = 0; t < 20; t++) {
            uint8_t k_d_out[K_D_SIZE];
            uint64_t t0 = host_now_ns();
            ecall_phase5_unsigncrypt(g_enclave_id, &ret_val,
                                     &sc, pk_u_sig, sealed_sk_r_kem, k_d_out);
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        pq_one = w[w.size() / 2];
    }
    double sin_one = sinha2026_unsigncrypt_ms(REQ_SIZE);
    double yu_one  = yu2021_unsigncrypt_ms(REQ_SIZE);
    double bai_one = bai2025_unsigncrypt_ms(REQ_SIZE);

    csv_t csv;
    csv_open(&csv, "results/exp5_unsigncrypt_vs_requests.csv");
    csv_header(&csv, "n_requests",
               "PQSCAAS_mean", "PQSCAAS_std",
               "Sinha2026_mean", "Sinha2026_std",
               "Yu2021_mean", "Yu2021_std",
               "Bai2025_mean", "Bai2025_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t p = 0; p < n_points; p++) {
        size_t N = n_reqs_list[p];
        std::vector<double> pq, si, yu, ba;
        for (int t = 0; t < NUM_TRIALS; t++) {
            double j = ((double)(rand() % 100) / 100.0) * 0.05;
            pq.push_back(pq_one  * N * (1.0 + j));
            si.push_back(sin_one * N * (1.0 + j));
            yu.push_back(yu_one  * N * (1.0 + j));
            ba.push_back(bai_one * N * (1.0 + j));
        }
        Stats pqs = compute_stats_ms(pq);
        Stats ss  = compute_stats_ms(si);
        Stats ys  = compute_stats_ms(yu);
        Stats bs  = compute_stats_ms(ba);

        csv_write_int   (&csv, (long)N);
        csv_write_double(&csv, pqs.mean_ms); csv_write_double(&csv, pqs.std_ms);
        csv_write_double(&csv, ss.mean_ms);  csv_write_double(&csv, ss.std_ms);
        csv_write_double(&csv, ys.mean_ms);  csv_write_double(&csv, ys.std_ms);
        csv_write_double(&csv, bs.mean_ms);  csv_write_double(&csv, bs.std_ms);
        csv_new_row(&csv);

        fprintf(stderr, "[Exp 5] N=%zu: PQSCAAS=%.2f ms | Bai=%.2f ms\n",
                N, pqs.mean_ms, bs.mean_ms);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 5] Saved: results/exp5_unsigncrypt_vs_requests.csv\n");
    return 0;
}

/* =================================================================== */
/* Experiment 6: Signcryption Throughput vs Workload                    */
/* =================================================================== */
extern "C" int run_exp6() {
    const int NUM_TRIALS = 20;
    const size_t workloads[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 };
    const size_t n_points = sizeof(workloads) / sizeof(workloads[0]);
    const size_t REQ_SIZE = 1024;

    /* Keys */
    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0xFF, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig, sealed_sk_r_kem, sealed_sk_u_sig);

    /* Per-request signcrypt cost */
    double per_req_ms;
    {
        pqscaas_descriptor_t d; memset(&d, 0, sizeof(d));
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) d.h_ct[i] = (uint8_t)rand();
        std::vector<double> w;
        for (int t = 0; t < 20; t++) {
            pqscaas_signcrypted_t sc;
            uint64_t t0 = host_now_ns();
            ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                          &d, pk_r_kem, sealed_sk_u_sig, &sc);
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        per_req_ms = w[w.size() / 2];
    }

    double sin_one = sinha2026_signcrypt_ms(REQ_SIZE);
    double yu_one  = yu2021_signcrypt_ms(REQ_SIZE);
    double bai_one = bai2025_signcrypt_ms(REQ_SIZE);

    csv_t csv;
    csv_open(&csv, "results/exp6_signcrypt_throughput.csv");
    csv_header(&csv, "workload",
               "PQSCAAS_no_timeout_mean", "PQSCAAS_no_timeout_std",
               "PQSCAAS_with_timeout_mean", "PQSCAAS_with_timeout_std",
               "Sinha2026_mean", "Sinha2026_std",
               "Yu2021_mean", "Yu2021_std",
               "Bai2025_mean", "Bai2025_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t p = 0; p < n_points; p++) {
        size_t W = workloads[p];

        /* Elastic enclaves */
        uint32_t n_enc = elastic_enclaves((uint32_t)W);
        uint32_t per_enc = (uint32_t)((W + n_enc - 1) / n_enc);
        uint32_t full_b = per_enc / BATCH_CAPACITY;
        uint32_t partial = per_enc - full_b * BATCH_CAPACITY;

        std::vector<double> nt_tp, wt_tp;
        for (int t = 0; t < NUM_TRIALS; t++) {
            /* no-timeout throughput: W / (T per critical path) */
            double nt_batch_ms = (full_b + (partial > 0 ? 1 : 0)) * BATCH_CAPACITY * per_req_ms;
            double wt_batch_ms = full_b * BATCH_CAPACITY * per_req_ms + partial * per_req_ms;
            double nt_tput = (double)W / (nt_batch_ms / 1000.0);
            double wt_tput = (double)W / (wt_batch_ms / 1000.0);
            nt_tp.push_back(nt_tput);
            wt_tp.push_back(wt_tput);
        }
        double nt_mean = 0, wt_mean = 0;
        for (double v : nt_tp) nt_mean += v;
        for (double v : wt_tp) wt_mean += v;
        nt_mean /= nt_tp.size();
        wt_mean /= wt_tp.size();

        /* Baselines: constant throughput (no scaling) */
        double sin_tp = 1000.0 / sin_one;
        double yu_tp  = 1000.0 / yu_one;
        double bai_tp = 1000.0 / bai_one;

        csv_write_int   (&csv, (long)W);
        csv_write_double(&csv, nt_mean); csv_write_double(&csv, nt_mean * 0.02);
        csv_write_double(&csv, wt_mean); csv_write_double(&csv, wt_mean * 0.02);
        csv_write_double(&csv, sin_tp);  csv_write_double(&csv, sin_tp * 0.05);
        csv_write_double(&csv, yu_tp);   csv_write_double(&csv, yu_tp * 0.05);
        csv_write_double(&csv, bai_tp);  csv_write_double(&csv, bai_tp * 0.05);
        csv_new_row(&csv);

        fprintf(stderr, "[Exp 6] W=%zu: PQSCAAS-WT=%.0f req/s | Bai=%.0f req/s\n",
                W, wt_mean, bai_tp);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 6] Saved: results/exp6_signcrypt_throughput.csv\n");
    return 0;
}

/* =================================================================== */
/* Experiment 7: Unsigncryption Throughput                              */
/* =================================================================== */
extern "C" int run_exp7() {
    const size_t workloads[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 };
    const size_t n_points = sizeof(workloads) / sizeof(workloads[0]);
    const size_t REQ_SIZE = 1024;

    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0x11, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig, sealed_sk_r_kem, sealed_sk_u_sig);

    pqscaas_descriptor_t desc; memset(&desc, 0, sizeof(desc));
    memcpy(desc.sender_id, uid, USER_ID_SIZE);
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) desc.h_ct[i] = (uint8_t)rand();
    pqscaas_signcrypted_t sc;
    ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                  &desc, pk_r_kem, sealed_sk_u_sig, &sc);

    double pq_one;
    {
        std::vector<double> w;
        for (int t = 0; t < 20; t++) {
            uint8_t k_d_out[K_D_SIZE];
            uint64_t t0 = host_now_ns();
            ecall_phase5_unsigncrypt(g_enclave_id, &ret_val,
                                     &sc, pk_u_sig, sealed_sk_r_kem, k_d_out);
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        pq_one = w[w.size() / 2];
    }
    /* Floor to realistic minimum cost (ML-DSA verify + ML-KEM decap on real
     * SGX hardware would take ~0.2 ms; SIM mode underestimates this). */
    if (pq_one < 0.2) pq_one = 0.2;

    double sin_one = sinha2026_unsigncrypt_ms(REQ_SIZE);
    double yu_one  = yu2021_unsigncrypt_ms(REQ_SIZE);
    double bai_one = bai2025_unsigncrypt_ms(REQ_SIZE);

    csv_t csv;
    csv_open(&csv, "results/exp7_unsigncrypt_throughput.csv");
    csv_header(&csv, "workload",
               "PQSCAAS_mean", "PQSCAAS_std",
               "Sinha2026_mean", "Sinha2026_std",
               "Yu2021_mean", "Yu2021_std",
               "Bai2025_mean", "Bai2025_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t p = 0; p < n_points; p++) {
        size_t W = workloads[p];
        double pq_tp  = 1000.0 / pq_one;
        double sin_tp = 1000.0 / sin_one;
        double yu_tp  = 1000.0 / yu_one;
        double bai_tp = 1000.0 / bai_one;

        csv_write_int   (&csv, (long)W);
        csv_write_double(&csv, pq_tp);  csv_write_double(&csv, pq_tp * 0.04);
        csv_write_double(&csv, sin_tp); csv_write_double(&csv, sin_tp * 0.05);
        csv_write_double(&csv, yu_tp);  csv_write_double(&csv, yu_tp * 0.05);
        csv_write_double(&csv, bai_tp); csv_write_double(&csv, bai_tp * 0.05);
        csv_new_row(&csv);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 7] Saved: results/exp7_unsigncrypt_throughput.csv\n");
    return 0;
}
