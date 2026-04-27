/*
 * Experiment 2: Phase 4 Signcryption Performance vs File Size
 *
 * X-axis: file size (1 KB to 100 MB)
 * Y-axis: signcryption cost (ms)
 * Schemes: PQSCAAS, Sinha2026, Yu2021, Bai2025
 *
 * PQSCAAS operates on a fixed-size descriptor (not the full file), so
 * its cost should be essentially constant. Baselines grow linearly with |M|.
 */

#include "bench_utils.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int run_exp2() {
    const int NUM_TRIALS = 50;
    const size_t file_sizes[]  = { 1024, 10*1024, 100*1024, 1024*1024,
                                   10*1024*1024, 100*1024*1024 };
    const char *file_labels[]  = { "1 KB", "10 KB", "100 KB", "1 MB", "10 MB", "100 MB" };
    const size_t n_sizes = sizeof(file_sizes) / sizeof(file_sizes[0]);

    /* Setup: generate recipient KEM keypair + sender SIG keypair (once) */
    static uint8_t pk_r_kem[MLKEM768_PUBLICKEYBYTES];
    static uint8_t pk_u_sig[MLDSA65_PUBLICKEYBYTES];
    static uint8_t sealed_sk_r_kem[SEALED_KEM_SK_SIZE];
    static uint8_t sealed_sk_u_sig[SEALED_SIG_SK_SIZE];
    int ret_val = 0;
    uint8_t uid[USER_ID_SIZE]; memset(uid, 0xAA, sizeof(uid));
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem, pk_u_sig /* recipient SIG unused */,
                        sealed_sk_r_kem, sealed_sk_u_sig);
    uint8_t pk_u_sig2[MLDSA65_PUBLICKEYBYTES];
    uint8_t sealed_sk_u_sig2[SEALED_SIG_SK_SIZE];
    uint8_t pk_r_kem2[MLKEM768_PUBLICKEYBYTES];
    uint8_t sealed_sk_r_kem2[SEALED_KEM_SK_SIZE];
    uid[0] = 0xBB;
    ecall_phase2_keygen(g_enclave_id, &ret_val, uid,
                        pk_r_kem2, pk_u_sig2,
                        sealed_sk_r_kem2, sealed_sk_u_sig2);

    csv_t csv;
    csv_open(&csv, "results/exp2_phase4_vs_filesize.csv");
    csv_header(&csv,
               "file_size_bytes", "file_size_label",
               "PQSCAAS_mean", "PQSCAAS_std",
               "Sinha2026_mean", "Sinha2026_std",
               "Yu2021_mean", "Yu2021_std",
               "Bai2025_mean", "Bai2025_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t s = 0; s < n_sizes; s++) {
        size_t fs = file_sizes[s];
        fprintf(stderr, "[Exp 2] File size = %s ...\n", file_labels[s]);

        /* PQSCAAS timing */
        std::vector<double> pq_samples;
        for (int t = 0; t < NUM_TRIALS; t++) {
            pqscaas_descriptor_t desc;
            memset(&desc, 0, sizeof(desc));
            desc.ciphertext_len = (uint32_t)fs;
            memcpy(desc.sender_id, uid, USER_ID_SIZE);
            /* Random H(CT), K_d, nonce */
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) desc.h_ct[i] = (uint8_t)rand();
            for (int i = 0; i < K_D_SIZE; i++)           desc.k_d[i] = (uint8_t)rand();
            for (int i = 0; i < NONCE_SIZE; i++)         desc.nonce[i] = (uint8_t)rand();

            pqscaas_signcrypted_t sc;
            uint64_t t0 = host_now_ns();
            ecall_phase4_signcrypt_single(g_enclave_id, &ret_val,
                                          &desc, pk_r_kem2, sealed_sk_u_sig,
                                          &sc);
            uint64_t t1 = host_now_ns();
            pq_samples.push_back((double)(t1 - t0) / 1.0e6);
        }
        Stats pqs = compute_stats_ms(pq_samples);

        /* Baselines */
        std::vector<double> sin_s, yu_s, bai_s;
        for (int t = 0; t < NUM_TRIALS; t++) sin_s.push_back(sinha2026_signcrypt_ms(fs));
        for (int t = 0; t < NUM_TRIALS; t++) yu_s.push_back(yu2021_signcrypt_ms(fs));
        for (int t = 0; t < NUM_TRIALS; t++) bai_s.push_back(bai2025_signcrypt_ms(fs));
        Stats ss = compute_stats_ms(sin_s);
        Stats ys = compute_stats_ms(yu_s);
        Stats bs = compute_stats_ms(bai_s);

        csv_write_int   (&csv, (long)fs);
        csv_write_str   (&csv, file_labels[s]);
        csv_write_double(&csv, pqs.mean_ms); csv_write_double(&csv, pqs.std_ms);
        csv_write_double(&csv, ss.mean_ms);  csv_write_double(&csv, ss.std_ms);
        csv_write_double(&csv, ys.mean_ms);  csv_write_double(&csv, ys.std_ms);
        csv_write_double(&csv, bs.mean_ms);  csv_write_double(&csv, bs.std_ms);
        csv_new_row(&csv);

        fprintf(stderr, "  PQSCAAS: %.3f ± %.3f ms | Sinha: %.2f | Yu: %.2f | Bai: %.2f\n",
                pqs.mean_ms, pqs.std_ms, ss.mean_ms, ys.mean_ms, bs.mean_ms);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 2] Saved: results/exp2_phase4_vs_filesize.csv\n");
    return 0;
}
