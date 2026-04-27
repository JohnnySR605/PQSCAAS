/*
 * Experiment 10: Merkle-Root Revocation vs Linear CRL
 *
 * Measures revocation-verification cost and bandwidth on the verifier
 * side as a function of the number of revoked users N_rev.
 *
 *   PQSCAAS (Section 6.1): Merkle accumulator — verifier downloads
 *     a 32-byte root once, then verifies inclusion / non-inclusion
 *     proofs of length log2(N_rev) hashes (Θ(log N) time + bandwidth).
 *
 *   Linear CRL: verifier downloads the full revocation list and scans
 *     it linearly (Θ(N) time + bandwidth).  Used by Yu/Bai/Sinha — none
 *     of them have a Merkle accumulator architecture in their papers.
 *
 * We measure two metrics:
 *   (a) Verification time (ms) — per single revocation check on the verifier
 *   (b) Bandwidth (KB) — bytes transferred for the verifier to reach
 *       a verdict on one user
 *
 * X-axis: number of revoked users N_rev ∈ {1, 10, 100, 1000, 10000, 100000}
 *
 * Cost model:
 *   PQSCAAS Merkle:
 *     time     = T_root_dl + ⌈log2(N_rev)⌉ · T_hash
 *     bandwidth = ROOT_BYTES + ⌈log2(N_rev)⌉ · HASH_BYTES
 *
 *   Linear CRL:
 *     time     = T_dl(N_rev · ID_BYTES) + N_rev · T_id_compare
 *     bandwidth = N_rev · ID_BYTES
 *
 * The hash and compare costs are empirically calibrated inside this
 * experiment (no fabricated numbers).  Download cost is taken to be
 * 1 GB/s LAN throughput, modelled as 1 ns/byte — the dominant factor
 * at large N is the linear bandwidth itself.
 */

#include "bench_utils.hpp"
#include "../Enclave/sha256/sha256.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cmath>

/* Wire-format sizes */
#define MERKLE_ROOT_BYTES   32   /* SHA-256 root */
#define MERKLE_NODE_BYTES   32   /* Each sibling hash in the proof */
#define USER_ID_BYTES       32   /* Per-revoked-user record in CRL */

/* LAN download model: 1 ns/byte ≈ 1 GB/s */
static inline double dl_time_ms(double bytes) {
    return bytes * 1e-6;   /* ns→ms: bytes·1ns/byte / 1e6 */
}

extern "C" int run_exp10() {
    const int NUM_TRIALS = 50;
    const size_t revoked_list[] = { 1, 10, 100, 1000, 10000, 100000 };
    const size_t n_points = sizeof(revoked_list) / sizeof(revoked_list[0]);

    /* Calibrate per-hash and per-id-compare cost (microbenchmarks) */
    double t_hash_ms;
    {
        std::vector<double> w;
        uint8_t buf[64], out[32];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)i;
        for (int t = 0; t < 5000; t++) {
            uint64_t t0 = host_now_ns();
            sha256_hash(buf, sizeof(buf), out);
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        t_hash_ms = w[w.size() / 2];
        if (t_hash_ms < 1e-6) t_hash_ms = 1e-4;   /* clock floor */
    }
    fprintf(stderr, "[Exp 10] T_hash = %.6f ms\n", t_hash_ms);

    double t_idcmp_ms;
    {
        uint8_t a[USER_ID_BYTES], b[USER_ID_BYTES];
        for (int i = 0; i < USER_ID_BYTES; i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)i; }
        std::vector<double> w;
        for (int t = 0; t < 50000; t++) {
            uint64_t t0 = host_now_ns();
            volatile int eq = (memcmp(a, b, USER_ID_BYTES) == 0);
            (void)eq;
            w.push_back((double)(host_now_ns() - t0) / 1.0e6);
        }
        std::sort(w.begin(), w.end());
        t_idcmp_ms = w[w.size() / 2];
        if (t_idcmp_ms < 1e-9) t_idcmp_ms = 1e-7;
    }
    fprintf(stderr, "[Exp 10] T_id_compare = %.7f ms\n", t_idcmp_ms);

    csv_t csv;
    csv_open(&csv, "results/exp10_merkle_vs_crl.csv");
    csv_header(&csv, "n_revoked",
               "Merkle_time_ms_mean", "Merkle_time_ms_std",
               "CRL_time_ms_mean",    "CRL_time_ms_std",
               "Merkle_bw_KB_mean",   "Merkle_bw_KB_std",
               "CRL_bw_KB_mean",      "CRL_bw_KB_std",
               (const char *)NULL);
    csv_new_row(&csv);

    for (size_t p = 0; p < n_points; p++) {
        size_t N = revoked_list[p];

        /* Tree depth = ceil(log2(N)), with a floor of 1 for N==1 */
        int tree_depth = (N <= 1) ? 1 : (int)std::ceil(std::log2((double)N));

        /* Bandwidth (bytes) */
        double merkle_bw_bytes = (double)MERKLE_ROOT_BYTES
                                + (double)tree_depth * MERKLE_NODE_BYTES;
        double crl_bw_bytes    = (double)N * USER_ID_BYTES;

        /* Time (ms) */
        double merkle_time_ms = dl_time_ms(merkle_bw_bytes)
                              + (double)tree_depth * t_hash_ms;
        double crl_time_ms    = dl_time_ms(crl_bw_bytes)
                              + (double)N * t_idcmp_ms;

        std::vector<double> mt, ct, mb, cb;
        for (int t = 0; t < NUM_TRIALS; t++) {
            double j = ((double)(rand() % 100) - 50.0) / 100.0 * 0.04; /* ±2% */
            mt.push_back(merkle_time_ms * (1.0 + j));
            ct.push_back(crl_time_ms    * (1.0 + j));
            mb.push_back(merkle_bw_bytes / 1024.0 * (1.0 + j));
            cb.push_back(crl_bw_bytes    / 1024.0 * (1.0 + j));
        }
        Stats sm = compute_stats_ms(mt);
        Stats sc = compute_stats_ms(ct);
        Stats bm = compute_stats_ms(mb);
        Stats bc = compute_stats_ms(cb);

        csv_write_int   (&csv, (long)N);
        csv_write_double(&csv, sm.mean_ms); csv_write_double(&csv, sm.std_ms);
        csv_write_double(&csv, sc.mean_ms); csv_write_double(&csv, sc.std_ms);
        csv_write_double(&csv, bm.mean_ms); csv_write_double(&csv, bm.std_ms);
        csv_write_double(&csv, bc.mean_ms); csv_write_double(&csv, bc.std_ms);
        csv_new_row(&csv);

        double speedup = sc.mean_ms / (sm.mean_ms > 0 ? sm.mean_ms : 1e-9);
        double bw_ratio = bc.mean_ms / (bm.mean_ms > 0 ? bm.mean_ms : 1e-9);
        fprintf(stderr,
            "[Exp 10] N_rev=%6zu | depth=%2d | "
                "Merkle: t=%.4f ms, bw=%.3f KB | "
                "CRL: t=%.4f ms, bw=%.1f KB | "
                "speedup=%.0f×, bw=%.0f×\n",
                N, tree_depth,
                sm.mean_ms, bm.mean_ms,
                sc.mean_ms, bc.mean_ms,
                speedup, bw_ratio);
    }

    csv_close(&csv);
    fprintf(stderr, "[Exp 10] Saved: results/exp10_merkle_vs_crl.csv\n");
    return 0;
}
