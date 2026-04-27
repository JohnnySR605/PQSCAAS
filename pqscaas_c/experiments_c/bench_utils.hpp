#ifndef BENCH_UTILS_HPP
#define BENCH_UTILS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <time.h>

#include "App.h"
#include "../include/pqscaas_types.h"
#include "../include/bench_common.h"
#include "../include/csv_writer.h"

/* Baselines (pure untrusted implementations in baselines_c/) */
extern "C" {
    double sinha2026_signcrypt_ms(size_t file_size);
    double sinha2026_unsigncrypt_ms(size_t file_size);
    double sinha2026_keygen_ms(size_t n_users);
    double yu2021_signcrypt_ms(size_t file_size);
    double yu2021_unsigncrypt_ms(size_t file_size);
    double yu2021_keygen_ms(size_t n_users);
    double bai2025_signcrypt_ms(size_t file_size);    /* Total = Off+On = 0.112ms */
    double bai2025_unsigncrypt_ms(size_t file_size);  /* 0.112 ms */
    double bai2025_keygen_ms(size_t n_users);
    double bai2025_offline_signcrypt_ms();             /* OffSig = 0.110 ms */
    double bai2025_online_signcrypt_ms(size_t fs);     /* OnSig = 0.002 ms */
}

/* Now-ns helper (normal world) */
static inline uint64_t host_now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---------- Simple statistics ---------- */
struct Stats {
    double mean_ms = 0.0;
    double std_ms = 0.0;
};

inline Stats compute_stats_ms(const std::vector<double>& samples) {
    Stats s;
    if (samples.empty()) return s;
    double sum = 0.0;
    for (double x : samples) sum += x;
    s.mean_ms = sum / (double)samples.size();
    double var = 0.0;
    for (double x : samples) { double d = x - s.mean_ms; var += d*d; }
    var /= (double)samples.size();
    s.std_ms = std::sqrt(var);
    return s;
}

/* ---------- Elastic scaling (Eq. 61) ---------- */
inline uint32_t elastic_enclaves(uint32_t n_requests, uint32_t batch_capacity = BATCH_CAPACITY) {
    /* Activate enclaves while utilization ρ = λ / (E · μ) ≥ τρ = 0.8 */
    uint32_t e = 1;
    while ((double)n_requests / ((double)e * (double)batch_capacity) >= 0.8) e++;
    return e;
}

#endif
