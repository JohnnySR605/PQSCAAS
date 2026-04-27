#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* High-resolution monotonic clock (nanoseconds) */
uint64_t now_ns(void);

/* Convert ns to milliseconds */
static inline double ns_to_ms(uint64_t ns) {
    return (double)ns / 1.0e6;
}

static inline double ns_to_s(uint64_t ns) {
    return (double)ns / 1.0e9;
}

/* Benchmark statistics */
typedef struct {
    double mean_ms;
    double std_ms;
    double min_ms;
    double max_ms;
    double median_ms;
    size_t n_trials;
} bench_stats_t;

/* Compute statistics from a sample array (in nanoseconds) */
void compute_stats(const uint64_t *samples, size_t n, bench_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_COMMON_H */
