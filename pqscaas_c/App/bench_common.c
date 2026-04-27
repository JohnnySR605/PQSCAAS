#include "bench_common.h"
#include "csv_writer.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

void compute_stats(const uint64_t *samples, size_t n, bench_stats_t *out) {
    if (n == 0) {
        memset(out, 0, sizeof(*out));
        return;
    }

    uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
    memcpy(sorted, samples, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), cmp_u64);

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) sum += (double)sorted[i];
    double mean = sum / (double)n;

    double var = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = (double)sorted[i] - mean;
        var += d * d;
    }
    var /= (double)n;

    out->mean_ms   = mean / 1.0e6;
    out->std_ms    = sqrt(var) / 1.0e6;
    out->min_ms    = (double)sorted[0] / 1.0e6;
    out->max_ms    = (double)sorted[n - 1] / 1.0e6;
    out->median_ms = (double)sorted[n / 2] / 1.0e6;
    out->n_trials  = n;

    free(sorted);
}

/* ======================================================================== */
/* CSV writer                                                                */
/* ======================================================================== */

int csv_open(csv_t *c, const char *path) {
    c->fp = fopen(path, "w");
    c->first_column = 1;
    return c->fp ? 0 : -1;
}

void csv_close(csv_t *c) {
    if (c->fp) {
        fputc('\n', c->fp);
        fclose(c->fp);
        c->fp = NULL;
    }
}

void csv_header(csv_t *c, ...) {
    va_list ap;
    va_start(ap, c);
    const char *col;
    int first = 1;
    while ((col = va_arg(ap, const char *)) != NULL) {
        if (!first) fputc(',', c->fp);
        fputs(col, c->fp);
        first = 0;
    }
    va_end(ap);
    c->first_column = 1;
}

void csv_new_row(csv_t *c) {
    fputc('\n', c->fp);
    c->first_column = 1;
}

static void sep(csv_t *c) {
    if (!c->first_column) fputc(',', c->fp);
    c->first_column = 0;
}

void csv_write_int(csv_t *c, long v) {
    sep(c);
    fprintf(c->fp, "%ld", v);
}

void csv_write_double(csv_t *c, double v) {
    sep(c);
    fprintf(c->fp, "%.6f", v);
}

void csv_write_str(csv_t *c, const char *s) {
    sep(c);
    fputs(s, c->fp);
}
