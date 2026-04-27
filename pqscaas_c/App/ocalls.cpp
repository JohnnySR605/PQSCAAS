/* OCALLs: functions the enclave can call in the untrusted world */

#include <cstdio>
#include <time.h>
#include <stdint.h>

extern "C" void ocall_print_string(const char *str) {
    fputs(str, stderr);
}

extern "C" void ocall_get_time_ns(uint64_t *t) {
    if (t == NULL) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *t = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
