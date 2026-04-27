#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_LEN  32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
    size_t   buflen;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LEN]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif
