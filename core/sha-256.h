#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  32
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void SHA256_Final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_SIZE]);
