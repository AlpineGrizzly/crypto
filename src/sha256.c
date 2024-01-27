/**
 * sha256.c 
 * Implemetation of sha256 algorithm functions
 * 
 * Author Dalton Kinney
 * Created Jan 27, 2024
*/
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#include "sha256.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// SHA-256 constants (K)
static const uint32_t SHA256_K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Structure to hold the state, count, and buffer for SHA-256
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX;

// SHA-256 transformation function
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2;

    // Prepare the message schedule
    for (i = 0; i < 16; i++)
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    for (i = 16; i < 64; i++)
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];

    // Initialize working variables with the current hash value
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // Main loop of SHA-256 transformation
    for (i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + SHA256_K[i] + w[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update the hash values with the results from this block
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    // Clear sensitive information in the local variables
    memset(w, 0, sizeof(w));
}

// SHA-256 initialization function
static void sha256_init(SHA256_CTX *ctx) {
    // Initialize the SHA-256 context with initial hash values
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

// SHA-256 update function
static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;

    // Update the context with input data
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = data[i];
        ctx->count++;

        // Perform the transformation for each block
        if (ctx->count % SHA256_BLOCK_SIZE == 0)
            sha256_transform(ctx, ctx->buffer);
    }
}

// SHA-256 finalization function
static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint64_t bit_count = ctx->count * 8;

    // Pad the message to ensure that the final block is complete
    ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = 0x80;
    ctx->count++;

    // Check if padding requires an extra block
    if (ctx->count % SHA256_BLOCK_SIZE > 56) {
        while (ctx->count % SHA256_BLOCK_SIZE != 0) {
            ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = 0x00;
            ctx->count++;
        }
    }

    // Append the bit count to the padding
    for (size_t i = 0; i < 8; i++) {
        ctx->buffer[(SHA256_BLOCK_SIZE - 1 - i) % SHA256_BLOCK_SIZE] = (uint8_t)(bit_count >> (i * 8));
    }

    // Perform the final transformation
    sha256_transform(ctx, ctx->buffer);

    // Copy the state to the hash output
    for (size_t i = 0; i < 8; i++) {
        hash[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)ctx->state[i];
    }

    // Clear sensitive information in the context structure
    memset(ctx, 0, sizeof(*ctx));
}

char* sha256(FILE *file) { 
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t buffer[SHA256_BLOCK_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, SHA256_BLOCK_SIZE, file)) > 0) {
        sha256_update(&ctx, buffer, bytesRead);
    }

    // Finalize the hash
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, hash);

    // Convert the binary hash to a hexadecimal string
    char* hexHash = (char*)malloc(2 * SHA256_DIGEST_SIZE + 1);
    if (hexHash == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(hexHash + 2 * i, "%02x", hash[i]);
    }
    hexHash[2 * SHA256_DIGEST_SIZE] = '\0';

    fclose(file);
    return hexHash;
}