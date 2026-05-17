#ifndef P256_H
#define P256_H

#include "bignum.h"
#include <stdint.h>

// A point on the P-256 curve (affine coordinates)
// Point at infinity represented by x=0, y=0
typedef struct {
    bignum_t x;
    bignum_t y;
} p256_point_t;

// Generate a random private key (scalar, 32 bytes)
int p256_gen_keypair(uint8_t *privkey, p256_point_t *pubkey);

// Scalar multiplication: result = scalar * point
void p256_scalar_mult(p256_point_t *result, const uint8_t *scalar,
                      const p256_point_t *point);

// Decode an uncompressed point (65 bytes: 04 || X || Y)
int p256_point_from_bytes(p256_point_t *p, const uint8_t *buf, size_t len);

// Get the shared secret X coordinate as 32 bytes
void p256_shared_secret(uint8_t *secret_out, const uint8_t *our_privkey,
                        const p256_point_t *their_pubkey);

// Encode our public key as uncompressed (65 bytes: 04 || X || Y)
void p256_point_to_bytes(const p256_point_t *p, uint8_t *buf);

#endif
