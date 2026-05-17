#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

// Max 4096 bits = 128 x 32-bit limbs (need room for intermediate products)
#define BN_MAX_LIMBS 128

typedef struct {
    uint32_t d[BN_MAX_LIMBS];  // little-endian limbs (d[0] = least significant)
    int len;                   // number of active limbs
} bignum_t;

void bn_zero(bignum_t *a);
void bn_from_bytes(bignum_t *a, const uint8_t *buf, size_t buf_len);
void bn_to_bytes(const bignum_t *a, uint8_t *buf, size_t buf_len);
int bn_cmp(const bignum_t *a, const bignum_t *b);
int bn_is_zero(const bignum_t *a);

void bn_add(bignum_t *r, const bignum_t *a, const bignum_t *b);
void bn_sub(bignum_t *r, const bignum_t *a, const bignum_t *b);  // a must >= b
void bn_mul(bignum_t *r, const bignum_t *a, const bignum_t *b);

// r = a mod m
void bn_mod(bignum_t *r, const bignum_t *a, const bignum_t *m);

// r = (a * b) mod m
void bn_mulmod(bignum_t *r, const bignum_t *a, const bignum_t *b, const bignum_t *m);

// r = base^exp mod m (square-and-multiply)
void bn_modpow(bignum_t *r, const bignum_t *base, const bignum_t *exp, const bignum_t *m);

// r = a^(-1) mod m (modular inverse using extended euclidean)
void bn_modinv(bignum_t *r, const bignum_t *a, const bignum_t *m);

#endif
