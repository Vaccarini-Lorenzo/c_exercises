#include "p256.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// P-256 curve parameters
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
static const uint8_t P256_P[] = {
    0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
};

// Generator point G (x coordinate)
static const uint8_t P256_GX[] = {
    0x6B,0x17,0xD1,0xF2, 0xE1,0x2C,0x42,0x47,
    0xF8,0xBC,0xE6,0xE5, 0x63,0xA4,0x40,0xF2,
    0x77,0x03,0x7D,0x81, 0x2D,0xEB,0x33,0xA0,
    0xF4,0xA1,0x39,0x45, 0xD8,0x98,0xC2,0x96
};

// Generator point G (y coordinate)
static const uint8_t P256_GY[] = {
    0x4F,0xE3,0x42,0xE2, 0xFE,0x1A,0x7F,0x9B,
    0x8E,0xE7,0xEB,0x4A, 0x7C,0x0F,0x9E,0x16,
    0x2B,0xCE,0x33,0x57, 0x6B,0x31,0x5E,0xCE,
    0xCB,0xB6,0x40,0x68, 0x37,0xBF,0x51,0xF5
};

static bignum_t field_p;
static int initialized = 0;

static void ensure_init(void)
{
    if (initialized) return;
    bn_from_bytes(&field_p, P256_P, 32);
    initialized = 1;
}

// Field operations mod p
static void field_add(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bn_add(r, a, b);
    if (bn_cmp(r, &field_p) >= 0)
        bn_sub(r, r, &field_p);
}

static void field_sub(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    if (bn_cmp(a, b) >= 0) {
        bn_sub(r, a, b);
    } else {
        bignum_t tmp;
        bn_add(&tmp, a, &field_p);
        bn_sub(r, &tmp, b);
    }
}

static void field_mul(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bn_mulmod(r, a, b, &field_p);
}

static void field_inv(bignum_t *r, const bignum_t *a)
{
    bn_modinv(r, a, &field_p);
}

static int point_is_inf(const p256_point_t *p)
{
    return bn_is_zero(&p->x) && bn_is_zero(&p->y);
}

static void point_set_inf(p256_point_t *p)
{
    bn_zero(&p->x);
    bn_zero(&p->y);
}

// Point doubling: result = 2 * p
static void point_double(p256_point_t *r, const p256_point_t *p)
{
    ensure_init();
    if (point_is_inf(p)) { point_set_inf(r); return; }

    // lambda = (3*x^2 + a) / (2*y), where a = -3 for P-256
    bignum_t x2, num, denom, lambda, tmp;

    field_mul(&x2, &p->x, &p->x);        // x^2
    field_add(&num, &x2, &x2);            // 2*x^2
    field_add(&num, &num, &x2);           // 3*x^2

    // a = -3 = p - 3
    bignum_t three;
    bn_zero(&three);
    three.d[0] = 3;
    bignum_t a_coeff;
    bn_sub(&a_coeff, &field_p, &three);   // p - 3

    field_add(&num, &num, &a_coeff);      // 3*x^2 + a

    field_add(&denom, &p->y, &p->y);      // 2*y
    field_inv(&tmp, &denom);              // 1/(2*y)
    field_mul(&lambda, &num, &tmp);       // lambda

    // x_r = lambda^2 - 2*x
    field_mul(&tmp, &lambda, &lambda);
    field_sub(&r->x, &tmp, &p->x);
    field_sub(&r->x, &r->x, &p->x);

    // y_r = lambda * (x - x_r) - y
    field_sub(&tmp, &p->x, &r->x);
    field_mul(&tmp, &lambda, &tmp);
    field_sub(&r->y, &tmp, &p->y);
}

// Point addition: result = a + b
static void point_add(p256_point_t *r, const p256_point_t *a, const p256_point_t *b)
{
    ensure_init();
    if (point_is_inf(a)) { *r = *b; return; }
    if (point_is_inf(b)) { *r = *a; return; }

    // If same point, use doubling
    if (bn_cmp(&a->x, &b->x) == 0) {
        if (bn_cmp(&a->y, &b->y) == 0) {
            point_double(r, a);
            return;
        }
        // a = -b, result is infinity
        point_set_inf(r);
        return;
    }

    // lambda = (y2 - y1) / (x2 - x1)
    bignum_t num, denom, lambda, tmp;
    field_sub(&num, &b->y, &a->y);
    field_sub(&denom, &b->x, &a->x);
    field_inv(&tmp, &denom);
    field_mul(&lambda, &num, &tmp);

    // x_r = lambda^2 - x1 - x2
    field_mul(&tmp, &lambda, &lambda);
    field_sub(&r->x, &tmp, &a->x);
    field_sub(&r->x, &r->x, &b->x);

    // y_r = lambda * (x1 - x_r) - y1
    field_sub(&tmp, &a->x, &r->x);
    field_mul(&tmp, &lambda, &tmp);
    field_sub(&r->y, &tmp, &a->y);
}

void p256_scalar_mult(p256_point_t *result, const uint8_t *scalar,
                      const p256_point_t *point)
{
    ensure_init();
    p256_point_t r, tmp;
    point_set_inf(&r);
    tmp = *point;

    // Double-and-add, LSB first
    for (int i = 255; i >= 0; i--) {
        point_double(&r, &r);
        int bit = (scalar[31 - i/8] >> (i % 8)) & 1;
        if (bit) {
            point_add(&r, &r, &tmp);
        }
    }
    *result = r;
}

int p256_point_from_bytes(p256_point_t *p, const uint8_t *buf, size_t len)
{
    if (len != 65 || buf[0] != 0x04) return -1;
    bn_from_bytes(&p->x, buf + 1, 32);
    bn_from_bytes(&p->y, buf + 33, 32);
    return 0;
}

void p256_point_to_bytes(const p256_point_t *p, uint8_t *buf)
{
    buf[0] = 0x04;
    bn_to_bytes(&p->x, buf + 1, 32);
    bn_to_bytes(&p->y, buf + 33, 32);
}

int p256_gen_keypair(uint8_t *privkey, p256_point_t *pubkey)
{
    // Read 32 random bytes as private key
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, privkey, 32);
    close(fd);
    if (n != 32) return -1;

    // Public key = privkey * G
    p256_point_t G;
    bn_from_bytes(&G.x, P256_GX, 32);
    bn_from_bytes(&G.y, P256_GY, 32);

    p256_scalar_mult(pubkey, privkey, &G);
    return 0;
}

void p256_shared_secret(uint8_t *secret_out, const uint8_t *our_privkey,
                        const p256_point_t *their_pubkey)
{
    p256_point_t shared;
    p256_scalar_mult(&shared, our_privkey, their_pubkey);
    // Shared secret is the X coordinate
    bn_to_bytes(&shared.x, secret_out, 32);
}
