#include "bignum.h"
#include <string.h>

void bn_zero(bignum_t *a)
{
    memset(a->d, 0, sizeof(a->d));
    a->len = 1;
}

void bn_from_bytes(bignum_t *a, const uint8_t *buf, size_t buf_len)
{
    bn_zero(a);
    // buf is big-endian, we store little-endian limbs
    int limbs = (buf_len + 3) / 4;
    if (limbs > BN_MAX_LIMBS) limbs = BN_MAX_LIMBS;

    for (size_t i = 0; i < buf_len; i++) {
        size_t byte_pos = buf_len - 1 - i;  // position from LSB
        int limb_idx = byte_pos / 4;
        // Flip: we read from buf[i] which is the most significant
        limb_idx = (buf_len - 1 - i) / 4;
        int shift = ((buf_len - 1 - i) % 4) * 8;
        if (limb_idx < BN_MAX_LIMBS)
            a->d[limb_idx] |= (uint32_t)buf[i] << shift;
    }
    a->len = limbs;
    // Trim leading zeros
    while (a->len > 1 && a->d[a->len - 1] == 0) a->len--;
}

void bn_to_bytes(const bignum_t *a, uint8_t *buf, size_t buf_len)
{
    memset(buf, 0, buf_len);
    for (size_t i = 0; i < buf_len; i++) {
        size_t byte_pos = buf_len - 1 - i;
        int limb_idx = i / 4;
        int shift = (i % 4) * 8;
        if (limb_idx < a->len)
            buf[byte_pos] = (a->d[limb_idx] >> shift) & 0xFF;
    }
}

int bn_is_zero(const bignum_t *a)
{
    for (int i = 0; i < a->len; i++)
        if (a->d[i] != 0) return 0;
    return 1;
}

int bn_cmp(const bignum_t *a, const bignum_t *b)
{
    int max = a->len > b->len ? a->len : b->len;
    for (int i = max - 1; i >= 0; i--) {
        uint32_t av = (i < a->len) ? a->d[i] : 0;
        uint32_t bv = (i < b->len) ? b->d[i] : 0;
        if (av > bv) return 1;
        if (av < bv) return -1;
    }
    return 0;
}

void bn_add(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    uint64_t carry = 0;
    int max = a->len > b->len ? a->len : b->len;
    for (int i = 0; i < max || carry; i++) {
        uint64_t sum = carry;
        if (i < a->len) sum += a->d[i];
        if (i < b->len) sum += b->d[i];
        r->d[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
        if (i >= max) max = i + 1;
    }
    r->len = max;
    if (r->len > BN_MAX_LIMBS) r->len = BN_MAX_LIMBS;
}

void bn_sub(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    int64_t borrow = 0;
    int max = a->len;
    for (int i = 0; i < max; i++) {
        int64_t diff = (int64_t)a->d[i] - borrow;
        if (i < b->len) diff -= b->d[i];
        if (diff < 0) {
            diff += (int64_t)1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        r->d[i] = (uint32_t)diff;
    }
    r->len = max;
    while (r->len > 1 && r->d[r->len - 1] == 0) r->len--;
}

void bn_mul(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bignum_t tmp;
    bn_zero(&tmp);
    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->len; j++) {
            int k = i + j;
            if (k >= BN_MAX_LIMBS) break;
            uint64_t prod = (uint64_t)a->d[i] * b->d[j] + tmp.d[k] + carry;
            tmp.d[k] = (uint32_t)(prod & 0xFFFFFFFF);
            carry = prod >> 32;
        }
        if (i + b->len < BN_MAX_LIMBS)
            tmp.d[i + b->len] = (uint32_t)carry;
    }
    tmp.len = a->len + b->len;
    if (tmp.len > BN_MAX_LIMBS) tmp.len = BN_MAX_LIMBS;
    while (tmp.len > 1 && tmp.d[tmp.len - 1] == 0) tmp.len--;
    *r = tmp;
}

// Shift left by 1 bit
static void bn_shl1(bignum_t *a)
{
    uint32_t carry = 0;
    for (int i = 0; i < a->len; i++) {
        uint32_t next_carry = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry && a->len < BN_MAX_LIMBS) {
        a->d[a->len] = carry;
        a->len++;
    }
}

void bn_mod(bignum_t *r, const bignum_t *a, const bignum_t *m)
{
    bignum_t tmp = *a;
    // Simple: repeated subtraction with shifting
    // Find highest bit of tmp
    int a_bits = tmp.len * 32;
    while (a_bits > 0 && ((tmp.d[(a_bits-1)/32] >> ((a_bits-1)%32)) & 1) == 0)
        a_bits--;
    int m_bits = m->len * 32;
    while (m_bits > 0 && ((m->d[(m_bits-1)/32] >> ((m_bits-1)%32)) & 1) == 0)
        m_bits--;

    if (a_bits == 0 || bn_cmp(&tmp, m) < 0) { *r = tmp; return; }

    // Shift m left to align with a
    bignum_t shifted = *m;
    int shift = a_bits - m_bits;
    // Shift m left by 'shift' bits
    for (int s = 0; s < shift; s++) bn_shl1(&shifted);

    for (int i = shift; i >= 0; i--) {
        if (bn_cmp(&tmp, &shifted) >= 0) {
            bn_sub(&tmp, &tmp, &shifted);
        }
        // Shift right by 1
        for (int j = 0; j < shifted.len; j++) {
            shifted.d[j] >>= 1;
            if (j + 1 < shifted.len)
                shifted.d[j] |= (shifted.d[j+1] & 1) << 31;
        }
        while (shifted.len > 1 && shifted.d[shifted.len-1] == 0) shifted.len--;
    }
    *r = tmp;
    while (r->len > 1 && r->d[r->len - 1] == 0) r->len--;
}

void bn_mulmod(bignum_t *r, const bignum_t *a, const bignum_t *b, const bignum_t *m)
{
    bignum_t tmp;
    bn_mul(&tmp, a, b);
    bn_mod(r, &tmp, m);
}

void bn_modpow(bignum_t *r, const bignum_t *base, const bignum_t *exp, const bignum_t *m)
{
    bignum_t result, b;
    bn_zero(&result);
    result.d[0] = 1;  // result = 1
    b = *base;
    bn_mod(&b, &b, m);

    // Find highest bit of exp
    int exp_bits = exp->len * 32;
    while (exp_bits > 0 && ((exp->d[(exp_bits-1)/32] >> ((exp_bits-1)%32)) & 1) == 0)
        exp_bits--;

    for (int i = 0; i < exp_bits; i++) {
        int bit = (exp->d[i/32] >> (i%32)) & 1;
        if (bit) {
            bn_mulmod(&result, &result, &b, m);
        }
        bn_mulmod(&b, &b, &b, m);
    }
    *r = result;
}

void bn_modinv(bignum_t *r, const bignum_t *a, const bignum_t *m)
{
    // Using Fermat's little theorem: a^(m-2) mod m (works when m is prime)
    // For general case we'd need extended GCD, but our moduli are prime
    bignum_t exp = *m;
    bignum_t two;
    bn_zero(&two);
    two.d[0] = 2;
    bn_sub(&exp, &exp, &two);
    bn_modpow(r, a, &exp, m);
}
