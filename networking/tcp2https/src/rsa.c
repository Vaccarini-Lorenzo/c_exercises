#include "rsa.h"
#include "bignum.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

// PKCS#1 v1.5 SHA-256 DigestInfo prefix (DER-encoded)
// SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING hash }
static const uint8_t DIGEST_INFO_PREFIX[] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

int rsa_verify_pkcs1_sha256(const rsa_pubkey_t *key,
                            const uint8_t *hash, size_t hash_len,
                            const uint8_t *signature, size_t sig_len)
{
    if (hash_len != 32) return -1;
    if (sig_len != key->modulus_len) return -1;

    // Convert key components to bignums
    bignum_t n, e, sig, decrypted;
    bn_from_bytes(&n, key->modulus, key->modulus_len);
    bn_from_bytes(&e, key->exponent, key->exponent_len);
    bn_from_bytes(&sig, signature, sig_len);

    // RSA verify: decrypted = signature^e mod n
    bn_modpow(&decrypted, &sig, &e, &n);

    // Convert back to bytes
    uint8_t result[256];
    size_t result_len = key->modulus_len;
    bn_to_bytes(&decrypted, result, result_len);

    // Verify PKCS#1 v1.5 padding:
    // 00 01 FF FF ... FF 00 [DigestInfo prefix] [hash]
    size_t pos = 0;

    if (result[pos++] != 0x00) {
        LOG("rsa: bad padding byte 0");
        return -1;
    }
    if (result[pos++] != 0x01) {
        LOG("rsa: bad padding byte 1");
        return -1;
    }

    // Skip 0xFF bytes
    while (pos < result_len && result[pos] == 0xFF) pos++;

    if (pos >= result_len || result[pos] != 0x00) {
        LOG("rsa: bad padding separator");
        return -1;
    }
    pos++; // skip 0x00

    // Check DigestInfo prefix
    if (pos + sizeof(DIGEST_INFO_PREFIX) + 32 > result_len) {
        LOG("rsa: not enough room for digest");
        return -1;
    }

    if (memcmp(result + pos, DIGEST_INFO_PREFIX, sizeof(DIGEST_INFO_PREFIX)) != 0) {
        LOG("rsa: DigestInfo mismatch");
        return -1;
    }
    pos += sizeof(DIGEST_INFO_PREFIX);

    // Compare hash
    if (memcmp(result + pos, hash, 32) != 0) {
        LOG("rsa: hash mismatch");
        return -1;
    }

    return 0;
}
