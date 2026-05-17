#ifndef RSA_H
#define RSA_H

#include "tls_cert.h"
#include <stddef.h>
#include <stdint.h>

// Verify an RSA PKCS#1 v1.5 SHA-256 signature.
// Returns 0 if valid, -1 if invalid.
int rsa_verify_pkcs1_sha256(const rsa_pubkey_t *key,
                            const uint8_t *hash, size_t hash_len,
                            const uint8_t *signature, size_t sig_len);

#endif
