#ifndef TLS_CERT_H
#define TLS_CERT_H

#include <stddef.h>
#include <stdint.h>

// RSA public key extracted from certificate
typedef struct {
    uint8_t modulus[256];     // up to 2048 bits
    size_t modulus_len;
    uint8_t exponent[4];     // typically 65537 (3 bytes)
    size_t exponent_len;
} rsa_pubkey_t;

// Parse the TLS Certificate message body.
// Extracts the RSA public key from the first (leaf) certificate.
// Returns 0 on success, -1 on failure.
int tls_cert_extract_rsa_pubkey(const uint8_t *data, size_t len,
                                rsa_pubkey_t *key_out);

#endif
