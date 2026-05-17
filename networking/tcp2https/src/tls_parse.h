#ifndef TLS_PARSE_H
#define TLS_PARSE_H

#include <stddef.h>
#include <stdint.h>

// Handshake message types
#define TLS_HS_SERVER_HELLO      0x02
#define TLS_HS_CERTIFICATE       0x0B
#define TLS_HS_SERVER_KEY_EXCH   0x0C
#define TLS_HS_SERVER_HELLO_DONE 0x0E

// Parsed ServerHello
typedef struct {
    uint16_t version;
    uint8_t server_random[32];
    uint16_t cipher_suite;
    uint8_t compression;
} server_hello_t;

// Parsed ServerKeyExchange (for ECDHE)
typedef struct {
    uint8_t curve_type;
    uint16_t named_curve;
    uint8_t pubkey[65];     // uncompressed P-256 point: 04 || X || Y
    uint8_t pubkey_len;
    uint8_t *signature;     // points into the record buffer (not owned)
    size_t signature_len;
} server_key_exchange_t;

// Parse ServerHello from handshake body (after 4-byte handshake header).
// Returns 0 on success, -1 on failure.
int tls_parse_server_hello(const uint8_t *data, size_t len, server_hello_t *out);

// Parse ServerKeyExchange from handshake body.
// Returns 0 on success, -1 on failure.
int tls_parse_server_key_exchange(const uint8_t *data, size_t len,
                                  server_key_exchange_t *out);

#endif
