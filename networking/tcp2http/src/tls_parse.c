#include "tls_parse.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

int tls_parse_server_hello(const uint8_t *data, size_t len, server_hello_t *out)
{
    // Minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1) = 38
    if (len < 38) {
        fprintf(stderr, "tls_parse: ServerHello too short (%zu)\n", len);
        return -1;
    }

    size_t pos = 0;

    // Version
    out->version = read_u16(data + pos);
    pos += 2;

    // Server random
    memcpy(out->server_random, data + pos, 32);
    pos += 32;

    // Session ID (skip it)
    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;

    if (pos + 3 > len) return -1;

    // Cipher suite chosen
    out->cipher_suite = read_u16(data + pos);
    pos += 2;

    // Compression method
    out->compression = data[pos];

    return 0;
}

int tls_parse_server_key_exchange(const uint8_t *data, size_t len,
                                  server_key_exchange_t *out)
{
    if (len < 4) {
        fprintf(stderr, "tls_parse: ServerKeyExchange too short\n");
        return -1;
    }

    size_t pos = 0;

    // EC curve type (should be 0x03 = named_curve)
    out->curve_type = data[pos];
    pos += 1;

    // Named curve
    out->named_curve = read_u16(data + pos);
    pos += 2;

    // Public key length
    uint8_t pk_len = data[pos];
    pos += 1;

    if (pk_len > 65 || pos + pk_len > len) {
        fprintf(stderr, "tls_parse: invalid pubkey length %u\n", pk_len);
        return -1;
    }

    // Public key (uncompressed point: 04 || X || Y)
    memcpy(out->pubkey, data + pos, pk_len);
    out->pubkey_len = pk_len;
    pos += pk_len;

    // Signature algorithm (2 bytes) — we just skip it for now
    if (pos + 2 > len) return -1;
    pos += 2;

    // Signature length
    if (pos + 2 > len) return -1;
    uint16_t sig_len = read_u16(data + pos);
    pos += 2;

    if (pos + sig_len > len) return -1;

    // Signature (points into original buffer)
    out->signature = (uint8_t *)(data + pos);
    out->signature_len = sig_len;

    return 0;
}
