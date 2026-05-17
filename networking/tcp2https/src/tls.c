#include "tls.h"
#include "tls_record.h"
#include "tls_hello.h"
#include "tls_parse.h"
#include "tls_cert.h"
#include "rsa.h"
#include "sha256.h"
#include "p256.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_state {
    int sockfd;
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t master_secret[48];
    // TODO: session keys for encrypt/decrypt
};

// Verify the RSA signature on ServerKeyExchange.
// The signed data is: client_random + server_random + server_params
// (curve_type + named_curve + pubkey_len + pubkey)
static int verify_ske_signature(const uint8_t *client_random,
                                const uint8_t *server_random,
                                const server_key_exchange_t *ske,
                                const rsa_pubkey_t *rsa_key,
                                const uint8_t *ske_raw, size_t ske_raw_len)
{
    (void)ske_raw_len;
    // The signed portion is everything before the signature:
    // curve_type(1) + named_curve(2) + pubkey_len(1) + pubkey(N)
    size_t params_len = 1 + 2 + 1 + ske->pubkey_len;

    // Build the data that was signed
    size_t signed_data_len = 32 + 32 + params_len;
    uint8_t *signed_data = malloc(signed_data_len);
    if (!signed_data) return -1;

    memcpy(signed_data, client_random, 32);
    memcpy(signed_data + 32, server_random, 32);
    memcpy(signed_data + 64, ske_raw, params_len);

    // Hash it with SHA-256
    uint8_t hash[32];
    sha256(signed_data, signed_data_len, hash);
    free(signed_data);

    // Verify RSA signature
    int result = rsa_verify_pkcs1_sha256(rsa_key, hash, 32,
                                         ske->signature, ske->signature_len);
    return result;
}

// Walk a buffer of concatenated handshake messages
static int process_handshake_messages(const uint8_t *data, size_t data_len,
                                      server_hello_t *sh,
                                      server_key_exchange_t *ske,
                                      rsa_pubkey_t *rsa_key,
                                      const uint8_t **ske_raw,
                                      size_t *ske_raw_len,
                                      int *got_done)
{
    size_t pos = 0;

    while (pos < data_len) {
        if (pos + 4 > data_len) return -1;

        uint8_t msg_type = data[pos];
        uint32_t msg_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        if (pos + msg_len > data_len) return -1;
        const uint8_t *body = data + pos;

        switch (msg_type) {
        case TLS_HS_SERVER_HELLO:
            LOG("[tls] <- ServerHello (%u bytes)", msg_len);
            if (tls_parse_server_hello(body, msg_len, sh) < 0) return -1;
            LOG("[tls]    version=0x%04X cipher=0x%04X",
                   sh->version, sh->cipher_suite);
            break;

        case TLS_HS_CERTIFICATE:
            LOG("[tls] <- Certificate (%u bytes)", msg_len);
            if (tls_cert_extract_rsa_pubkey(body, msg_len, rsa_key) < 0)
                return -1;
            break;

        case TLS_HS_SERVER_KEY_EXCH:
            LOG("[tls] <- ServerKeyExchange (%u bytes)", msg_len);
            *ske_raw = body;
            *ske_raw_len = msg_len;
            if (tls_parse_server_key_exchange(body, msg_len, ske) < 0)
                return -1;
            LOG("[tls]    curve=0x%04X pubkey_len=%u sig_len=%zu",
                   ske->named_curve, ske->pubkey_len, ske->signature_len);
            break;

        case TLS_HS_SERVER_HELLO_DONE:
            LOG("[tls] <- ServerHelloDone");
            *got_done = 1;
            break;

        default:
            LOG("[tls] <- Unknown type 0x%02X (%u bytes)", msg_type, msg_len);
            break;
        }
        pos += msg_len;
    }
    return 0;
}

tls_state_t *tls_handshake(int sockfd, const char *hostname)
{
    uint8_t buf[4096];
    uint8_t client_random[32];

    // Build and send ClientHello
    size_t hello_len = tls_build_client_hello(buf, sizeof(buf),
                                              hostname, client_random);
    LOG("[tls] -> ClientHello (%zu bytes)", hello_len);

    if (tls_record_send(sockfd, TLS_CONTENT_HANDSHAKE,
                        TLS_VERSION_1_0, buf, hello_len) < 0) {
        LOG("tls: failed to send ClientHello");
        return NULL;
    }

    // Read all server handshake messages
    server_hello_t sh;
    server_key_exchange_t ske;
    rsa_pubkey_t rsa_key;
    const uint8_t *ske_raw = NULL;
    size_t ske_raw_len = 0;
    int got_done = 0;

    while (!got_done) {
        uint8_t recv_buf[TLS_MAX_RECORD_PAYLOAD];
        uint8_t content_type;
        size_t recv_len;

        if (tls_record_recv(sockfd, &content_type, recv_buf, &recv_len) < 0) {
            LOG("tls: failed to read server record");
            return NULL;
        }
        if (content_type == TLS_CONTENT_ALERT) {
            LOG("tls: ALERT level=%u desc=%u",
                    recv_buf[0], recv_buf[1]);
            return NULL;
        }
        if (content_type != TLS_CONTENT_HANDSHAKE) {
            LOG("tls: unexpected type 0x%02X", content_type);
            return NULL;
        }
        if (process_handshake_messages(recv_buf, recv_len,
                                       &sh, &ske, &rsa_key,
                                       &ske_raw, &ske_raw_len,
                                       &got_done) < 0) {
            return NULL;
        }
    }

    // Verify signature on ServerKeyExchange
    LOG("[tls] verifying ServerKeyExchange signature...");
    if (verify_ske_signature(client_random, sh.server_random,
                             &ske, &rsa_key, ske_raw, ske_raw_len) < 0) {
        LOG("tls: signature verification FAILED");
        return NULL;
    }
    LOG("[tls] signature OK");

    // ECDH key exchange
    uint8_t our_privkey[32];
    p256_point_t our_pubkey;
    if (p256_gen_keypair(our_privkey, &our_pubkey) < 0) {
        LOG("tls: keygen failed");
        return NULL;
    }

    // Compute shared secret
    p256_point_t server_pubkey;
    if (p256_point_from_bytes(&server_pubkey, ske.pubkey, ske.pubkey_len) < 0) {
        LOG("tls: bad server pubkey");
        return NULL;
    }

    uint8_t premaster_secret[32];
    p256_shared_secret(premaster_secret, our_privkey, &server_pubkey);
    LOG("[tls] ECDH shared secret computed");

    // Send ClientKeyExchange (our public key)
    size_t cke_pos = 0;
    buf[cke_pos++] = 0x10;  // handshake type: ClientKeyExchange
    // Length placeholder (3 bytes)
    size_t cke_len_pos = cke_pos;
    cke_pos += 3;
    // Public key length (1 byte) + public key (65 bytes)
    buf[cke_pos++] = 65;
    p256_point_to_bytes(&our_pubkey, buf + cke_pos);
    cke_pos += 65;
    // Fill length
    size_t cke_body_len = cke_pos - cke_len_pos - 3;
    buf[cke_len_pos]   = (cke_body_len >> 16) & 0xFF;
    buf[cke_len_pos+1] = (cke_body_len >> 8) & 0xFF;
    buf[cke_len_pos+2] = cke_body_len & 0xFF;

    LOG("[tls] -> ClientKeyExchange (%zu bytes)", cke_pos);
    if (tls_record_send(sockfd, TLS_CONTENT_HANDSHAKE,
                        TLS_VERSION_1_2, buf, cke_pos) < 0) {
        LOG("tls: failed to send ClientKeyExchange");
        return NULL;
    }

    // derive keys, send ChangeCipherSpec + Finished
    LOG("[tls] TODO: key derivation + Finished");
    return NULL;
}

int tls_send(tls_state_t *tls, const void *data, size_t len)
{
    (void)tls; (void)data; (void)len;
    return -1;
}

int tls_recv(tls_state_t *tls, void *buf, size_t buf_len)
{
    (void)tls; (void)buf; (void)buf_len;
    return -1;
}

void tls_free(tls_state_t *tls)
{
    free(tls);
}
