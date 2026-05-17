#include "tls.h"
#include "tls_record.h"
#include "tls_hello.h"
#include "tls_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_state {
    int sockfd;
    uint8_t client_random[32];
    uint8_t server_random[32];
};

// Walk a buffer of concatenated handshake messages.
// Calls the appropriate parser for each one.
// Returns 0 on success, -1 on failure.
static int process_handshake_messages(const uint8_t *data, size_t data_len,
                                      server_hello_t *sh,
                                      server_key_exchange_t *ske,
                                      int *got_done)
{
    size_t pos = 0;

    while (pos < data_len) {
        if (pos + 4 > data_len) {
            fprintf(stderr, "tls: truncated handshake header\n");
            return -1;
        }

        uint8_t msg_type = data[pos];
        uint32_t msg_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        if (pos + msg_len > data_len) {
            fprintf(stderr, "tls: truncated handshake body (type=0x%02X)\n", msg_type);
            return -1;
        }

        const uint8_t *body = data + pos;

        switch (msg_type) {
        case TLS_HS_SERVER_HELLO:
            printf("[tls] <- ServerHello (%u bytes)\n", msg_len);
            if (tls_parse_server_hello(body, msg_len, sh) < 0) return -1;
            printf("[tls]    version=0x%04X cipher=0x%04X\n",
                   sh->version, sh->cipher_suite);
            break;

        case TLS_HS_CERTIFICATE:
            printf("[tls] <- Certificate (%u bytes)\n", msg_len);
            // TODO: parse certificate chain
            break;

        case TLS_HS_SERVER_KEY_EXCH:
            printf("[tls] <- ServerKeyExchange (%u bytes)\n", msg_len);
            if (tls_parse_server_key_exchange(body, msg_len, ske) < 0) return -1;
            printf("[tls]    curve=0x%04X pubkey_len=%u sig_len=%zu\n",
                   ske->named_curve, ske->pubkey_len, ske->signature_len);
            break;

        case TLS_HS_SERVER_HELLO_DONE:
            printf("[tls] <- ServerHelloDone\n");
            *got_done = 1;
            break;

        default:
            printf("[tls] <- Unknown handshake type 0x%02X (%u bytes)\n",
                   msg_type, msg_len);
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

    printf("[tls] sending ClientHello (%zu bytes)\n", hello_len);

    if (tls_record_send(sockfd, TLS_CONTENT_HANDSHAKE,
                        TLS_VERSION_1_0, buf, hello_len) < 0) {
        fprintf(stderr, "tls: failed to send ClientHello\n");
        return NULL;
    }

    // Read server handshake messages (may span multiple records)
    server_hello_t sh;
    server_key_exchange_t ske;
    int got_done = 0;

    while (!got_done) {
        uint8_t recv_buf[TLS_MAX_RECORD_PAYLOAD];
        uint8_t content_type;
        size_t recv_len;

        if (tls_record_recv(sockfd, &content_type, recv_buf, &recv_len) < 0) {
            fprintf(stderr, "tls: failed to read server record\n");
            return NULL;
        }

        if (content_type == TLS_CONTENT_ALERT) {
            fprintf(stderr, "tls: ALERT level=%u desc=%u\n",
                    recv_buf[0], recv_buf[1]);
            return NULL;
        }

        if (content_type != TLS_CONTENT_HANDSHAKE) {
            fprintf(stderr, "tls: unexpected content type 0x%02X\n", content_type);
            return NULL;
        }

        if (process_handshake_messages(recv_buf, recv_len,
                                       &sh, &ske, &got_done) < 0) {
            return NULL;
        }
    }

    // Verify server chose what we offered
    if (sh.cipher_suite != 0xC02F) {
        fprintf(stderr, "tls: server chose unexpected cipher 0x%04X\n",
                sh.cipher_suite);
        return NULL;
    }

    printf("[tls] handshake messages received successfully\n");

    // TODO: verify certificate, compute shared secret, send ClientKeyExchange, etc.
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
