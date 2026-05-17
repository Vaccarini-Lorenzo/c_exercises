#include "tls.h"
#include "tls_record.h"
#include "tls_hello.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_state {
    int sockfd;
    uint8_t client_random[32];
    uint8_t server_random[32];
};

tls_state_t *tls_handshake(int sockfd, const char *hostname)
{
    uint8_t buf[4096];
    uint8_t client_random[32];

    // Build and send ClientHello 
    size_t hello_len = tls_build_client_hello(buf, sizeof(buf),
                                              hostname, client_random);

    printf("[tls] sending ClientHello (%zu bytes)\n", hello_len);
    /*
    ┌─────────────────────── TLS Record Layer ───────────────────────┐
    │ type(1) │ version(2) │ record_length(2) │       payload        │
    │  0x16   │   0x0301   │      N bytes     │                      │
    │         │            │                  │ ┌─ Handshake Msg ──┐ │
    │         │            │                  │ │ type(1) │ len(3) │ │
    │         │            │                  │ │  0x01   │  ...   │ │
    │         │            │                  │ │   ClientHello... │ │
    │         │            │                  │ └──────────────────┘ │
    └────────────────────────────────────────────────────────────────┘
    */
    if (tls_record_send(sockfd, TLS_CONTENT_HANDSHAKE,
                        TLS_VERSION_1_0, buf, hello_len) < 0) {
        fprintf(stderr, "tls: failed to send ClientHello\n");
        return NULL;
    }

    // Read server response
    uint8_t recv_buf[TLS_MAX_RECORD_PAYLOAD];
    uint8_t content_type;
    size_t recv_len;

    if (tls_record_recv(sockfd, &content_type, recv_buf, &recv_len) < 0) {
        fprintf(stderr, "tls: failed to read server response\n");
        return NULL;
    }

    printf("[tls] received record: type=0x%02X, len=%zu\n",
           content_type, recv_len);

    if (content_type == TLS_CONTENT_ALERT) {
        printf("[tls] ALERT: level=%u, desc=%u\n", recv_buf[0], recv_buf[1]);
        return NULL;
    }

    // For now, just print first bytes of response to see what we got
    printf("[tls] first bytes: ");
    for (size_t i = 0; i < (recv_len < 16 ? recv_len : 16); i++)
        printf("%02X ", recv_buf[i]);
    printf("\n");

    // TODO: parse ServerHello, Certificate, etc.
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
