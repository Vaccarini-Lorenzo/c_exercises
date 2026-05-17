#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "tcp.h"
#include "tls.h"
#include "http.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: tcp2http <hostname>\n");
        return 1;
    }

    const char *url = argv[1];
    const char *hostname;
    const char *port = "443";

    // Split URL by "/" to extract hostname
    char *slash = strchr(url, '/');
    if (slash != NULL) {
        hostname = strndup(url, slash - url);
    } else {
        hostname = url;
    }

    // DNS resolution
    char ip[64];
    if (dns_resolve(hostname, ip, sizeof(ip)) != 0) {
        fprintf(stderr, "dns: failed to resolve %s\n", hostname);
        return 1;
    }
    printf("[dns] %s -> %s\n", hostname, ip);

    // TCP connection
    int sockfd = tcp_connect(ip, port);
    if (sockfd < 0) {
        fprintf(stderr, "tcp: connection failed\n");
        return 1;
    }
    printf("[tcp] connected to %s:%s (fd=%d)\n", ip, port, sockfd);

    /*
    TLS handshake
    ```
    Client                                          Server
        |                                               |
        |--- ClientHello (random, ciphers, SNI) ------->|
        |                                               |
        |<-- ServerHello (chosen cipher, random) -------|
        |<-- Certificate (X.509 chain) -----------------|
        |<-- ServerKeyExchange (ECDH pubkey, signed) ---|
        |<-- ServerHelloDone ---------------------------|
        |                                               |
        |--- ClientKeyExchange (our ECDH pubkey) ------>|
        |--- ChangeCipherSpec ------------------------->|
        |--- Finished (encrypted verify) -------------->|
        |                                               |
        |<-- ChangeCipherSpec --------------------------|
        |<-- Finished (encrypted verify) ---------------|
        |                                               |
        |===== Application data (HTTP) encrypted =======|
    ```
    */
    tls_state_t *tls = tls_handshake(sockfd, hostname);
    if (!tls) {
        fprintf(stderr, "tls: handshake failed\n");
        tcp_close(sockfd);
        return 1;
    }

    tls_free(tls);
    tcp_close(sockfd);
    return 0;
}
