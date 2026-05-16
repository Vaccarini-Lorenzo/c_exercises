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

    const char *hostname = argv[1];
    const char *port = "443";

    /* Step 1: DNS resolution */
    char ip[64];
    if (dns_resolve(hostname, ip, sizeof(ip)) != 0) {
        fprintf(stderr, "dns: failed to resolve %s\n", hostname);
        return 1;
    }
    printf("[dns] %s -> %s\n", hostname, ip);

    /* Step 2: TCP connection */
    int sockfd = tcp_connect(ip, port);
    if (sockfd < 0) {
        fprintf(stderr, "tcp: connection failed\n");
        return 1;
    }
    printf("[tcp] connected to %s:%s\n", ip, port);

    /* Step 3: TLS handshake */
    tls_state_t *tls = tls_handshake(sockfd, hostname);
    if (!tls) {
        fprintf(stderr, "tls: handshake failed\n");
        tcp_close(sockfd);
        return 1;
    }
    printf("[tls] handshake complete\n");

    /* Step 4: HTTP request over TLS */
    http_get(tls, hostname, "/");

    /* Cleanup */
    tls_free(tls);
    tcp_close(sockfd);

    return 0;
}
