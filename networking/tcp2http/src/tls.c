#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tls_state {
    int sockfd;
    /* TODO: session keys, sequence numbers, etc. */
};

tls_state_t *tls_handshake(int sockfd, const char *hostname)
{
    /*
     * TODO: Full TLS 1.2 handshake:
     *  1. ClientHello (supported ciphers, random, SNI extension)
     *  2. Read ServerHello (chosen cipher, random)
     *  3. Read Certificate (parse X.509, verify chain)
     *  4. Read ServerKeyExchange (if DHE/ECDHE)
     *  5. Read ServerHelloDone
     *  6. Send ClientKeyExchange (premaster secret / ECDH public)
     *  7. Send ChangeCipherSpec
     *  8. Send Finished (verify data)
     *  9. Read ChangeCipherSpec + Finished
     */
    (void)sockfd;
    (void)hostname;
    return NULL;
}

int tls_send(tls_state_t *tls, const void *data, size_t len)
{
    /* TODO: wrap in TLS record, encrypt, send */
    (void)tls;
    (void)data;
    (void)len;
    return -1;
}

int tls_recv(tls_state_t *tls, void *buf, size_t buf_len)
{
    /* TODO: read TLS record, decrypt, return plaintext */
    (void)tls;
    (void)buf;
    (void)buf_len;
    return -1;
}

void tls_free(tls_state_t *tls)
{
    free(tls);
}
