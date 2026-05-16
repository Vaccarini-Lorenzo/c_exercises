#ifndef TLS_H
#define TLS_H

#include <stddef.h>

/*
 * Opaque TLS connection state.
 * We implement TLS 1.2/1.3 record protocol by hand.
 */
typedef struct tls_state tls_state_t;

/*
 * Perform TLS handshake over an established TCP socket.
 * Returns TLS state on success, NULL on failure.
 */
tls_state_t *tls_handshake(int sockfd, const char *hostname);

/*
 * Send application data over TLS.
 */
int tls_send(tls_state_t *tls, const void *data, size_t len);

/*
 * Receive application data over TLS.
 * Returns bytes read, 0 on close, -1 on error.
 */
int tls_recv(tls_state_t *tls, void *buf, size_t buf_len);

/*
 * Free TLS state.
 */
void tls_free(tls_state_t *tls);

#endif
