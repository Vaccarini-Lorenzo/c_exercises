#ifndef TLS_HELLO_H
#define TLS_HELLO_H

#include <stddef.h>
#include <stdint.h>

// Build a ClientHello message (handshake payload, without record header).
// Writes into buf, returns number of bytes written.
// client_random_out: filled with the 32-byte random we generated.
size_t tls_build_client_hello(uint8_t *buf, size_t buf_len,
                              const char *hostname,
                              uint8_t *client_random_out);

#endif
