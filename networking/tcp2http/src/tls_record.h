#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

// TLS content types
#define TLS_CONTENT_HANDSHAKE       0x16
#define TLS_CONTENT_CHANGE_CIPHER   0x14
#define TLS_CONTENT_ALERT           0x15
#define TLS_CONTENT_APPLICATION     0x17

// TLS versions
#define TLS_VERSION_1_0  0x0301
#define TLS_VERSION_1_2  0x0303

// Max TLS record payload: 16KB
#define TLS_MAX_RECORD_PAYLOAD  16384

// Send a TLS record: 5-byte header + payload.
// Returns 0 on success, -1 on failure.
int tls_record_send(int fd, uint8_t content_type, uint16_t version,
                    const uint8_t *payload, size_t payload_len);

// Receive a TLS record. Fills content_type, payload, and payload_len.
// Caller provides buffer. Returns 0 on success, -1 on failure.
int tls_record_recv(int fd, uint8_t *content_type,
                    uint8_t *payload, size_t *payload_len);

#endif
