#include "tls_record.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

// Send exactly n bytes (loop around partial writes)
static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

// Read exactly n bytes (loop around partial reads)
static int recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

int tls_record_send(int fd, uint8_t content_type, uint16_t version,
                    const uint8_t *payload, size_t payload_len)
{
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes
    uint8_t header[5];
    header[0] = content_type;
    header[1] = (version >> 8) & 0xFF;
    header[2] = version & 0xFF;
    header[3] = (payload_len >> 8) & 0xFF;
    header[4] = payload_len & 0xFF;

    if (send_all(fd, header, 5) < 0) return -1;
    if (send_all(fd, payload, payload_len) < 0) return -1;
    return 0;
}

int tls_record_recv(int fd, uint8_t *content_type,
                    uint8_t *payload, size_t *payload_len)
{
    // Read 5-byte header
    uint8_t header[5];
    if (recv_all(fd, header, 5) < 0) return -1;

    *content_type = header[0];
    uint16_t len = (header[3] << 8) | header[4];

    if (len > TLS_MAX_RECORD_PAYLOAD) {
        fprintf(stderr, "tls_record: payload too large: %u\n", len);
        return -1;
    }

    // Read payload
    if (recv_all(fd, payload, len) < 0) return -1;
    *payload_len = len;
    return 0;
}
