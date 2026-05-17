#include "tls_hello.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Generate 32 random bytes from /dev/urandom
static int fill_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

// Append bytes to buffer, advance cursor
static void put_bytes(uint8_t *buf, size_t *pos, const void *data, size_t len)
{
    memcpy(buf + *pos, data, len);
    *pos += len;
}

static void put_u8(uint8_t *buf, size_t *pos, uint8_t val)
{
    buf[*pos] = val;
    *pos += 1;
}

static void put_u16(uint8_t *buf, size_t *pos, uint16_t val)
{
    buf[*pos] = (val >> 8) & 0xFF;
    buf[(*pos) + 1] = val & 0xFF;
    *pos += 2;
}

// Build SNI extension
static size_t build_ext_sni(uint8_t *buf, const char *hostname)
{
    size_t pos = 0;
    size_t name_len = strlen(hostname);

    put_u16(buf, &pos, 0x0000);  // Extension type: SNI
    put_u16(buf, &pos, name_len + 5);  // Extension data length
    put_u16(buf, &pos, name_len + 3);  // SNI list length
    put_u8(buf, &pos, 0x00);     // Host name type: DNS
    put_u16(buf, &pos, name_len);  // Host name length
    put_bytes(buf, &pos, hostname, name_len);  // Host name

    return pos;
}

// Build Supported Groups extension (we support P-256 = 0x0017)
static size_t build_ext_supported_groups(uint8_t *buf)
{
    size_t pos = 0;

    put_u16(buf, &pos, 0x000A);  // Extension type: supported_groups
    put_u16(buf, &pos, 4);       // Extension data length
    put_u16(buf, &pos, 2);       // Named curve list length
    put_u16(buf, &pos, 0x0017);  // secp256r1 (P-256)

    return pos;
}

// Build EC Point Formats extension (uncompressed = 0x00)
static size_t build_ext_ec_point_formats(uint8_t *buf)
{
    size_t pos = 0;

    put_u16(buf, &pos, 0x000B);  // Extension type: ec_point_formats
    put_u16(buf, &pos, 2);       // Extension data length
    put_u8(buf, &pos, 1);        // Format list length
    put_u8(buf, &pos, 0x00);     // Uncompressed

    return pos;
}

// Build Signature Algorithms extension
static size_t build_ext_signature_algorithms(uint8_t *buf)
{
    size_t pos = 0;

    put_u16(buf, &pos, 0x000D);  // Extension type: signature_algorithms
    put_u16(buf, &pos, 4);       // Extension data length
    put_u16(buf, &pos, 2);       // Algorithm list length
    put_u16(buf, &pos, 0x0401);  // RSA PKCS1 SHA-256

    return pos;
}

size_t tls_build_client_hello(uint8_t *buf, size_t buf_len,
                              const char *hostname,
                              uint8_t *client_random_out)
{
    (void)buf_len;
    size_t pos = 0;

    // Handshake header (filled at the end)
    size_t handshake_header_pos = pos;
    pos += 4;  // type(1) + length(3), filled later

    // Client version: TLS 1.2
    put_u16(buf, &pos, 0x0303);

    // Client random (32 bytes)
    uint8_t client_random[32];
    fill_random(client_random, 32);
    put_bytes(buf, &pos, client_random, 32);
    memcpy(client_random_out, client_random, 32);

    // Session ID: empty
    put_u8(buf, &pos, 0x00);

    // Cipher suites
    put_u16(buf, &pos, 2);       // Length: 2 bytes (one suite)
    put_u16(buf, &pos, 0xC02F);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    // Compression methods
    put_u8(buf, &pos, 1);    // 1 method
    put_u8(buf, &pos, 0x00); // null compression

    // Extensions
    size_t extensions_length_pos = pos;
    pos += 2;  // filled later

    size_t extensions_start = pos;

    pos += build_ext_sni(buf + pos, hostname);
    pos += build_ext_supported_groups(buf + pos);
    pos += build_ext_ec_point_formats(buf + pos);
    pos += build_ext_signature_algorithms(buf + pos);

    // Fill extensions length
    size_t ext_len = pos - extensions_start;
    buf[extensions_length_pos] = (ext_len >> 8) & 0xFF;
    buf[extensions_length_pos + 1] = ext_len & 0xFF;

    // Fill handshake header
    size_t hello_len = pos - handshake_header_pos - 4;
    buf[handshake_header_pos] = 0x01;  // ClientHello
    buf[handshake_header_pos + 1] = (hello_len >> 16) & 0xFF;
    buf[handshake_header_pos + 2] = (hello_len >> 8) & 0xFF;
    buf[handshake_header_pos + 3] = hello_len & 0xFF;

    return pos;
}
