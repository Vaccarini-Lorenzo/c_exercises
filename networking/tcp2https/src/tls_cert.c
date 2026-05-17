#include "tls_cert.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

// Minimal ASN.1 DER parser — just enough for X.509 RSA public key extraction

// ASN.1 tag types
#define ASN1_SEQUENCE    0x30
#define ASN1_INTEGER     0x02
#define ASN1_BITSTRING   0x03
#define ASN1_OID         0x06

// Read ASN.1 length. Returns bytes consumed, fills *out_len.
static int asn1_read_length(const uint8_t *buf, size_t avail, size_t *out_len)
{
    if (avail < 1) return -1;

    if (buf[0] < 0x80) {
        *out_len = buf[0];
        return 1;
    }

    int num_bytes = buf[0] & 0x7F;
    if (num_bytes > 4 || (size_t)(num_bytes + 1) > avail) return -1;

    *out_len = 0;
    for (int i = 0; i < num_bytes; i++) {
        *out_len = (*out_len << 8) | buf[1 + i];
    }
    return 1 + num_bytes;
}

// Skip an ASN.1 TLV. Returns total bytes consumed (tag + length + value).
static int asn1_skip(const uint8_t *buf, size_t avail)
{
    if (avail < 2) return -1;
    size_t len;
    int hdr = 1 + asn1_read_length(buf + 1, avail - 1, &len);
    if (hdr < 0) return -1;
    return hdr + (int)len;
}

// Find SubjectPublicKeyInfo inside a DER-encoded certificate.
// X.509 structure (simplified):
//   SEQUENCE (Certificate)
//     SEQUENCE (TBSCertificate)
//       [0] version
//       INTEGER serialNumber
//       SEQUENCE signature algorithm
//       SEQUENCE issuer
//       SEQUENCE validity
//       SEQUENCE subject
//       SEQUENCE subjectPublicKeyInfo  <-- we want this
//         SEQUENCE algorithm
//         BIT STRING public key
static int find_spki(const uint8_t *cert, size_t cert_len,
                     const uint8_t **spki_out, size_t *spki_len_out)
{
    const uint8_t *p = cert;
    size_t remaining = cert_len;

    // Outer SEQUENCE (Certificate)
    if (*p != ASN1_SEQUENCE) return -1;
    size_t outer_len;
    int hdr = 1 + asn1_read_length(p + 1, remaining - 1, &outer_len);
    p += hdr;
    remaining = outer_len;

    // TBSCertificate SEQUENCE
    if (*p != ASN1_SEQUENCE) return -1;
    size_t tbs_len;
    hdr = 1 + asn1_read_length(p + 1, remaining - 1, &tbs_len);
    p += hdr;
    remaining = tbs_len;

    // [0] version (context tag 0xA0) — skip if present
    if (*p == 0xA0) {
        int skip = asn1_skip(p, remaining);
        if (skip < 0) return -1;
        p += skip; remaining -= skip;
    }

    // serialNumber — skip
    int skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // signature algorithm — skip
    skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // issuer — skip
    skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // validity — skip
    skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // subject — skip
    skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // subjectPublicKeyInfo — this is what we want
    if (*p != ASN1_SEQUENCE) return -1;
    size_t spki_total_len;
    int spki_hdr = 1 + asn1_read_length(p + 1, remaining - 1, &spki_total_len);
    *spki_out = p + spki_hdr;
    *spki_len_out = spki_total_len;
    return 0;
}

// Extract RSA modulus and exponent from SubjectPublicKeyInfo
static int parse_rsa_from_spki(const uint8_t *spki, size_t spki_len,
                               rsa_pubkey_t *key)
{
    const uint8_t *p = spki;
    size_t remaining = spki_len;

    // SEQUENCE (algorithm identifier) — skip
    int skip = asn1_skip(p, remaining);
    if (skip < 0) return -1;
    p += skip; remaining -= skip;

    // BIT STRING containing the RSA public key
    if (*p != ASN1_BITSTRING) return -1;
    size_t bs_len;
    int hdr = 1 + asn1_read_length(p + 1, remaining - 1, &bs_len);
    p += hdr;
    // First byte of BIT STRING is "unused bits" count (should be 0)
    p += 1; bs_len -= 1;

    // Now p points to a SEQUENCE containing INTEGER modulus + INTEGER exponent
    if (*p != ASN1_SEQUENCE) return -1;
    size_t seq_len;
    hdr = 1 + asn1_read_length(p + 1, bs_len - 1, &seq_len);
    p += hdr;

    // INTEGER modulus
    if (*p != ASN1_INTEGER) return -1;
    size_t mod_len;
    hdr = 1 + asn1_read_length(p + 1, seq_len, &mod_len);
    p += hdr;
    // Skip leading zero byte if present (ASN.1 sign padding)
    if (mod_len > 0 && *p == 0x00) { p++; mod_len--; }
    if (mod_len > sizeof(key->modulus)) return -1;
    memcpy(key->modulus, p, mod_len);
    key->modulus_len = mod_len;
    p += mod_len;

    // INTEGER exponent
    if (*p != ASN1_INTEGER) return -1;
    size_t exp_len;
    hdr = 1 + asn1_read_length(p + 1, 16, &exp_len);
    p += hdr;
    if (exp_len > sizeof(key->exponent)) return -1;
    memcpy(key->exponent, p, exp_len);
    key->exponent_len = exp_len;

    return 0;
}

int tls_cert_extract_rsa_pubkey(const uint8_t *data, size_t len,
                                rsa_pubkey_t *key_out)
{
    // TLS Certificate message format:
    //   certificates_length (3 bytes)
    //   first cert:
    //     cert_length (3 bytes)
    //     cert_data (DER-encoded X.509)
    //   more certs...

    if (len < 3) return -1;
    size_t pos = 0;

    // Total certs length
    pos += 3;  // skip, we just parse the first cert

    if (pos + 3 > len) return -1;
    size_t cert_len = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2];
    pos += 3;

    if (pos + cert_len > len) return -1;
    const uint8_t *cert = data + pos;

    // Find SubjectPublicKeyInfo in the certificate
    const uint8_t *spki;
    size_t spki_len;
    if (find_spki(cert, cert_len, &spki, &spki_len) < 0) {
        LOG("tls_cert: failed to find SPKI");
        return -1;
    }

    // Extract RSA key from SPKI
    if (parse_rsa_from_spki(spki, spki_len, key_out) < 0) {
        LOG("tls_cert: failed to parse RSA key");
        return -1;
    }

    LOG("[tls]    RSA key: modulus=%zu bytes, exponent=%zu bytes",
           key_out->modulus_len, key_out->exponent_len);
    return 0;
}
