#ifndef DNS_H
#define DNS_H

#include <stddef.h>

// Resolve hostname to an IPv4 address string.
// Returns 0 on success, -1 on failure.
// Uses getaddrinfo (allowed - part of POSIX sockets API).
int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len);

#endif
