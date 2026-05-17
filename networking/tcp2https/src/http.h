#ifndef HTTP_H
#define HTTP_H

#include "tls.h"

// Send an HTTP GET request over TLS and print the response.
int http_get(tls_state_t *tls, const char *hostname, const char *path);

#endif
