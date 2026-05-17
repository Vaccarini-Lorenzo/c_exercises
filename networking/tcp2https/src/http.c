#include "http.h"

#include <stdio.h>
#include <string.h>

int http_get(tls_state_t *tls, const char *hostname, const char *path)
{
    // TODO:
    //  1. Format HTTP/1.1 GET request with Host header
    //  2. tls_send the request
    //  3. tls_recv the response in a loop
    //  4. Print status line, headers, body
    (void)tls;
    (void)hostname;
    (void)path;
    return -1;
}
