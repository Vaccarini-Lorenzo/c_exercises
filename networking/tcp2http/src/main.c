#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "tcp.h"
#include "tls.h"
#include "http.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: tcp2http <hostname>\n");
        return 1;
    }

    const char *url = argv[1];
    const char *hostname;
    const char *port = "443";

    // Split URL by "/" to extract hostname
    char *slash = strchr(url, '/');
    if (slash != NULL) {
        hostname = strndup(url, slash - url);
    } else {
        hostname = url;
    }

    // DNS resolution
    char ip[64];
    if (dns_resolve(hostname, ip, sizeof(ip)) != 0) {
        fprintf(stderr, "dns: failed to resolve %s\n", hostname);
        return 1;
    }
    printf("[dns] %s -> %s\n", hostname, ip);

    return 0;
}
