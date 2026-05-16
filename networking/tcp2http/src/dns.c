#include "dns.h"

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len)
{
    /* TODO: resolve hostname using getaddrinfo */
    (void)hostname;
    (void)ip_out;
    (void)ip_out_len;
    return -1;
}
