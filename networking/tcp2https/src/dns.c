#include "dns.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len)
{
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    // IPv4
    hints.ai_family = AF_INET;      
    // TPC
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(hostname, NULL, &hints, &result);
    if (err != 0) {
        LOG("dns: getaddrinfo: %s", gai_strerror(err));
        return -1;
    }

    // Result is a linked list

    // Note: `getaddrinfo` may return multiple addresses for the same hostname.
    // For example, google.com returns 6 IPs.
    // An AppService instance usually returns only one IP (the loadbalancer IP).
    
    // Why google has multiple IPs? 
    // They must push redundancy to the client itself: The browser itself handles one IP failure by retrying the request with another IP.
    // This is a common practice for large-scale services to ensure high availability and reliability.
    // By providing multiple IP addresses, they can distribute the load and mitigate the impact of any single point of failure.
    
    struct addrinfo *curr = result;
    int i = 0;
    char buf[64];
    while (curr) {
        struct sockaddr_in *a = (struct sockaddr_in *)curr->ai_addr;
        inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf));
        LOG("[dns] IP_%d: %s", i, buf);
        LOG("[dns] port: %d", ntohs(a->sin_port));
        curr = curr->ai_next;
        i++;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;

    // Convert binary IP to string
    // Note:
    // `freeaddrinfo` frees the linked list allocated by getaddrinfo
    // different from `free()` traverse the whole linked list and free each node
    if (!inet_ntop(AF_INET, &addr->sin_addr, ip_out, ip_out_len)) {
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}
