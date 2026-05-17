#include "tcp.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int tcp_connect(const char *ip, const char *port)
{
    // Create socket
    // Here we are just creating the kernel structure for the socket.
    // AF_INET  = IPv4
    // SOCK_STREAM = TCP 
    // 0 = let kernel pick protocol (TCP for SOCK_STREAM)
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG("tcp: socket creation failed");
        return -1;
    }

    // Fill destination address struct
    // We could have specified the port in `getaddrinfo` and then used the returned `addrinfo` struct directly here.
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(port));

    // Convert IP string to binary form
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LOG("tcp: invalid ip %s", ip);
        close(fd);
        return -1;
    }

    // 3-way handshake:
    // Thread blocks here until SYN-ACK received and ACK sent
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("tcp: connect failed");
        close(fd);
        return -1;
    }

    return fd;
}

void tcp_close(int sockfd)
{
    close(sockfd);
}
