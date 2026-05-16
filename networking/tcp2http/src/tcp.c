#include "tcp.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int tcp_connect(const char *ip, const char *port)
{
    /* TODO: create socket, fill sockaddr_in, connect */
    (void)ip;
    (void)port;
    return -1;
}

void tcp_close(int sockfd)
{
    close(sockfd);
}
