#ifndef TCP_H
#define TCP_H

// Establish a TCP connection to ip:port.
// Returns socket fd on success, -1 on failure.
int tcp_connect(const char *ip, const char *port);

// Close a TCP socket.
void tcp_close(int sockfd);

#endif
