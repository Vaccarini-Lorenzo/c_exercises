# tcp2http

HTTPS request from scratch in C.
No libraries except stdlib and POSIX sockets.

Walks through every layer manually:
1. **DNS** — resolve hostname via `getaddrinfo`
2. **TCP** — raw socket connect to port 443
3. **TLS** — handshake, certificate verification, record encryption/decryption
4. **HTTP** — format and send a GET request, read the response

Target server is hosted on Azure.

## Build & Run

```
make
./build/tcp2http <hostname>
```
