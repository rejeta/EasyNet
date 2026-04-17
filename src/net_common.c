#include "net_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
    #include <netinet/tcp.h>
#endif

#ifdef _WIN32
static int g_wsa_initialized = 0;
#endif

int net_init(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (!g_wsa_initialized) {
        int rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (rc != 0) return -1;
        g_wsa_initialized = 1;
    }
#endif
    return 0;
}

void net_cleanup(void)
{
#ifdef _WIN32
    if (g_wsa_initialized) {
        WSACleanup();
        g_wsa_initialized = 0;
    }
#endif
}

socket_t net_udp_socket(const char *bind_addr, uint16_t port)
{
    socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == NET_INVALID_SOCKET) return NET_INVALID_SOCKET;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &sin.sin_addr) != 1) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }
    return fd;
}

socket_t net_tcp_listen(const char *bind_addr, uint16_t port)
{
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == NET_INVALID_SOCKET) return NET_INVALID_SOCKET;

    int reuse = 1;
#ifdef _WIN32
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) != 0) {
#else
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse, sizeof(reuse)) != 0) {
#endif
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &sin.sin_addr) != 1) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }

    if (listen(fd, 128) != 0) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }
    return fd;
}

socket_t net_tcp_connect(const char *addr, uint16_t port)
{
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == NET_INVALID_SOCKET) return NET_INVALID_SOCKET;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1) {
        closesocket(fd);
        return NET_INVALID_SOCKET;
    }

    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        int err = net_error();
#ifdef _WIN32
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
#else
        if (err != EWOULDBLOCK && err != EINPROGRESS) {
#endif
            closesocket(fd);
            return NET_INVALID_SOCKET;
        }
    }
    return fd;
}

void net_tcp_tune(socket_t fd)
{
    int nodelay = 1;
    int sndbuf = 262144;
    int rcvbuf = 262144;
#ifdef _WIN32
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
#else
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
#endif
}

int net_set_nonblocking(socket_t fd)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

int net_poll(struct pollfd *fds, int nfds, int timeout_ms)
{
#ifdef _WIN32
    return WSAPoll(fds, nfds, timeout_ms);
#else
    return poll(fds, nfds, timeout_ms);
#endif
}

int net_addr_parse(const char *addr, uint16_t port, net_addr_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    struct sockaddr_in *sin = (struct sockaddr_in *)&out->ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
        return -1;
    }
    out->len = sizeof(*sin);
    return 0;
}

const char *net_addr_str(const net_addr_t *addr, char *buf, size_t buflen)
{
    if (!addr || !buf || buflen == 0) return NULL;
    char ipstr[INET6_ADDRSTRLEN];
    const void *src = NULL;
    uint16_t port = 0;

    if (addr->ss.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr->ss;
        src = &sin->sin_addr;
        port = ntohs(sin->sin_port);
    } else if (addr->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&addr->ss;
        src = &sin6->sin6_addr;
        port = ntohs(sin6->sin6_port);
    } else {
        snprintf(buf, buflen, "unknown");
        return buf;
    }

    if (!inet_ntop(addr->ss.ss_family, src, ipstr, sizeof(ipstr))) {
        snprintf(buf, buflen, "invalid");
        return buf;
    }
    snprintf(buf, buflen, "%s:%u", ipstr, (unsigned int)port);
    return buf;
}

int net_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

int net_would_block(int err)
{
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EWOULDBLOCK;
#endif
}
