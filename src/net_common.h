#ifndef NET_COMMON_H
#define NET_COMMON_H

#include <stdint.h>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
    typedef SOCKET socket_t;
    #define NET_INVALID_SOCKET INVALID_SOCKET
    #define NET_SOCKET_ERROR   SOCKET_ERROR
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <poll.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int socket_t;
    #define NET_INVALID_SOCKET -1
    #define NET_SOCKET_ERROR   -1
    #define closesocket close
#endif

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
} net_addr_t;

int net_init(void);
void net_cleanup(void);
socket_t net_udp_socket(const char *bind_addr, uint16_t port);
socket_t net_tcp_listen(const char *bind_addr, uint16_t port);
socket_t net_tcp_connect(const char *addr, uint16_t port);
void net_tcp_tune(socket_t fd);
int net_set_nonblocking(socket_t fd);
int net_poll(struct pollfd *fds, int nfds, int timeout_ms);
int net_addr_parse(const char *addr, uint16_t port, net_addr_t *out);
const char *net_addr_str(const net_addr_t *addr, char *buf, size_t buflen);
int net_error(void);
int net_would_block(int err);

#endif
