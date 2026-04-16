#include "server.h"
#include "net_common.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <time.h>
#endif

#define MAX_CLIENTS 16
#define HEARTBEAT_TIMEOUT_MS 60000

typedef struct {
    int active;
    char client_id[33];
    net_addr_t udp_addr;
    uint64_t last_heartbeat_ms;
} client_entry_t;

static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static client_entry_t *find_client(client_entry_t *clients, const net_addr_t *addr)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            struct sockaddr_in *a = (struct sockaddr_in *)&clients[i].udp_addr.ss;
            struct sockaddr_in *b = (struct sockaddr_in *)&addr->ss;
            if (a->sin_family == AF_INET && b->sin_family == AF_INET &&
                a->sin_addr.s_addr == b->sin_addr.s_addr &&
                a->sin_port == b->sin_port) {
                return &clients[i];
            }
        }
    }
    return NULL;
}

static client_entry_t *alloc_client(client_entry_t *clients)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            memset(&clients[i], 0, sizeof(clients[i]));
            clients[i].active = 1;
            return &clients[i];
        }
    }
    return NULL;
}

static int send_msg(socket_t fd, const net_addr_t *dest, const crypto_keys_t *keys,
                    const msg_t *msg)
{
    uint8_t plaintext[512];
    size_t plaintext_len;
    if (protocol_encode(msg, plaintext, sizeof(plaintext), &plaintext_len) != 0) return -1;

    uint8_t packet[1024];
    size_t packet_len;
    if (protocol_pack(keys->enc_key, plaintext, plaintext_len, packet, sizeof(packet), &packet_len) != 0) return -1;

    int n = sendto(fd, (const char *)packet, (int)packet_len, 0,
                   (const struct sockaddr *)&dest->ss, dest->len);
    return (n == (int)packet_len) ? 0 : -1;
}

int server_run(const app_config_t *cfg, const crypto_keys_t *keys)
{
    socket_t fd = net_udp_socket(cfg->bind_addr, cfg->bind_port);
    if (fd == NET_INVALID_SOCKET) {
        fprintf(stderr, "[server] failed to bind UDP socket\n");
        return 1;
    }
    if (net_set_nonblocking(fd) != 0) {
        fprintf(stderr, "[server] failed to set nonblocking\n");
        closesocket(fd);
        return 1;
    }

    client_entry_t clients[MAX_CLIENTS];
    memset(clients, 0, sizeof(clients));

    fprintf(stderr, "[server] listening on UDP %s:%u\n", cfg->bind_addr, cfg->bind_port);

    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    uint64_t last_cleanup = get_time_ms();

    while (1) {
        int rc = net_poll(fds, 1, 1000);
        if (rc < 0) {
            fprintf(stderr, "[server] poll error\n");
            break;
        }

        uint64_t now = get_time_ms();

        if (fds[0].revents & POLLIN) {
            uint8_t packet[1500];
            net_addr_t from;
            memset(&from, 0, sizeof(from));
            from.len = sizeof(from.ss);
            int n = recvfrom(fd, (char *)packet, sizeof(packet), 0,
                             (struct sockaddr *)&from.ss, &from.len);
            if (n > 0) {
                uint8_t plaintext[1500];
                size_t plaintext_len;
                if (protocol_unpack(keys->enc_key, packet, (size_t)n, plaintext, sizeof(plaintext), &plaintext_len) != 0) {
                    continue; /* decrypt failed, drop */
                }
                msg_t msg;
                if (protocol_decode(plaintext, plaintext_len, &msg) != 0) {
                    continue;
                }

                if (msg.type == MSG_REGISTER) {
                    if (msg.payload_len >= 64) {
                        /* Check auth token */
                        if (memcmp(msg.payload, keys->auth_token, 32) == 0) {
                            client_entry_t *c = find_client(clients, &from);
                            if (!c) c = alloc_client(clients);
                            if (c) {
                                c->udp_addr = from;
                                c->last_heartbeat_ms = now;
                                memset(c->client_id, 0, sizeof(c->client_id));
                                size_t id_len = msg.payload_len - 64;
                                if (id_len > 32) id_len = 32;
                                memcpy(c->client_id, msg.payload + 32, id_len);
                                fprintf(stderr, "[server] client registered: %s\n", c->client_id);

                                msg_t ack;
                                ack.type = MSG_REGISTER_ACK;
                                ack.session_id = 0;
                                ack.seq = 0;
                                ack.payload = NULL;
                                ack.payload_len = 0;
                                send_msg(fd, &from, keys, &ack);
                            }
                        }
                    }
                } else if (msg.type == MSG_HEARTBEAT) {
                    client_entry_t *c = find_client(clients, &from);
                    if (c) {
                        c->last_heartbeat_ms = now;
                        fprintf(stderr, "[server] heartbeat from %s\n", c->client_id);
                    }
                }
            }
        }

        if (now - last_cleanup >= 5000) {
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active && (now - clients[i].last_heartbeat_ms) > HEARTBEAT_TIMEOUT_MS) {
                    fprintf(stderr, "[server] client timeout: %s\n", clients[i].client_id);
                    clients[i].active = 0;
                }
            }
            last_cleanup = now;
        }
    }

    closesocket(fd);
    return 0;
}
