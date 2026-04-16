#include "client.h"
#include "net_common.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <time.h>
#endif

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

static int send_register(socket_t fd, const net_addr_t *dest, const crypto_keys_t *keys,
                         const app_config_t *cfg, uint32_t seq)
{
    uint8_t payload[256];
    size_t p = 0;
    memcpy(payload + p, keys->auth_token, 32); p += 32;
    const char *client_id = "easynet-client";
    memset(payload + p, 0, 32);
    memcpy(payload + p, client_id, strlen(client_id)); p += 32;
    payload[p++] = (uint8_t)cfg->tunnel_count;
    for (int i = 0; i < cfg->tunnel_count; i++) {
        payload[p++] = (uint8_t)cfg->tunnels[i].protocol;
        payload[p++] = (uint8_t)(cfg->tunnels[i].local_port >> 8);
        payload[p++] = (uint8_t)(cfg->tunnels[i].local_port & 0xFF);
        payload[p++] = (uint8_t)(cfg->tunnels[i].remote_port >> 8);
        payload[p++] = (uint8_t)(cfg->tunnels[i].remote_port & 0xFF);
    }

    msg_t msg;
    msg.type = MSG_REGISTER;
    msg.session_id = 0;
    msg.seq = seq;
    msg.payload = payload;
    msg.payload_len = p;

    uint8_t plaintext[512];
    size_t plaintext_len;
    if (protocol_encode(&msg, plaintext, sizeof(plaintext), &plaintext_len) != 0) return -1;

    uint8_t packet[1500];
    size_t packet_len;
    if (protocol_pack(keys->enc_key, plaintext, plaintext_len, packet, sizeof(packet), &packet_len) != 0) return -1;

    int n = sendto(fd, (const char *)packet, (int)packet_len, 0,
                   (const struct sockaddr *)&dest->ss, dest->len);
    return (n == (int)packet_len) ? 0 : -1;
}

static int send_heartbeat(socket_t fd, const net_addr_t *dest, const crypto_keys_t *keys, uint32_t seq)
{
    msg_t msg;
    msg.type = MSG_HEARTBEAT;
    msg.session_id = 0;
    msg.seq = seq;
    msg.payload = NULL;
    msg.payload_len = 0;

    uint8_t plaintext[64];
    size_t plaintext_len;
    if (protocol_encode(&msg, plaintext, sizeof(plaintext), &plaintext_len) != 0) return -1;

    uint8_t packet[256];
    size_t packet_len;
    if (protocol_pack(keys->enc_key, plaintext, plaintext_len, packet, sizeof(packet), &packet_len) != 0) return -1;

    int n = sendto(fd, (const char *)packet, (int)packet_len, 0,
                   (const struct sockaddr *)&dest->ss, dest->len);
    return (n == (int)packet_len) ? 0 : -1;
}

int client_run(const app_config_t *cfg, const crypto_keys_t *keys)
{
    socket_t fd = net_udp_socket("0.0.0.0", 0);
    if (fd == NET_INVALID_SOCKET) {
        fprintf(stderr, "[client] failed to create UDP socket\n");
        return 1;
    }
    if (net_set_nonblocking(fd) != 0) {
        fprintf(stderr, "[client] failed to set nonblocking\n");
        closesocket(fd);
        return 1;
    }

    net_addr_t server_addr;
    if (net_addr_parse(cfg->server_addr, cfg->server_port, &server_addr) != 0) {
        fprintf(stderr, "[client] failed to parse server address\n");
        closesocket(fd);
        return 1;
    }

    uint32_t seq = 1;
    int registered = 0;
    uint64_t last_register_sent = 0;
    uint64_t last_heartbeat_sent = 0;

    printf("[client] starting, server=%s:%u\n", cfg->server_addr, cfg->server_port);

    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    while (1) {
        int rc = net_poll(fds, 1, 100);
        if (rc < 0) {
            fprintf(stderr, "[client] poll error\n");
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
                if (protocol_unpack(keys->enc_key, packet, (size_t)n, plaintext, sizeof(plaintext), &plaintext_len) == 0) {
                    msg_t msg;
                    if (protocol_decode(plaintext, plaintext_len, &msg) == 0) {
                        if (msg.type == MSG_REGISTER_ACK) {
                            printf("[client] received REGISTER_ACK\n");
                            registered = 1;
                        } else if (msg.type == MSG_HEARTBEAT) {
                            /* server heartbeat reply or proactive heartbeat */
                        }
                    }
                }
            }
        }

        if (!registered) {
            if (now - last_register_sent >= 3000) {
                if (send_register(fd, &server_addr, keys, cfg, seq++) == 0) {
                    printf("[client] sent REGISTER (seq=%u)\n", seq - 1);
                    last_register_sent = now;
                }
            }
        } else {
            if (now - last_heartbeat_sent >= 15000) {
                if (send_heartbeat(fd, &server_addr, keys, seq++) == 0) {
                    printf("[client] sent HEARTBEAT (seq=%u)\n", seq - 1);
                    last_heartbeat_sent = now;
                }
            }
        }
    }

    closesocket(fd);
    return 0;
}
