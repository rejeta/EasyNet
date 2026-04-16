#include "client.h"
#include "net_common.h"
#include "protocol.h"
#include "session.h"
#include "threading.h"
#include "worker.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
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

static session_t *find_session_by_fd(session_pool_t *pool, socket_t fd)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (pool->items[i].state != SESS_STATE_IDLE && pool->items[i].local_fd == fd) {
            return &pool->items[i];
        }
    }
    return NULL;
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

    session_pool_t sessions;
    session_pool_init(&sessions);

    task_queue_t *q = task_queue_create();
    if (!q) {
        fprintf(stderr, "[client] failed to create task queue\n");
        closesocket(fd);
        return 1;
    }

    worker_ctx_t *wctx = (worker_ctx_t *)malloc(sizeof(worker_ctx_t));
    if (!wctx) {
        task_queue_destroy(q);
        closesocket(fd);
        return 1;
    }
    wctx->queue = q;
    wctx->keys = keys;
    wctx->udp_fd = fd;
    if (thread_create(worker_thread, wctx) != 0) {
        fprintf(stderr, "[client] failed to create worker thread\n");
        free(wctx);
        task_queue_destroy(q);
        closesocket(fd);
        return 1;
    }

    uint32_t seq = 1;
    int registered = 0;
    uint64_t last_register_sent = 0;
    uint64_t last_heartbeat_sent = 0;

    printf("[client] starting, server=%s:%u\n", cfg->server_addr, cfg->server_port);

    while (1) {
        struct pollfd fds[1 + MAX_SESSIONS];
        int nfds = 0;

        fds[nfds].fd = fd;
        fds[nfds].events = POLLIN;
        nfds++;

        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (sessions.items[i].state == SESS_STATE_ESTABLISHED) {
                fds[nfds].fd = sessions.items[i].local_fd;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        int rc = net_poll(fds, nfds, 100);
        if (rc < 0) {
            fprintf(stderr, "[client] poll error\n");
            break;
        }

        uint64_t now = get_time_ms();

        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & POLLIN)) continue;

            if (fds[i].fd == fd) {
                uint8_t packet[1500];
                net_addr_t from;
                memset(&from, 0, sizeof(from));
                from.len = sizeof(from.ss);
                int n = recvfrom(fd, (char *)packet, sizeof(packet), 0,
                                 (struct sockaddr *)&from.ss, &from.len);
                if (n <= 0) continue;

                uint8_t plaintext[1500];
                size_t plaintext_len;
                if (protocol_unpack(keys->enc_key, packet, (size_t)n, plaintext, sizeof(plaintext), &plaintext_len) != 0) {
                    continue;
                }
                msg_t msg;
                if (protocol_decode(plaintext, plaintext_len, &msg) != 0) {
                    continue;
                }

                if (msg.type == MSG_REGISTER_ACK) {
                    printf("[client] received REGISTER_ACK\n");
                    registered = 1;
                } else if (msg.type == MSG_HEARTBEAT) {
                    /* server proactive heartbeat or reply */
                } else if (msg.type == MSG_SESSION_OPEN) {
                    if (msg.payload_len >= 2) {
                        uint16_t remote_port = ((uint16_t)msg.payload[0] << 8) | msg.payload[1];
                        const tunnel_config_t *tc = NULL;
                        for (int t = 0; t < cfg->tunnel_count; t++) {
                            if (cfg->tunnels[t].remote_port == remote_port) {
                                tc = &cfg->tunnels[t];
                                break;
                            }
                        }
                        if (tc) {
                            socket_t local_fd = net_tcp_connect(tc->local_addr, tc->local_port);
                            if (local_fd != NET_INVALID_SOCKET) {
                                net_set_nonblocking(local_fd);
                                session_t *s = session_alloc(&sessions);
                                if (s) {
                                    s->id = msg.session_id;
                                    s->local_fd = local_fd;
                                    s->tunnel_fd = fd;
                                    s->peer_addr = server_addr;
                                    s->remote_port = remote_port;
                                    s->state = SESS_STATE_ESTABLISHED;
                                    s->last_active_ms = now;
                                    printf("[client] session %u opened to %s:%u (remote:%u)\n",
                                           s->id, tc->local_addr, tc->local_port, remote_port);
                                } else {
                                    closesocket(local_fd);
                                }
                            } else {
                                fprintf(stderr, "[client] failed to connect local service %s:%u\n",
                                        tc->local_addr, tc->local_port);
                            }
                        }
                    }
                } else if (msg.type == MSG_SESSION_CLOSE) {
                    session_t *s = session_find(&sessions, msg.session_id);
                    if (s) {
                        printf("[client] session %u closed by server\n", msg.session_id);
                        session_free(&sessions, s);
                    }
                } else if (msg.type == MSG_SESSION_DATA) {
                    session_t *s = session_find(&sessions, msg.session_id);
                    if (s && s->state == SESS_STATE_ESTABLISHED) {
                        task_t task;
                        memset(&task, 0, sizeof(task));
                        task.type = TASK_DECRYPT_AND_WRITE;
                        task.session_id = msg.session_id;
                        task.len = msg.payload_len;
                        if (task.len > sizeof(task.data)) task.len = sizeof(task.data);
                        memcpy(task.data, msg.payload, task.len);
                        task.tcp_fd = s->local_fd;
                        task_queue_push(q, &task);
                    }
                }
            } else {
                /* Local service data */
                session_t *s = find_session_by_fd(&sessions, fds[i].fd);
                if (s) {
                    char buf[MAX_PAYLOAD_LEN];
                    int n = recv(fds[i].fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        s->last_active_ms = now;
                        task_t task;
                        memset(&task, 0, sizeof(task));
                        task.type = TASK_ENCRYPT_AND_SEND;
                        task.session_id = s->id;
                        task.len = (size_t)n;
                        memcpy(task.data, buf, task.len);
                        task.udp_dest = server_addr;
                        task.tcp_fd = NET_INVALID_SOCKET;
                        task_queue_push(q, &task);
                    } else if (n == 0 || (n < 0 && net_error() != WSAEWOULDBLOCK && net_error() != EWOULDBLOCK)) {
                        printf("[client] session %u local disconnected\n", s->id);
                        msg_t close_msg;
                        close_msg.type = MSG_SESSION_CLOSE;
                        close_msg.session_id = s->id;
                        close_msg.seq = 0;
                        close_msg.payload = NULL;
                        close_msg.payload_len = 0;
                        send_msg(fd, &server_addr, keys, &close_msg);
                        session_free(&sessions, s);
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
