#include "server.h"
#include "net_common.h"
#include "protocol.h"
#include "session.h"
#include "threading.h"
#include "worker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <time.h>
#endif

#define MAX_CLIENTS 16
#define MAX_LISTENS 32
#define HEARTBEAT_TIMEOUT_MS 60000

typedef struct {
    int active;
    char client_id[33];
    net_addr_t udp_addr;
    uint64_t last_heartbeat_ms;
} client_entry_t;

typedef struct {
    int active;
    socket_t fd;
    uint16_t remote_port;
    net_addr_t client_udp_addr;
} listen_entry_t;

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

static listen_entry_t *find_listen(listen_entry_t *listens, uint16_t remote_port)
{
    for (int i = 0; i < MAX_LISTENS; i++) {
        if (listens[i].active && listens[i].remote_port == remote_port) {
            return &listens[i];
        }
    }
    return NULL;
}

static listen_entry_t *find_listen_by_fd(listen_entry_t *listens, socket_t fd)
{
    for (int i = 0; i < MAX_LISTENS; i++) {
        if (listens[i].active && listens[i].fd == fd) {
            return &listens[i];
        }
    }
    return NULL;
}

static listen_entry_t *alloc_listen(listen_entry_t *listens)
{
    for (int i = 0; i < MAX_LISTENS; i++) {
        if (!listens[i].active) {
            memset(&listens[i], 0, sizeof(listens[i]));
            listens[i].active = 1;
            return &listens[i];
        }
    }
    return NULL;
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
    socket_t udp_fd = net_udp_socket(cfg->bind_addr, cfg->bind_port);
    if (udp_fd == NET_INVALID_SOCKET) {
        fprintf(stderr, "[server] failed to bind UDP socket\n");
        return 1;
    }
    if (net_set_nonblocking(udp_fd) != 0) {
        fprintf(stderr, "[server] failed to set nonblocking\n");
        closesocket(udp_fd);
        return 1;
    }

    client_entry_t clients[MAX_CLIENTS];
    listen_entry_t listens[MAX_LISTENS];
    session_pool_t *sessions = (session_pool_t *)malloc(sizeof(session_pool_t));
    if (!sessions) {
        fprintf(stderr, "[server] failed to allocate session pool\n");
        closesocket(udp_fd);
        return 1;
    }
    memset(clients, 0, sizeof(clients));
    memset(listens, 0, sizeof(listens));
    session_pool_init(sessions);

    task_queue_t *q = task_queue_create();
    if (!q) {
        fprintf(stderr, "[server] failed to create task queue\n");
        free(sessions);
        closesocket(udp_fd);
        return 1;
    }

    task_queue_t *send_q = task_queue_create();
    if (!send_q) {
        fprintf(stderr, "[server] failed to create send queue\n");
        task_queue_destroy(q);
        free(sessions);
        closesocket(udp_fd);
        return 1;
    }

    worker_ctx_t *wctx = (worker_ctx_t *)malloc(sizeof(worker_ctx_t));
    if (!wctx) {
        task_queue_destroy(send_q);
        task_queue_destroy(q);
        free(sessions);
        closesocket(udp_fd);
        return 1;
    }
    wctx->queue = q;
    wctx->send_q = send_q;
    wctx->keys = keys;
    wctx->udp_fd = udp_fd;
    if (thread_create(worker_thread, wctx) != 0) {
        fprintf(stderr, "[server] failed to create worker thread\n");
        free(wctx);
        task_queue_destroy(send_q);
        task_queue_destroy(q);
        free(sessions);
        closesocket(udp_fd);
        return 1;
    }

    fprintf(stderr, "[server] listening on UDP %s:%u\n", cfg->bind_addr, cfg->bind_port);

    uint64_t last_cleanup = get_time_ms();

    while (1) {
        struct pollfd fds[1 + MAX_LISTENS + MAX_SESSIONS];
        int nfds = 0;

        fds[nfds].fd = udp_fd;
        fds[nfds].events = POLLIN;
        nfds++;

        for (int i = 0; i < MAX_LISTENS; i++) {
            if (listens[i].active) {
                fds[nfds].fd = listens[i].fd;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (sessions->items[i].state == SESS_STATE_ESTABLISHED) {
                fds[nfds].fd = sessions->items[i].local_fd;
                fds[nfds].events = POLLIN;
                if (sessions->items[i].tx_len > 0) {
                    fds[nfds].events |= POLLOUT;
                }
                nfds++;
            }
        }

        /* Drain TCP send tasks from worker before poll */
        for (int i = 0; i < 10; i++) {
            task_t task;
            if (task_queue_pop(send_q, &task, 0) != 0) break;
            session_t *s = session_find(sessions, task.session_id);
            if (!s || s->state != SESS_STATE_ESTABLISHED || s->local_fd == NET_INVALID_SOCKET) continue;
            size_t sent = 0;
            while (sent < task.len) {
                int n = send(s->local_fd, task.data + sent, (int)(task.len - sent), 0);
                if (n > 0) {
                    sent += (size_t)n;
                } else {
                    int err = net_error();
                    if (n < 0 && err == EWOULDBLOCK) {
                        size_t remain = task.len - sent;
                        if (remain > sizeof(s->tx_buf)) remain = sizeof(s->tx_buf);
                        memcpy(s->tx_buf, task.data + sent, remain);
                        s->tx_len = remain;
                        s->tx_off = 0;
                        break;
                    } else {
                        fprintf(stderr, "[server] session %u tcp send error\n", s->id);
                        msg_t close_msg;
                        close_msg.type = MSG_SESSION_CLOSE;
                        close_msg.session_id = s->id;
                        close_msg.seq = 0;
                        close_msg.payload = NULL;
                        close_msg.payload_len = 0;
                        send_msg(udp_fd, &s->peer_addr, keys, &close_msg);
                        session_free(sessions, s);
                        break;
                    }
                }
            }
        }

        int rc = net_poll(fds, nfds, 1000);
        if (rc < 0) {
            fprintf(stderr, "[server] poll error\n");
            break;
        }

        uint64_t now = get_time_ms();

        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & (POLLIN | POLLOUT))) continue;

            if (fds[i].fd == udp_fd) {
                uint8_t packet[1500];
                net_addr_t from;
                memset(&from, 0, sizeof(from));
                from.len = sizeof(from.ss);
                int n = recvfrom(udp_fd, (char *)packet, sizeof(packet), 0,
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

                if (msg.type == MSG_REGISTER) {
                    if (msg.payload_len >= 64) {
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

                                /* Parse tunnels and create listen sockets */
                                size_t p = 64;
                                if (msg.payload_len > p) {
                                    uint8_t tunnel_count = msg.payload[p++];
                                    for (int t = 0; t < tunnel_count && p + 5 <= msg.payload_len; t++) {
                                        uint8_t proto = msg.payload[p++];
                                        uint16_t local_port = ((uint16_t)msg.payload[p] << 8) | msg.payload[p+1];
                                        p += 2;
                                        uint16_t remote_port = ((uint16_t)msg.payload[p] << 8) | msg.payload[p+1];
                                        p += 2;
                                        (void)proto;
                                        (void)local_port;

                                        listen_entry_t *le = find_listen(listens, remote_port);
                                        if (!le) le = alloc_listen(listens);
                                        if (le && !le->fd) {
                                            le->fd = net_tcp_listen("0.0.0.0", remote_port);
                                            if (le->fd != NET_INVALID_SOCKET) {
                                                net_set_nonblocking(le->fd);
                                                le->remote_port = remote_port;
                                                fprintf(stderr, "[server] listening TCP 0.0.0.0:%u\n", remote_port);
                                            } else {
                                                le->active = 0;
                                            }
                                        }
                                        if (le) {
                                            le->client_udp_addr = from;
                                        }
                                    }
                                }

                                msg_t ack;
                                ack.type = MSG_REGISTER_ACK;
                                ack.session_id = 0;
                                ack.seq = 0;
                                ack.payload = NULL;
                                ack.payload_len = 0;
                                send_msg(udp_fd, &from, keys, &ack);
                            }
                        }
                    }
                } else if (msg.type == MSG_HEARTBEAT) {
                    client_entry_t *c = find_client(clients, &from);
                    if (c) {
                        c->last_heartbeat_ms = now;
                        fprintf(stderr, "[server] heartbeat from %s\n", c->client_id);
                    }
                } else if (msg.type == MSG_SESSION_CLOSE) {
                    session_t *s = session_find(sessions, msg.session_id);
                    if (s) {
                        fprintf(stderr, "[server] session %u closed by client\n", msg.session_id);
                        session_free(sessions, s);
                    }
                } else if (msg.type == MSG_SESSION_DATA) {
                    session_t *s = session_find(sessions, msg.session_id);
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
                /* Check if listen socket */
                listen_entry_t *le = find_listen_by_fd(listens, fds[i].fd);
                if (le) {
                    net_addr_t client_addr;
                    memset(&client_addr, 0, sizeof(client_addr));
                    client_addr.len = sizeof(client_addr.ss);
                    socket_t client_fd = accept(fds[i].fd, (struct sockaddr *)&client_addr.ss, &client_addr.len);
                    if (client_fd != NET_INVALID_SOCKET) {
                        net_set_nonblocking(client_fd);
                        session_t *s = session_alloc(sessions);
                        if (s) {
                            s->local_fd = client_fd;
                            s->tunnel_fd = udp_fd;
                            s->peer_addr = le->client_udp_addr;
                            s->remote_port = le->remote_port;
                            s->state = SESS_STATE_ESTABLISHED;
                            s->last_active_ms = now;
                            fprintf(stderr, "[server] accepted session %u for port %u\n", s->id, le->remote_port);

                            uint8_t rp[2];
                            rp[0] = (uint8_t)(le->remote_port >> 8);
                            rp[1] = (uint8_t)(le->remote_port & 0xFF);
                            msg_t open_msg;
                            open_msg.type = MSG_SESSION_OPEN;
                            open_msg.session_id = s->id;
                            open_msg.seq = 0;
                            open_msg.payload = rp;
                            open_msg.payload_len = 2;
                            send_msg(udp_fd, &le->client_udp_addr, keys, &open_msg);
                        } else {
                            closesocket(client_fd);
                        }
                    }
                } else {
                    /* Must be client TCP data */
                    session_t *s = find_session_by_fd(sessions, fds[i].fd);
                    if (s) {
                        if (fds[i].revents & POLLOUT) {
                            while (s->tx_len > 0) {
                                int n = send(s->local_fd, (char *)(s->tx_buf + s->tx_off), (int)s->tx_len, 0);
                                if (n > 0) {
                                    s->tx_off += (size_t)n;
                                    s->tx_len -= (size_t)n;
                                } else {
                                    int err = net_error();
                                    if (n < 0 && err == EWOULDBLOCK) {
                                        break;
                                    } else {
                                        fprintf(stderr, "[server] session %u tcp send error (buffered)\n", s->id);
                                        msg_t close_msg;
                                        close_msg.type = MSG_SESSION_CLOSE;
                                        close_msg.session_id = s->id;
                                        close_msg.seq = 0;
                                        close_msg.payload = NULL;
                                        close_msg.payload_len = 0;
                                        send_msg(udp_fd, &s->peer_addr, keys, &close_msg);
                                        session_free(sessions, s);
                                        break;
                                    }
                                }
                            }
                            if (s && s->state == SESS_STATE_ESTABLISHED && s->tx_len == 0) {
                                s->tx_off = 0;
                            }
                        }
                        if (s && s->state == SESS_STATE_ESTABLISHED && (fds[i].revents & POLLIN)) {
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
                            task.udp_dest = s->peer_addr;
                            task.tcp_fd = NET_INVALID_SOCKET;
                            task_queue_push(q, &task);
                        } else if (n == 0 || (n < 0 && net_error() != EWOULDBLOCK)) {
                            fprintf(stderr, "[server] session %u disconnected\n", s->id);
                            msg_t close_msg;
                            close_msg.type = MSG_SESSION_CLOSE;
                            close_msg.session_id = s->id;
                            close_msg.seq = 0;
                            close_msg.payload = NULL;
                            close_msg.payload_len = 0;
                            send_msg(udp_fd, &s->peer_addr, keys, &close_msg);
                            session_free(sessions, s);
                        }
                    }
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

    free(sessions);
    closesocket(udp_fd);
    return 0;
}
