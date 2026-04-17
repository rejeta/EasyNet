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

static void append_to_tx_buf(session_t *s, const uint8_t *data, size_t len)
{
    size_t remain = len;
    if (remain > sizeof(s->tx_buf)) remain = sizeof(s->tx_buf);
    size_t buf_used_end = s->tx_off + s->tx_len;
    if (s->tx_len > 0 && buf_used_end + remain > sizeof(s->tx_buf)) {
        memmove(s->tx_buf, s->tx_buf + s->tx_off, s->tx_len);
        s->tx_off = 0;
        buf_used_end = s->tx_len;
    }
    size_t avail = sizeof(s->tx_buf) - buf_used_end;
    if (remain > avail) remain = avail;
    if (remain > 0) {
        memcpy(s->tx_buf + buf_used_end, data, remain);
        s->tx_len += remain;
    }
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

    session_pool_t *sessions = (session_pool_t *)malloc(sizeof(session_pool_t));
    if (!sessions) {
        fprintf(stderr, "[client] failed to allocate session pool\n");
        closesocket(fd);
        return 1;
    }
    session_pool_init(sessions);

#define NUM_WORKERS 4
    task_queue_t *qs[NUM_WORKERS];
    for (int w = 0; w < NUM_WORKERS; w++) qs[w] = NULL;

    for (int w = 0; w < NUM_WORKERS; w++) {
        qs[w] = task_queue_create();
        if (!qs[w]) {
            fprintf(stderr, "[client] failed to create task queue %d\n", w);
            for (int j = 0; j < w; j++) task_queue_destroy(qs[j]);
            free(sessions);
            closesocket(fd);
            return 1;
        }
    }

    task_queue_t *send_q = task_queue_create();
    if (!send_q) {
        fprintf(stderr, "[client] failed to create send queue\n");
        for (int w = 0; w < NUM_WORKERS; w++) task_queue_destroy(qs[w]);
        free(sessions);
        closesocket(fd);
        return 1;
    }

    int workers_ok = 0;
    for (int w = 0; w < NUM_WORKERS; w++) {
        worker_ctx_t *wctx = (worker_ctx_t *)malloc(sizeof(worker_ctx_t));
        if (!wctx) {
            fprintf(stderr, "[client] failed to alloc worker ctx %d\n", w);
            continue;
        }
        wctx->queue = qs[w];
        wctx->send_q = send_q;
        wctx->keys = keys;
        wctx->udp_fd = fd;
        if (thread_create(worker_thread, wctx) == 0) {
            workers_ok++;
        } else {
            free(wctx);
        }
    }
    if (workers_ok == 0) {
        fprintf(stderr, "[client] failed to create any worker thread\n");
        task_queue_destroy(send_q);
        for (int w = 0; w < NUM_WORKERS; w++) task_queue_destroy(qs[w]);
        free(sessions);
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
            if (sessions->items[i].state == SESS_STATE_ESTABLISHED ||
                sessions->items[i].state == SESS_STATE_CONNECTING) {
                fds[nfds].fd = sessions->items[i].local_fd;
                fds[nfds].events = 0;
                if (sessions->items[i].state == SESS_STATE_CONNECTING ||
                    sessions->items[i].send_pkt_count < SEND_WND_SIZE) {
                    fds[nfds].events |= POLLIN;
                }
                if (sessions->items[i].state == SESS_STATE_CONNECTING || sessions->items[i].tx_len > 0) {
                    fds[nfds].events |= POLLOUT;
                }
                nfds++;
            }
        }

        /* Drain TCP send tasks from worker before poll */
        while (1) {
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
                    if (n < 0 && net_would_block(err)) {
                        size_t remain = task.len - sent;
                        size_t buf_used_end = s->tx_off + s->tx_len;
                        if (s->tx_len > 0 && buf_used_end + remain > sizeof(s->tx_buf)) {
                            memmove(s->tx_buf, s->tx_buf + s->tx_off, s->tx_len);
                            s->tx_off = 0;
                            buf_used_end = s->tx_len;
                        }
                        size_t avail = sizeof(s->tx_buf) - buf_used_end;
                        if (remain > avail) remain = avail;
                        if (remain > 0) {
                            memcpy(s->tx_buf + buf_used_end, task.data + sent, remain);
                            s->tx_len += remain;
                        }
                        break;
                    } else {
                        fprintf(stderr, "[client] session %u tcp send error (%d)\n", s->id, err);
                        msg_t close_msg;
                        close_msg.type = MSG_SESSION_CLOSE;
                        close_msg.session_id = s->id;
                        close_msg.seq = 0;
                        close_msg.payload = NULL;
                        close_msg.payload_len = 0;
                        send_msg(fd, &server_addr, keys, &close_msg);
                        session_free(sessions, s);
                        break;
                    }
                }
            }
        }

        int rc = net_poll(fds, nfds, 100);
        if (rc < 0) {
            fprintf(stderr, "[client] poll error\n");
            break;
        }

        uint64_t now = get_time_ms();

        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & (POLLIN | POLLOUT))) continue;

            if (fds[i].fd == fd) {
                while (1) {
                    uint8_t packet[1500];
                    net_addr_t from;
                    memset(&from, 0, sizeof(from));
                    from.len = sizeof(from.ss);
                    int n = recvfrom(fd, (char *)packet, sizeof(packet), 0,
                                     (struct sockaddr *)&from.ss, &from.len);
                    if (n <= 0) {
                        if (n < 0 && net_would_block(net_error())) break;
                        break;
                    }

                    uint8_t plaintext[1500];
                    size_t plaintext_len;
                    if (protocol_unpack(keys->enc_key, packet, (size_t)n, plaintext, sizeof(plaintext), &plaintext_len) != 0) {
                        fprintf(stderr, "[client] protocol_unpack failed (n=%d)\n", n);
                        continue;
                    }
                    msg_t msg;
                    if (protocol_decode(plaintext, plaintext_len, &msg) != 0) {
                        fprintf(stderr, "[client] protocol_decode failed\n");
                        continue;
                    }
                    if (msg.type == MSG_SESSION_DATA || msg.type == MSG_SESSION_ACK) {
                        fprintf(stderr, "[client] recv msg type=%u session=%u seq=%u payload=%zu\n",
                                (unsigned)msg.type, msg.session_id, msg.seq, msg.payload_len);
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
                            socket_t local_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if (local_fd != NET_INVALID_SOCKET) {
                                net_set_nonblocking(local_fd);
                                struct sockaddr_in sin;
                                memset(&sin, 0, sizeof(sin));
                                sin.sin_family = AF_INET;
                                sin.sin_port = htons(tc->local_port);
                                if (inet_pton(AF_INET, tc->local_addr, &sin.sin_addr) == 1) {
                                    int cr = connect(local_fd, (struct sockaddr *)&sin, sizeof(sin));
                                    int conn_err = (cr == 0) ? 0 : net_error();
                                    if (cr == 0 || net_would_block(conn_err) || conn_err == EINPROGRESS
#ifdef _WIN32
                                        || conn_err == WSAEINPROGRESS
#endif
                                        ) {
                                        session_t *s = session_alloc(sessions);
                                        if (s) {
                                            s->id = msg.session_id;
                                            s->local_fd = local_fd;
                                            s->tunnel_fd = fd;
                                            s->peer_addr = server_addr;
                                            s->remote_port = remote_port;
                                            s->state = SESS_STATE_CONNECTING;
                                            s->last_active_ms = now;
                                            s->tx_len = 0;
                                            s->tx_off = 0;
                                            net_tcp_tune(local_fd);
                                            printf("[client] session %u connecting to %s:%u (remote:%u)\n",
                                                   s->id, tc->local_addr, tc->local_port, remote_port);
                                        } else {
                                            closesocket(local_fd);
                                        }
                                    } else {
                                        fprintf(stderr, "[client] failed to connect local service %s:%u (err=%d)\n",
                                                tc->local_addr, tc->local_port, conn_err);
                                        closesocket(local_fd);
                                    }
                                } else {
                                    closesocket(local_fd);
                                }
                            }
                        }
                    }
                } else if (msg.type == MSG_SESSION_CLOSE) {
                    session_t *s = session_find(sessions, msg.session_id);
                    if (s) {
                        printf("[client] session %u closed by server\n", msg.session_id);
                        session_free(sessions, s);
                    }
                } else if (msg.type == MSG_SESSION_ACK) {
                    session_t *s = session_find(sessions, msg.session_id);
                    if (s && s->state == SESS_STATE_ESTABLISHED) {
                        uint16_t ack_seq = (uint16_t)msg.seq;
                        int cleared = 0;
                        for (int k = 0; k < SEND_WND_SIZE; k++) {
                            if (s->send_pkts[k].len > 0) {
                                if ((int16_t)(s->send_pkts[k].seq - ack_seq) < 0) {
                                    s->send_pkts[k].len = 0;
                                    s->send_pkt_count--;
                                    cleared++;
                                }
                            }
                        }
                        fprintf(stderr, "[client] SESSION_ACK recv session=%u ack_seq=%u cleared=%d window=%d\n",
                                s->id, ack_seq, cleared, s->send_pkt_count);
                    }
                } else if (msg.type == MSG_SESSION_DATA) {
                    session_t *s = session_find(sessions, msg.session_id);
                    if (!s) continue;
                    uint16_t seq = (uint16_t)msg.seq;
                    fprintf(stderr, "[client] SESSION_DATA recv session=%u seq=%u rx_next=%u state=%d\n",
                            s->id, seq, s->rx_next_seq, s->state);
                    int need_ack = 0;
                    if (seq == s->rx_next_seq) {
                        if (s->state == SESS_STATE_ESTABLISHED) {
                            task_t task;
                            memset(&task, 0, sizeof(task));
                            task.type = TASK_DECRYPT_AND_WRITE;
                            task.session_id = msg.session_id;
                            task.len = msg.payload_len;
                            if (task.len > sizeof(task.data)) task.len = sizeof(task.data);
                            memcpy(task.data, msg.payload, task.len);
                            task.tcp_fd = s->local_fd;
                            task_queue_push(qs[task.session_id % NUM_WORKERS], &task);
                        } else if (s->state == SESS_STATE_CONNECTING) {
                            append_to_tx_buf(s, msg.payload, msg.payload_len);
                        }
                        s->rx_next_seq++;
                        while (1) {
                            int idx = s->rx_next_seq % RECV_WND_SIZE;
                            if (s->recv_slots[idx].valid && s->recv_slots[idx].seq == s->rx_next_seq) {
                                if (s->state == SESS_STATE_ESTABLISHED) {
                                    task_t ctask;
                                    memset(&ctask, 0, sizeof(ctask));
                                    ctask.type = TASK_DECRYPT_AND_WRITE;
                                    ctask.session_id = msg.session_id;
                                    ctask.len = s->recv_slots[idx].len;
                                    if (ctask.len > sizeof(ctask.data)) ctask.len = sizeof(ctask.data);
                                    memcpy(ctask.data, s->recv_slots[idx].payload, ctask.len);
                                    ctask.tcp_fd = s->local_fd;
                                    task_queue_push(qs[msg.session_id % NUM_WORKERS], &ctask);
                                } else if (s->state == SESS_STATE_CONNECTING) {
                                    append_to_tx_buf(s, s->recv_slots[idx].payload, s->recv_slots[idx].len);
                                }
                                s->recv_slots[idx].valid = 0;
                                s->rx_next_seq++;
                            } else {
                                break;
                            }
                        }
                        need_ack = 1;
                    } else if ((int16_t)(seq - s->rx_next_seq) > 0 && (int16_t)(seq - s->rx_next_seq) < RECV_WND_SIZE) {
                        int idx = seq % RECV_WND_SIZE;
                        if (!s->recv_slots[idx].valid || s->recv_slots[idx].seq != seq) {
                            s->recv_slots[idx].valid = 1;
                            s->recv_slots[idx].seq = seq;
                            s->recv_slots[idx].len = msg.payload_len;
                            if (s->recv_slots[idx].len > MAX_PAYLOAD_LEN) s->recv_slots[idx].len = MAX_PAYLOAD_LEN;
                            memcpy(s->recv_slots[idx].payload, msg.payload, s->recv_slots[idx].len);
                        }
                        need_ack = 1;
                    } else if ((int16_t)(seq - s->rx_next_seq) < 0) {
                        need_ack = 1;
                    }
                    if (need_ack) {
                        msg_t ack_msg;
                        ack_msg.type = MSG_SESSION_ACK;
                        ack_msg.session_id = s->id;
                        ack_msg.seq = s->rx_next_seq;
                        ack_msg.payload = NULL;
                        ack_msg.payload_len = 0;
                        fprintf(stderr, "[client] sending ACK session=%u ack_seq=%u\n", s->id, s->rx_next_seq);
                        send_msg(fd, &server_addr, keys, &ack_msg);
                    }
                }
                }  /* end while(1) drain UDP */
            } else {
                /* Local service data */
                session_t *s = find_session_by_fd(sessions, fds[i].fd);
                if (s) {
                    if (fds[i].revents & POLLOUT) {
                        if (s->state == SESS_STATE_CONNECTING) {
                            int so_err = 0;
                            socklen_t so_err_len = sizeof(so_err);
                            if (getsockopt(s->local_fd, SOL_SOCKET, SO_ERROR, (char *)&so_err, &so_err_len) == 0) {
                                if (so_err == 0) {
                                    s->state = SESS_STATE_ESTABLISHED;
                                    printf("[client] session %u connected\n", s->id);
                                } else {
                                    fprintf(stderr, "[client] session %u connect failed (%d)\n", s->id, so_err);
                                    msg_t close_msg;
                                    close_msg.type = MSG_SESSION_CLOSE;
                                    close_msg.session_id = s->id;
                                    close_msg.seq = 0;
                                    close_msg.payload = NULL;
                                    close_msg.payload_len = 0;
                                    send_msg(fd, &server_addr, keys, &close_msg);
                                    session_free(sessions, s);
                                }
                            }
                        }
                        if (s && s->state == SESS_STATE_ESTABLISHED) {
                            while (s->tx_len > 0) {
                                int n = send(s->local_fd, (char *)(s->tx_buf + s->tx_off), (int)s->tx_len, 0);
                                if (n > 0) {
                                    s->tx_off += (size_t)n;
                                    s->tx_len -= (size_t)n;
                                } else {
                                    int err = net_error();
                                    if (n < 0 && net_would_block(err)) {
                                        break;
                                    } else {
                                        fprintf(stderr, "[client] session %u tcp send error (buffered)\n", s->id);
                                        msg_t close_msg;
                                        close_msg.type = MSG_SESSION_CLOSE;
                                        close_msg.session_id = s->id;
                                        close_msg.seq = 0;
                                        close_msg.payload = NULL;
                                        close_msg.payload_len = 0;
                                        send_msg(fd, &server_addr, keys, &close_msg);
                                        session_free(sessions, s);
                                        break;
                                    }
                                }
                            }
                        }
                        if (s && s->state == SESS_STATE_ESTABLISHED && s->tx_len == 0) {
                            s->tx_off = 0;
                        }
                    }
                    if (s && s->state == SESS_STATE_ESTABLISHED && (fds[i].revents & POLLIN)) {
                        if (s->send_pkt_count < SEND_WND_SIZE) {
                            char buf[MAX_PAYLOAD_LEN];
                            int n = recv(fds[i].fd, buf, sizeof(buf), 0);
                            if (n > 0) {
                                s->last_active_ms = now;
                                uint16_t seq = s->tx_next_seq++;
                                int idx = seq % SEND_WND_SIZE;
                                s->send_pkts[idx].seq = seq;
                                s->send_pkts[idx].len = (size_t)n;
                                memcpy(s->send_pkts[idx].payload, buf, (size_t)n);
                                s->send_pkts[idx].send_time_ms = now;
                                s->send_pkts[idx].retries = 0;
                                s->send_pkt_count++;

                                task_t task;
                                memset(&task, 0, sizeof(task));
                                task.type = TASK_ENCRYPT_AND_SEND;
                                task.session_id = s->id;
                                task.seq = seq;
                                task.len = (size_t)n;
                                memcpy(task.data, buf, task.len);
                                task.udp_dest = server_addr;
                                task.tcp_fd = NET_INVALID_SOCKET;
                                task_queue_push(qs[task.session_id % NUM_WORKERS], &task);
                            } else if (n == 0 || (n < 0 && !net_would_block(net_error()))) {
                                printf("[client] session %u local disconnected\n", s->id);
                                msg_t close_msg;
                                close_msg.type = MSG_SESSION_CLOSE;
                                close_msg.session_id = s->id;
                                close_msg.seq = 0;
                                close_msg.payload = NULL;
                                close_msg.payload_len = 0;
                                send_msg(fd, &server_addr, keys, &close_msg);
                                session_free(sessions, s);
                            }
                        }
                    }
                }
            }
        }

        /* ARQ retransmit scan */
        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &sessions->items[i];
            if (s->state != SESS_STATE_ESTABLISHED) continue;
            for (int j = 0; j < SEND_WND_SIZE; j++) {
                if (s->send_pkts[j].len > 0) {
                    uint16_t pkt_seq = s->send_pkts[j].seq;
                    int16_t diff = (int16_t)(s->tx_next_seq - pkt_seq);
                    if (diff > 0 && diff <= SEND_WND_SIZE) {
                        if ((now - s->send_pkts[j].send_time_ms) > RETRANSMIT_TIMEOUT_MS) {
                            s->send_pkts[j].retries++;
                            if (s->send_pkts[j].retries > MAX_RETRANSMIT_RETRIES) {
                                fprintf(stderr, "[client] session %u max retransmits exceeded\n", s->id);
                                msg_t close_msg;
                                close_msg.type = MSG_SESSION_CLOSE;
                                close_msg.session_id = s->id;
                                close_msg.seq = 0;
                                close_msg.payload = NULL;
                                close_msg.payload_len = 0;
                                send_msg(fd, &server_addr, keys, &close_msg);
                                session_free(sessions, s);
                                break;
                            }
                            task_t task;
                            memset(&task, 0, sizeof(task));
                            task.type = TASK_ENCRYPT_AND_SEND;
                            task.session_id = s->id;
                            task.seq = pkt_seq;
                            task.len = s->send_pkts[j].len;
                            memcpy(task.data, s->send_pkts[j].payload, task.len);
                            task.udp_dest = server_addr;
                            task.tcp_fd = NET_INVALID_SOCKET;
                            task_queue_push(qs[s->id % NUM_WORKERS], &task);
                            s->send_pkts[j].send_time_ms = now;
                            fprintf(stderr, "[client] session %u retransmit seq=%u retries=%d\n", s->id, pkt_seq, s->send_pkts[j].retries);
                        }
                    } else if (diff > SEND_WND_SIZE || diff < -SEND_WND_SIZE) {
                        s->send_pkts[j].len = 0;
                        s->send_pkt_count--;
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

    free(sessions);
    closesocket(fd);
    return 0;
}
