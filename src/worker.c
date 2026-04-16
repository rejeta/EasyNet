#include "worker.h"
#include "protocol.h"
#include "net_common.h"
#include <stdio.h>
#include <string.h>

void *worker_thread(void *arg)
{
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    task_t task;

    printf("[worker] started\n");
    while (1) {
        int rc = task_queue_pop(ctx->queue, &task, 100);
        if (rc != 0) continue;

        if (task.type == TASK_ENCRYPT_AND_SEND) {
            msg_t msg;
            msg.type = MSG_SESSION_DATA;
            msg.session_id = task.session_id;
            msg.seq = 0;
            msg.payload = (const uint8_t *)task.data;
            msg.payload_len = task.len;

            uint8_t plaintext[1500];
            size_t plaintext_len;
            if (protocol_encode(&msg, plaintext, sizeof(plaintext), &plaintext_len) != 0) {
                fprintf(stderr, "[worker] protocol_encode failed\n");
                continue;
            }

            uint8_t packet[1600];
            size_t packet_len;
            if (protocol_pack(ctx->keys->enc_key, plaintext, plaintext_len,
                              packet, sizeof(packet), &packet_len) != 0) {
                fprintf(stderr, "[worker] protocol_pack failed\n");
                continue;
            }

            int n = sendto(ctx->udp_fd, (const char *)packet, (int)packet_len, 0,
                           (const struct sockaddr *)&task.udp_dest.ss, task.udp_dest.len);
            if (n != (int)packet_len) {
                fprintf(stderr, "[worker] sendto failed\n");
            }
        } else if (task.type == TASK_DECRYPT_AND_WRITE) {
            /* Main thread already decrypted the UDP packet; worker only needs to write to TCP */
            int n = send(task.tcp_fd, task.data, (int)task.len, 0);
            if (n != (int)task.len) {
                fprintf(stderr, "[worker] tcp send failed\n");
            }
        }
    }

    printf("[worker] exiting\n");
    return NULL;
}
