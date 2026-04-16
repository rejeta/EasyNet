#ifndef WORKER_H
#define WORKER_H

#include "threading.h"
#include "crypto.h"

typedef struct {
    task_queue_t *queue;
    const crypto_keys_t *keys;
    socket_t udp_fd;
} worker_ctx_t;

void *worker_thread(void *arg);

#endif
