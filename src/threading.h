#ifndef THREADING_H
#define THREADING_H

#include <stddef.h>
#include <stdint.h>
#include "net_common.h"

/* Thread */
int thread_create(void *(*func)(void *), void *arg);

/* Mutex */
typedef struct mutex_t mutex_t;
mutex_t *mutex_create(void);
void mutex_destroy(mutex_t *m);
void mutex_lock(mutex_t *m);
void mutex_unlock(mutex_t *m);

/* Condition variable */
typedef struct cond_t cond_t;
cond_t *cond_create(void);
void cond_destroy(cond_t *c);
void cond_wait(cond_t *c, mutex_t *m);
void cond_signal(cond_t *c);

/* Task queue */
typedef struct task_queue_t task_queue_t;

typedef enum {
    TASK_ENCRYPT_AND_SEND,
    TASK_DECRYPT_AND_WRITE,
    TASK_SEND_TCP
} task_type_t;

typedef struct {
    task_type_t type;
    uint32_t session_id;
    uint16_t seq;             /* ARQ 序列号（仅 SESSION_DATA 有效） */
    char data[4096];
    size_t len;
    net_addr_t udp_dest;
    socket_t tcp_fd;
} task_t;

task_queue_t *task_queue_create(void);
void task_queue_destroy(task_queue_t *q);
void task_queue_push(task_queue_t *q, const task_t *task);
int task_queue_pop(task_queue_t *q, task_t *out, int timeout_ms);
void task_queue_set_exit(task_queue_t *q);

#endif
