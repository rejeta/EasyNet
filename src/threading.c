#include "threading.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

struct mutex_t {
    pthread_mutex_t mtx;
};

struct cond_t {
    pthread_cond_t cnd;
};

#define TASK_QUEUE_SIZE 1024

struct task_queue_t {
    task_t buffer[TASK_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    int exit_flag;
    pthread_mutex_t mtx;
    pthread_cond_t cnd;
    pthread_cond_t cnd_full;
};

/* Thread */
int thread_create(void *(*func)(void *), void *arg)
{
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, func, arg);
    if (rc != 0) return -1;
    pthread_detach(tid);
    return 0;
}

/* Mutex */
mutex_t *mutex_create(void)
{
    mutex_t *m = (mutex_t *)malloc(sizeof(mutex_t));
    if (!m) return NULL;
    if (pthread_mutex_init(&m->mtx, NULL) != 0) {
        free(m);
        return NULL;
    }
    return m;
}

void mutex_destroy(mutex_t *m)
{
    if (!m) return;
    pthread_mutex_destroy(&m->mtx);
    free(m);
}

void mutex_lock(mutex_t *m)
{
    if (m) pthread_mutex_lock(&m->mtx);
}

void mutex_unlock(mutex_t *m)
{
    if (m) pthread_mutex_unlock(&m->mtx);
}

/* Condition variable */
cond_t *cond_create(void)
{
    cond_t *c = (cond_t *)malloc(sizeof(cond_t));
    if (!c) return NULL;
    if (pthread_cond_init(&c->cnd, NULL) != 0) {
        free(c);
        return NULL;
    }
    return c;
}

void cond_destroy(cond_t *c)
{
    if (!c) return;
    pthread_cond_destroy(&c->cnd);
    free(c);
}

void cond_wait(cond_t *c, mutex_t *m)
{
    if (c && m) pthread_cond_wait(&c->cnd, &m->mtx);
}

void cond_signal(cond_t *c)
{
    if (c) pthread_cond_signal(&c->cnd);
}

/* Task queue */
task_queue_t *task_queue_create(void)
{
    task_queue_t *q = (task_queue_t *)malloc(sizeof(task_queue_t));
    if (!q) return NULL;
    memset(q, 0, sizeof(*q));
    q->exit_flag = 0;
    if (pthread_mutex_init(&q->mtx, NULL) != 0) {
        free(q);
        return NULL;
    }
    if (pthread_cond_init(&q->cnd, NULL) != 0) {
        pthread_mutex_destroy(&q->mtx);
        free(q);
        return NULL;
    }
    if (pthread_cond_init(&q->cnd_full, NULL) != 0) {
        pthread_cond_destroy(&q->cnd);
        pthread_mutex_destroy(&q->mtx);
        free(q);
        return NULL;
    }
    return q;
}

void task_queue_destroy(task_queue_t *q)
{
    if (!q) return;
    pthread_mutex_destroy(&q->mtx);
    pthread_cond_destroy(&q->cnd);
    pthread_cond_destroy(&q->cnd_full);
    free(q);
}

void task_queue_push(task_queue_t *q, const task_t *task)
{
    if (!q || !task) return;
    pthread_mutex_lock(&q->mtx);
    while (q->count >= TASK_QUEUE_SIZE && !q->exit_flag) {
        pthread_cond_wait(&q->cnd_full, &q->mtx);
    }
    if (q->exit_flag) {
        pthread_mutex_unlock(&q->mtx);
        return;
    }
    q->buffer[q->tail] = *task;
    q->tail = (q->tail + 1) % TASK_QUEUE_SIZE;
    q->count++;
    pthread_cond_signal(&q->cnd);
    pthread_mutex_unlock(&q->mtx);
}

int task_queue_pop(task_queue_t *q, task_t *out, int timeout_ms)
{
    if (!q || !out) return -1;
    pthread_mutex_lock(&q->mtx);

    if (q->count == 0 && !q->exit_flag) {
        struct timespec ts;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        long sec = tv.tv_sec + (timeout_ms / 1000);
        long nsec = tv.tv_usec * 1000 + (timeout_ms % 1000) * 1000000;
        if (nsec >= 1000000000) {
            sec++;
            nsec -= 1000000000;
        }
        ts.tv_sec = sec;
        ts.tv_nsec = nsec;

        int rc = pthread_cond_timedwait(&q->cnd, &q->mtx, &ts);
        if (rc != 0) {
            pthread_mutex_unlock(&q->mtx);
            return -1;
        }
    }

    if (q->count == 0) {
        pthread_mutex_unlock(&q->mtx);
        return -1;
    }

    *out = q->buffer[q->head];
    q->head = (q->head + 1) % TASK_QUEUE_SIZE;
    q->count--;
    pthread_cond_signal(&q->cnd_full);
    pthread_mutex_unlock(&q->mtx);
    return 0;
}

void task_queue_set_exit(task_queue_t *q)
{
    if (!q) return;
    pthread_mutex_lock(&q->mtx);
    q->exit_flag = 1;
    pthread_cond_broadcast(&q->cnd);
    pthread_cond_broadcast(&q->cnd_full);
    pthread_mutex_unlock(&q->mtx);
}
