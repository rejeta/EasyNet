#include "session.h"
#include <string.h>

void session_pool_init(session_pool_t *pool)
{
    memset(pool, 0, sizeof(*pool));
    pool->next_id = 1;
}

session_t *session_alloc(session_pool_t *pool)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (pool->items[i].state == SESS_STATE_IDLE) {
            pool->items[i].state = SESS_STATE_CONNECTING;
            pool->items[i].id = pool->next_id++;
            if (pool->next_id == 0) pool->next_id = 1;
            return &pool->items[i];
        }
    }
    return NULL;
}

void session_free(session_pool_t *pool, session_t *s)
{
    (void)pool;
    if (!s) return;
    if (s->local_fd != NET_INVALID_SOCKET) {
        closesocket(s->local_fd);
        s->local_fd = NET_INVALID_SOCKET;
    }
    memset(s, 0, sizeof(*s));
    s->state = SESS_STATE_IDLE;
}

session_t *session_find(session_pool_t *pool, uint32_t id)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (pool->items[i].state != SESS_STATE_IDLE && pool->items[i].id == id) {
            return &pool->items[i];
        }
    }
    return NULL;
}
