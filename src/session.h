#ifndef SESSION_H
#define SESSION_H

#include "net_common.h"
#include <stdint.h>

#define MAX_SESSIONS 256

typedef enum {
    SESS_STATE_IDLE = 0,
    SESS_STATE_CONNECTING,
    SESS_STATE_ESTABLISHED,
    SESS_STATE_CLOSING
} session_state_t;

typedef struct {
    uint32_t id;
    session_state_t state;
    socket_t local_fd;
    socket_t tunnel_fd;
    net_addr_t peer_addr;
    uint64_t last_active_ms;
    uint16_t remote_port;
    uint8_t tx_buf[8192];
    size_t tx_len;
    size_t tx_off;
} session_t;

typedef struct {
    session_t items[MAX_SESSIONS];
    uint32_t next_id;
} session_pool_t;

void session_pool_init(session_pool_t *pool);
session_t *session_alloc(session_pool_t *pool);
void session_free(session_pool_t *pool, session_t *s);
session_t *session_find(session_pool_t *pool, uint32_t id);

#endif
