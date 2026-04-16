#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define MAX_TUNNELS 16
#define PASSWORD_MAX_LEN 128

typedef enum {
    PROTO_TCP = 0,
    PROTO_UDP = 1
} protocol_t;

typedef struct {
    char local_addr[64];
    uint16_t local_port;
    uint16_t remote_port;
    protocol_t protocol;
} tunnel_config_t;

typedef struct {
    int is_server;
    char bind_addr[64];
    uint16_t bind_port;
    char server_addr[64];
    uint16_t server_port;
    char password[PASSWORD_MAX_LEN + 1];
    tunnel_config_t tunnels[MAX_TUNNELS];
    int tunnel_count;
} app_config_t;

int config_load(const char *filename, app_config_t *out);

#endif
