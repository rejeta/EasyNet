#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include "crypto.h"

int server_run(const app_config_t *cfg, const crypto_keys_t *keys);

#endif
