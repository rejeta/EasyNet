#ifndef CLIENT_H
#define CLIENT_H

#include "config.h"
#include "crypto.h"

int client_run(const app_config_t *cfg, const crypto_keys_t *keys);

#endif
