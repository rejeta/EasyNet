#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_common.h"
#include "config.h"
#include "crypto.h"
#include "client.h"
#include "server.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -c <config.toml>\n", prog);
}

int main(int argc, char *argv[])
{
    const char *config_file = "easynet.toml";

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            config_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (net_init() != 0) {
        fprintf(stderr, "[main] net_init failed\n");
        return 1;
    }

    app_config_t cfg;
    if (config_load(config_file, &cfg) != 0) {
        net_cleanup();
        return 1;
    }

    printf("[main] config: %s\n", config_file);
    printf("[main] mode: %s\n", cfg.is_server ? "server" : "client");

    crypto_keys_t keys;
    crypto_derive_keys(cfg.password, strlen(cfg.password), &keys);

    int rc;
    if (cfg.is_server) {
        rc = server_run(&cfg, &keys);
    } else {
        rc = client_run(&cfg, &keys);
    }

    net_cleanup();
    return rc;
}
