#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_common.h"
#include "threading.h"
#include "config.h"
#include "crypto.h"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -c <config.toml>\n", prog);
}

static int self_test_crypto(const crypto_keys_t *keys)
{
    const char *plaintext = "Hello, EasyNet! This is a crypto self-test.";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    uint8_t tag[TAG_SIZE];
    uint8_t nonce[NONCE_SIZE];

    crypto_random_nonce(nonce);

    if (crypto_encrypt(keys->enc_key, nonce,
                       (const uint8_t *)plaintext, len,
                       NULL, 0,
                       ciphertext, tag) != 0) {
        fprintf(stderr, "[self_test] encrypt failed\n");
        return -1;
    }

    if (crypto_decrypt(keys->enc_key, nonce,
                       ciphertext, len,
                       tag,
                       NULL, 0,
                       decrypted) != 0) {
        fprintf(stderr, "[self_test] decrypt failed\n");
        return -1;
    }

    if (memcmp(plaintext, decrypted, len) != 0) {
        fprintf(stderr, "[self_test] plaintext mismatch\n");
        return -1;
    }

    /* Tamper with ciphertext, expect decrypt to fail */
    ciphertext[0] ^= 0xFF;
    if (crypto_decrypt(keys->enc_key, nonce,
                       ciphertext, len,
                       tag,
                       NULL, 0,
                       decrypted) == 0) {
        fprintf(stderr, "[self_test] tampered data should have failed decrypt\n");
        return -1;
    }

    printf("[self_test] crypto OK\n");
    return 0;
}

int main(int argc, char *argv[])
{
    const char *config_file = "easynet.toml";
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
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

    printf("[main] config: %s\n", config_file);

    app_config_t cfg;
    if (config_load(config_file, &cfg) != 0) {
        return 1;
    }

    printf("[main] mode: %s\n", cfg.is_server ? "server" : "client");
    if (!cfg.is_server) {
        printf("[main] server: %s:%u\n", cfg.server_addr, cfg.server_port);
        printf("[main] tunnels: %d\n", cfg.tunnel_count);
        for (i = 0; i < cfg.tunnel_count; i++) {
            printf("[main]   tunnel %d: %s:%u -> remote:%u (%s)\n",
                   i,
                   cfg.tunnels[i].local_addr,
                   cfg.tunnels[i].local_port,
                   cfg.tunnels[i].remote_port,
                   cfg.tunnels[i].protocol == PROTO_UDP ? "udp" : "tcp");
        }
    } else {
        printf("[main] bind: %s:%u\n", cfg.bind_addr, cfg.bind_port);
    }

    crypto_keys_t keys;
    crypto_derive_keys(cfg.password, strlen(cfg.password), &keys);

    /* Verify key derivation is deterministic */
    crypto_keys_t keys2;
    crypto_derive_keys(cfg.password, strlen(cfg.password), &keys2);
    if (memcmp(&keys, &keys2, sizeof(keys)) != 0) {
        fprintf(stderr, "[main] key derivation is not deterministic!\n");
        return 1;
    }
    memset(&keys2, 0, sizeof(keys2));

    if (self_test_crypto(&keys) != 0) {
        fprintf(stderr, "[main] crypto self-test failed\n");
        return 1;
    }

    printf("[main] Phase 2 initialization complete. Ready for Phase 3.\n");
    return 0;
}
