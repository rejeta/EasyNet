#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define KEY_SIZE 32
#define NONCE_SIZE 24
#define TAG_SIZE 16
#define MASTER_KEY_SIZE 64

typedef struct {
    uint8_t enc_key[KEY_SIZE];
    uint8_t auth_token[KEY_SIZE];
} crypto_keys_t;

void crypto_derive_keys(const char *password, size_t pwd_len, crypto_keys_t *keys);
int crypto_encrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *ad, size_t ad_len,
                   uint8_t *ciphertext, uint8_t *tag);
int crypto_decrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *tag,
                   const uint8_t *ad, size_t ad_len,
                   uint8_t *plaintext);
void crypto_random_nonce(uint8_t nonce[NONCE_SIZE]);

#endif
