#include "crypto.h"
#include "monocypher.h"
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "bcrypt.lib")
    #endif
#else
    #include <stdio.h>
#endif

void crypto_derive_keys(const char *password, size_t pwd_len, crypto_keys_t *keys)
{
    uint8_t master_key[MASTER_KEY_SIZE];
    crypto_blake2b(master_key, MASTER_KEY_SIZE,
                   (const uint8_t *)password, pwd_len);
    memcpy(keys->enc_key, master_key, KEY_SIZE);
    memcpy(keys->auth_token, master_key + KEY_SIZE, KEY_SIZE);
    crypto_wipe(master_key, sizeof(master_key));
}

int crypto_encrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *ad, size_t ad_len,
                   uint8_t *ciphertext, uint8_t *tag)
{
    crypto_aead_lock(ciphertext, tag, key, nonce,
                     ad, ad_len,
                     plaintext, plaintext_len);
    return 0;
}

int crypto_decrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *tag,
                   const uint8_t *ad, size_t ad_len,
                   uint8_t *plaintext)
{
    return crypto_aead_unlock(plaintext, tag, key, nonce,
                              ad, ad_len,
                              ciphertext, ciphertext_len);
}

void crypto_random_nonce(uint8_t nonce[NONCE_SIZE])
{
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, nonce, NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    (void)status;
#else
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        size_t n = fread(nonce, 1, NONCE_SIZE, fp);
        (void)n;
        fclose(fp);
    }
#endif
}
