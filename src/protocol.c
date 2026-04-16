#include "protocol.h"
#include <string.h>

static void write_u32_be(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)v;
}

static uint32_t read_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

int protocol_encode(const msg_t *msg, uint8_t *out_buf, size_t out_buflen, size_t *out_len)
{
    size_t total = 1 + 4 + 4 + msg->payload_len;
    if (out_buflen < total) return -1;
    out_buf[0] = (uint8_t)msg->type;
    write_u32_be(out_buf + 1, msg->session_id);
    write_u32_be(out_buf + 5, msg->seq);
    if (msg->payload_len > 0) {
        memcpy(out_buf + 9, msg->payload, msg->payload_len);
    }
    *out_len = total;
    return 0;
}

int protocol_decode(const uint8_t *in_buf, size_t in_len, msg_t *out)
{
    if (in_len < 9) return -1;
    out->type = (msg_type_t)in_buf[0];
    out->session_id = read_u32_be(in_buf + 1);
    out->seq = read_u32_be(in_buf + 5);
    if (in_len > 9) {
        out->payload = in_buf + 9;
        out->payload_len = in_len - 9;
    } else {
        out->payload = NULL;
        out->payload_len = 0;
    }
    return 0;
}

int protocol_pack(const uint8_t *key,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *packet, size_t packet_buflen, size_t *packet_len)
{
    if (packet_buflen < NONCE_SIZE + plaintext_len + TAG_SIZE) return -1;
    uint8_t nonce[NONCE_SIZE];
    crypto_random_nonce(nonce);
    uint8_t tag[TAG_SIZE];
    crypto_encrypt(key, nonce, plaintext, plaintext_len, NULL, 0,
                   packet + NONCE_SIZE, tag);
    memcpy(packet, nonce, NONCE_SIZE);
    memcpy(packet + NONCE_SIZE + plaintext_len, tag, TAG_SIZE);
    *packet_len = NONCE_SIZE + plaintext_len + TAG_SIZE;
    return 0;
}

int protocol_unpack(const uint8_t *key,
                    const uint8_t *packet, size_t packet_len,
                    uint8_t *plaintext, size_t plaintext_buflen, size_t *plaintext_len)
{
    if (packet_len < NONCE_SIZE + TAG_SIZE + 1) return -1;
    size_t cipher_len = packet_len - NONCE_SIZE - TAG_SIZE;
    if (plaintext_buflen < cipher_len) return -1;
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + NONCE_SIZE;
    const uint8_t *tag = packet + packet_len - TAG_SIZE;
    if (crypto_decrypt(key, nonce, ciphertext, cipher_len, tag, NULL, 0, plaintext) != 0) {
        return -1;
    }
    *plaintext_len = cipher_len;
    return 0;
}
