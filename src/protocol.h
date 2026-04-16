#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

#define MAX_PAYLOAD_LEN 1300
#define PACKET_OVERHEAD (NONCE_SIZE + TAG_SIZE)

/* Payload formats:
 * MSG_REGISTER:     [auth_token:32][client_id:32][tunnel_count:1]
 *                   for each tunnel: [protocol:1][local_port:2][remote_port:2]
 * MSG_REGISTER_ACK: (empty)
 * MSG_HEARTBEAT:    (empty)
 * MSG_SESSION_OPEN: [remote_port:2] (big-endian)
 * MSG_SESSION_CLOSE: (empty)
 * MSG_SESSION_DATA: raw bytes
 */
typedef enum {
    MSG_REGISTER = 0x01,
    MSG_REGISTER_ACK = 0x02,
    MSG_HEARTBEAT = 0x03,
    MSG_SESSION_OPEN = 0x04,
    MSG_SESSION_CLOSE = 0x05,
    MSG_SESSION_DATA = 0x06
} msg_type_t;

typedef struct {
    msg_type_t type;
    uint32_t session_id;
    uint32_t seq;
    const uint8_t *payload;
    size_t payload_len;
} msg_t;

int protocol_encode(const msg_t *msg, uint8_t *out_buf, size_t out_buflen, size_t *out_len);
int protocol_decode(const uint8_t *in_buf, size_t in_len, msg_t *out);
int protocol_pack(const uint8_t *key,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *packet, size_t packet_buflen, size_t *packet_len);
int protocol_unpack(const uint8_t *key,
                    const uint8_t *packet, size_t packet_len,
                    uint8_t *plaintext, size_t plaintext_buflen, size_t *plaintext_len);

#endif
