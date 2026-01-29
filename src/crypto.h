#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

uint8_t  crc8_ccitt(const uint8_t *data, size_t len);
uint16_t crc16_arc(const uint8_t *data, size_t len);

void generate_session_key(const uint8_t seed[2], const uint8_t srand[16],
                          uint8_t out[16]);

uint8_t *aes_encrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len);

uint8_t *aes_decrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len);

void generate_auth_payload(const char *user_id, const char *device_sn,
                           uint8_t out[32]);

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif
