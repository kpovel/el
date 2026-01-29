#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* CRC checksums matching EcoFlow protocol. */
uint8_t  crc8_ccitt(const uint8_t *data, size_t len);
uint16_t crc16_arc(const uint8_t *data, size_t len);

/*
 * Generate 16-byte session key from 2-byte seed and 16-byte sRand
 * using the keydata lookup table + MD5.
 * out must point to a 16-byte buffer.
 */
void generate_session_key(const uint8_t seed[2], const uint8_t srand[16],
                          uint8_t out[16]);

/*
 * AES-128-CBC encrypt with PKCS7 padding.
 * Returns malloc'd buffer; caller must free().
 * *out_len is set to the ciphertext length.
 */
uint8_t *aes_encrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len);

/*
 * AES-128-CBC decrypt with PKCS7 unpadding.
 * Returns malloc'd buffer; caller must free().
 * *out_len is set to the plaintext length.
 * Returns NULL on error.
 */
uint8_t *aes_decrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len);

/*
 * Generate 32-byte auth payload from user_id and device_sn strings.
 * out must point to a 32-byte buffer.
 * Result is the uppercase hex of MD5(user_id || device_sn) as ASCII bytes.
 */
void generate_auth_payload(const char *user_id, const char *device_sn,
                           uint8_t out[32]);

/*
 * Compute MD5 hash.
 * out must point to a 16-byte buffer.
 */
void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif /* CRYPTO_H */
