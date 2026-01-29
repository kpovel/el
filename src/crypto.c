#include "crypto.h"
#include "keydata.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/md5.h>

uint8_t crc8_ccitt(const uint8_t *data, size_t len)
{
    uint8_t crc = 0x00;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80)
                crc = (crc << 1) ^ 0x07;
            else
                crc <<= 1;
        }
    }
    return crc;
}

uint16_t crc16_arc(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (int b = 0; b < 8; b++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xA001;
            else
                crc >>= 1;
        }
    }
    return crc;
}

void generate_session_key(const uint8_t seed[2], const uint8_t srand_bytes[16],
                          uint8_t out[16])
{
    uint8_t buf[32];

    size_t pos = (size_t)seed[0] * 0x10 + (size_t)((seed[1] - 1) & 0xFF) * 0x100;
    memcpy(buf, keydata_get8bytes(pos), 8);
    memcpy(buf + 8, keydata_get8bytes(pos + 8), 8);
    memcpy(buf + 16, srand_bytes, 16);

    md5_hash(buf, 32, out);
}

uint8_t *aes_encrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    size_t max_len = data_len + 16;
    uint8_t *out = malloc(max_len);
    if (!out) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        goto fail;
    if (EVP_EncryptUpdate(ctx, out, &len, data, (int)data_len) != 1)
        goto fail;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1)
        goto fail;
    total += len;

    *out_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return out;

fail:
    EVP_CIPHER_CTX_free(ctx);
    free(out);
    return NULL;
}

uint8_t *aes_decrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    uint8_t *out = malloc(data_len);
    if (!out) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        goto fail;
    if (EVP_DecryptUpdate(ctx, out, &len, data, (int)data_len) != 1)
        goto fail;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, out + total, &len) != 1)
        goto fail;
    total += len;

    *out_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return out;

fail:
    EVP_CIPHER_CTX_free(ctx);
    free(out);
    return NULL;
}

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int md_len = 0;
    EVP_DigestFinal_ex(ctx, out, &md_len);
    EVP_MD_CTX_free(ctx);
}

void generate_auth_payload(const char *user_id, const char *device_sn,
                           uint8_t out[32])
{
    size_t uid_len = strlen(user_id);
    size_t sn_len  = strlen(device_sn);
    size_t total   = uid_len + sn_len;

    uint8_t *buf = malloc(total);
    memcpy(buf, user_id, uid_len);
    memcpy(buf + uid_len, device_sn, sn_len);

    uint8_t md5[16];
    md5_hash(buf, total, md5);
    free(buf);

    for (int i = 0; i < 16; i++)
        sprintf((char *)out + i * 2, "%02X", md5[i]);
}
