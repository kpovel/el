#include "crypto.h"
#include "keydata.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <mbedtls/aes.h>
#include <mbedtls/md5.h>

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
    /* PKCS#7 padding */
    uint8_t pad = (uint8_t)(16 - (data_len % 16));
    size_t padded_len = data_len + pad;

    uint8_t *padded = malloc(padded_len);
    if (!padded) return NULL;
    memcpy(padded, data, data_len);
    memset(padded + data_len, pad, pad);

    uint8_t *out = malloc(padded_len);
    if (!out) { free(padded); return NULL; }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0)
        goto fail;
    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT,
                               padded_len, iv_copy, padded, out) != 0)
        goto fail;

    mbedtls_aes_free(&ctx);
    free(padded);
    *out_len = padded_len;
    return out;

fail:
    mbedtls_aes_free(&ctx);
    free(padded);
    free(out);
    return NULL;
}

uint8_t *aes_decrypt(const uint8_t *data, size_t data_len,
                     const uint8_t key[16], const uint8_t iv[16],
                     size_t *out_len)
{
    if (data_len == 0 || data_len % 16 != 0)
        return NULL;

    uint8_t *out = malloc(data_len);
    if (!out) return NULL;

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    if (mbedtls_aes_setkey_dec(&ctx, key, 128) != 0)
        goto fail;
    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT,
                               data_len, iv_copy, data, out) != 0)
        goto fail;

    mbedtls_aes_free(&ctx);

    /* Strip PKCS#7 padding */
    uint8_t pad = out[data_len - 1];
    if (pad == 0 || pad > 16)
        goto fail_out;
    for (size_t i = 0; i < pad; i++) {
        if (out[data_len - 1 - i] != pad)
            goto fail_out;
    }

    *out_len = data_len - pad;
    return out;

fail:
    mbedtls_aes_free(&ctx);
fail_out:
    free(out);
    return NULL;
}

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, data, len);
    mbedtls_md5_finish(&ctx, out);
    mbedtls_md5_free(&ctx);
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
