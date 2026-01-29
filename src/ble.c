#include "ble.h"
#include "crypto.h"
#include "protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <systemd/sd-bus.h>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

/* ── Constants ───────────────────────────────────────────────────── */

#define BLUEZ_SERVICE       "org.bluez"
#define ADAPTER_IFACE       "org.bluez.Adapter1"
#define DEVICE_IFACE        "org.bluez.Device1"
#define GATT_CHAR_IFACE     "org.bluez.GattCharacteristic1"
#define GATT_SERVICE_IFACE  "org.bluez.GattService1"
#define DBUS_OM_IFACE       "org.freedesktop.DBus.ObjectManager"
#define DBUS_PROP_IFACE     "org.freedesktop.DBus.Properties"

#define NOTIFY_UUID "00000003-0000-1000-8000-00805f9b34fb"
#define WRITE_UUID  "00000002-0000-1000-8000-00805f9b34fb"

#define ECOFLOW_MFR_ID      0xB5B5

static const char *RIVER3_PREFIXES[] = {
    "R631", "R651", "R653", "R654", "R655", NULL
};

/* ── Logging ─────────────────────────────────────────────────────── */

#define LOG_INFO(...)  fprintf(stderr, "[INFO] " __VA_ARGS__), fprintf(stderr, "\n")
#define LOG_ERR(...)   fprintf(stderr, "[ERROR] " __VA_ARGS__), fprintf(stderr, "\n")
#define LOG_DBG(...)   ((void)0)

/* ── Connection state ────────────────────────────────────────────── */

struct BLEConn {
    sd_bus *bus;
    char    device_path[256];
    char    notify_path[256];
    char    write_path[256];
    char    adapter_path[64];

    /* Auth */
    char    device_sn[64];
    char    user_id[64];
    bool    authenticated;
    bool    running;

    /* Crypto state */
    EVP_PKEY *our_key;
    uint8_t   shared_key[20]; /* secp160r1 => 20 bytes max */
    size_t    shared_key_len;
    uint8_t   iv[16];
    uint8_t   session_key[16];
    bool      has_session_key;

    /* Data */
    uint8_t   recv_buf[4096];
    size_t    recv_len;
    River3Status latest_status;
    bool         has_status;

    /* Callback */
    ble_status_cb  status_cb;
    void          *status_cb_user;

    /* Signal slots */
    sd_bus_slot *prop_slot;
};

/* ── Helpers ─────────────────────────────────────────────────────── */

static int get_ecdh_size(int curve_num)
{
    switch (curve_num) {
    case 1: return 52;
    case 2: return 56;
    case 3: return 64;
    case 4: return 64;
    default: return 40;
    }
}

/* Convert "XX:XX:XX:XX:XX:XX" to D-Bus path component "dev_XX_XX_XX_XX_XX_XX" */
static void addr_to_path(const char *addr, char *out)
{
    strcpy(out, "dev_");
    size_t j = 4;
    for (size_t i = 0; addr[i]; i++) {
        out[j++] = (addr[i] == ':') ? '_' : addr[i];
    }
    out[j] = '\0';
}

/* Find GATT characteristic path by UUID under the device path. */
static bool find_char_path(sd_bus *bus, const char *dev_path,
                           const char *uuid, char *out, size_t out_size)
{
    sd_bus_message *reply = NULL;
    int r = sd_bus_call_method(bus, BLUEZ_SERVICE, "/",
                               DBUS_OM_IFACE, "GetManagedObjects",
                               NULL, &reply, "");
    if (r < 0) return false;

    /* Iterate: a{oa{sa{sv}}} */
    r = sd_bus_message_enter_container(reply, 'a', "{oa{sa{sv}}}");
    if (r < 0) goto out;

    while (sd_bus_message_enter_container(reply, 'e', "oa{sa{sv}}") > 0) {
        const char *path = NULL;
        sd_bus_message_read(reply, "o", &path);

        /* Only look under our device path */
        if (!path || strncmp(path, dev_path, strlen(dev_path)) != 0) {
            sd_bus_message_skip(reply, "a{sa{sv}}");
            sd_bus_message_exit_container(reply);
            continue;
        }

        /* Iterate interfaces */
        sd_bus_message_enter_container(reply, 'a', "{sa{sv}}");
        while (sd_bus_message_enter_container(reply, 'e', "sa{sv}") > 0) {
            const char *iface = NULL;
            sd_bus_message_read(reply, "s", &iface);

            if (iface && strcmp(iface, GATT_CHAR_IFACE) == 0) {
                /* Check UUID property */
                sd_bus_message_enter_container(reply, 'a', "{sv}");
                while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
                    const char *prop = NULL;
                    sd_bus_message_read(reply, "s", &prop);
                    if (prop && strcmp(prop, "UUID") == 0) {
                        const char *val = NULL;
                        sd_bus_message_read(reply, "v", "s", &val);
                        if (val && strcasecmp(val, uuid) == 0) {
                            snprintf(out, out_size, "%s", path);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_exit_container(reply);
                            sd_bus_message_unref(reply);
                            return true;
                        }
                    } else {
                        sd_bus_message_skip(reply, "v");
                    }
                    sd_bus_message_exit_container(reply);
                }
                sd_bus_message_exit_container(reply);
            } else {
                sd_bus_message_skip(reply, "a{sv}");
            }
            sd_bus_message_exit_container(reply);
        }
        sd_bus_message_exit_container(reply);
        sd_bus_message_exit_container(reply);
    }
    sd_bus_message_exit_container(reply);

out:
    sd_bus_message_unref(reply);
    return false;
}

/* Write raw bytes to a GATT characteristic. */
static int gatt_write(sd_bus *bus, const char *char_path,
                      const uint8_t *data, size_t len)
{
    sd_bus_message *msg = NULL;
    int r = sd_bus_message_new_method_call(bus, &msg, BLUEZ_SERVICE,
                                           char_path, GATT_CHAR_IFACE,
                                           "WriteValue");
    if (r < 0) return r;

    r = sd_bus_message_append_array(msg, 'y', data, len);
    if (r < 0) { sd_bus_message_unref(msg); return r; }

    /* Options dict: a{sv} (empty) */
    r = sd_bus_message_open_container(msg, 'a', "{sv}");
    if (r < 0) { sd_bus_message_unref(msg); return r; }
    r = sd_bus_message_close_container(msg);
    if (r < 0) { sd_bus_message_unref(msg); return r; }

    sd_bus_error error = SD_BUS_ERROR_NULL;
    r = sd_bus_call(bus, msg, 5000000, &error, NULL);
    if (r < 0)
        LOG_ERR("WriteValue failed: %s", error.message ? error.message : "?");
    sd_bus_error_free(&error);
    sd_bus_message_unref(msg);
    return r;
}

/* Start or stop notifications on a characteristic. */
static int gatt_notify(sd_bus *bus, const char *char_path, bool start)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = sd_bus_call_method(bus, BLUEZ_SERVICE, char_path,
                               GATT_CHAR_IFACE,
                               start ? "StartNotify" : "StopNotify",
                               &error, NULL, "");
    if (r < 0 && start)
        LOG_ERR("%s failed: %s",
                start ? "StartNotify" : "StopNotify",
                error.message ? error.message : "?");
    sd_bus_error_free(&error);
    return r;
}

/* ── ECDH key generation (secp160r1) — OpenSSL 3.0+ EVP API ─────── */

/*
 * Generate ECDH keypair on secp160r1.
 * pub_out: 40-byte buffer for raw public key (x || y, no 0x04 prefix)
 * Returns EVP_PKEY* (caller owns) or NULL.
 */
static EVP_PKEY *ecdh_generate(uint8_t pub_out[40])
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) return NULL;

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto fail;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)"secp160r1", 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0)
        goto fail;

    if (EVP_PKEY_generate(pctx, &pkey) <= 0)
        goto fail;

    /* Extract uncompressed public key: 0x04 || x(20) || y(20) = 41 bytes */
    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, &pub_len) <= 0)
        goto fail_key;

    uint8_t pub_buf[65]; /* max uncompressed EC point */
    if (pub_len > sizeof(pub_buf))
        goto fail_key;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub_buf, sizeof(pub_buf), &pub_len) <= 0)
        goto fail_key;

    /* Skip the 0x04 uncompressed prefix */
    if (pub_len >= 41 && pub_buf[0] == 0x04)
        memcpy(pub_out, pub_buf + 1, 40);
    else
        memcpy(pub_out, pub_buf, pub_len < 40 ? pub_len : 40);

    EVP_PKEY_CTX_free(pctx);
    return pkey;

fail_key:
    EVP_PKEY_free(pkey);
fail:
    EVP_PKEY_CTX_free(pctx);
    return NULL;
}

/*
 * Compute ECDH shared secret from our private key and the peer's raw
 * public key bytes (x || y, each 20 bytes for secp160r1).
 * out: buffer for shared secret, out_len set to actual length.
 * Returns true on success.
 */
static bool ecdh_compute(EVP_PKEY *our_key, const uint8_t *peer_pub,
                         size_t peer_len, uint8_t *out, size_t *out_len)
{
    /* Build uncompressed point: 0x04 || peer_pub */
    uint8_t point[65];
    point[0] = 0x04;
    memcpy(point + 1, peer_pub, peer_len);
    size_t point_len = 1 + peer_len;

    /* Build peer EVP_PKEY from raw public key */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) return false;

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    "secp160r1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                     point, point_len);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return false;

    EVP_PKEY_CTX *fromdata_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *peer_pkey = NULL;
    bool ok = false;

    if (!fromdata_ctx) goto done_params;
    if (EVP_PKEY_fromdata_init(fromdata_ctx) <= 0) goto done_fromdata;
    if (EVP_PKEY_fromdata(fromdata_ctx, &peer_pkey,
                          EVP_PKEY_PUBLIC_KEY, params) <= 0)
        goto done_fromdata;

    /* Derive shared secret */
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!derive_ctx) goto done_peer;

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) goto done_derive;
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pkey) <= 0) goto done_derive;

    size_t slen = 0;
    if (EVP_PKEY_derive(derive_ctx, NULL, &slen) <= 0) goto done_derive;
    if (slen > 20) slen = 20;
    if (EVP_PKEY_derive(derive_ctx, out, &slen) <= 0) goto done_derive;

    *out_len = slen;
    ok = true;

done_derive:
    EVP_PKEY_CTX_free(derive_ctx);
done_peer:
    EVP_PKEY_free(peer_pkey);
done_fromdata:
    EVP_PKEY_CTX_free(fromdata_ctx);
done_params:
    OSSL_PARAM_free(params);
    return ok;
}

/* ── Enc packet response parsing ─────────────────────────────────── */

/* Parse a simple (unencrypted) enc-packet response.
 * Returns pointer into data for the payload, sets *payload_len.
 * Returns NULL on CRC error or if too short.
 */
static const uint8_t *parse_enc_response(const uint8_t *data, size_t len,
                                         size_t *payload_len)
{
    if (len < 8) return NULL;
    uint16_t plen = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    size_t data_end = 6 + plen;
    if (data_end > len) return NULL;

    const uint8_t *payload = data + 6;
    size_t pl = plen - 2; /* subtract trailing CRC */

    uint16_t stored_crc = (uint16_t)data[data_end - 2] |
                          ((uint16_t)data[data_end - 1] << 8);
    if (crc16_arc(data, data_end - 2) != stored_crc)
        return NULL;

    *payload_len = pl;
    return payload;
}

/* ── Authentication ──────────────────────────────────────────────── */

/* Send data, then poll for a notification response. Returns response
 * length in resp_buf, or -1 on timeout. */
static int send_and_poll(BLEConn *conn, const uint8_t *data, size_t len,
                         uint8_t *resp_buf, size_t resp_size,
                         int timeout_ms)
{
    /* StartNotify */
    gatt_notify(conn->bus, conn->notify_path, true);

    /* Small delay for BlueZ to set up */
    struct timespec ts = {0, 50000000}; /* 50ms */
    nanosleep(&ts, NULL);

    /* Write */
    if (gatt_write(conn->bus, conn->write_path, data, len) < 0)
        return -1;

    /* Poll for PropertiesChanged on notify char */
    uint64_t deadline = 0;
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000
                   + (uint64_t)timeout_ms;
    }

    int got = -1;
    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t now_ms = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
        if (now_ms >= deadline) break;

        int r = sd_bus_process(conn->bus, NULL);
        if (r < 0) break;
        if (r > 0) continue; /* more to process */

        /* Check if Value property changed */
        sd_bus_message *prop_msg = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        r = sd_bus_get_property(conn->bus, BLUEZ_SERVICE,
                                conn->notify_path, GATT_CHAR_IFACE,
                                "Value", &error, &prop_msg, "ay");
        sd_bus_error_free(&error);
        if (r >= 0 && prop_msg) {
            const void *arr = NULL;
            size_t arr_len = 0;
            r = sd_bus_message_read_array(prop_msg, 'y', &arr, &arr_len);
            if (r >= 0 && arr_len > 0) {
                size_t copy = arr_len < resp_size ? arr_len : resp_size;
                memcpy(resp_buf, arr, copy);
                got = (int)copy;
                sd_bus_message_unref(prop_msg);
                break;
            }
            sd_bus_message_unref(prop_msg);
        }

        uint64_t remain = deadline - now_ms;
        if (remain > 200) remain = 200;
        sd_bus_wait(conn->bus, remain * 1000);
    }

    gatt_notify(conn->bus, conn->notify_path, false);
    return got;
}

static bool authenticate(BLEConn *conn)
{
    uint8_t resp[512];

    /* Step 1: Public key exchange */
    LOG_INFO("Step 1: Public key exchange");
    uint8_t our_pub[40];
    conn->our_key = ecdh_generate(our_pub);
    if (!conn->our_key) {
        LOG_ERR("Failed to generate ECDH key");
        return false;
    }

    /* Build command: 0x01 0x00 <40-byte pubkey> */
    uint8_t cmd1[42];
    cmd1[0] = 0x01;
    cmd1[1] = 0x00;
    memcpy(cmd1 + 2, our_pub, 40);

    size_t enc_len = 0;
    uint8_t *pkt1 = enc_packet_build(cmd1, 42, FRAME_TYPE_COMMAND, NULL, NULL, &enc_len);
    if (!pkt1) return false;

    int rlen = send_and_poll(conn, pkt1, enc_len, resp, sizeof(resp), 5000);
    free(pkt1);
    if (rlen <= 0) {
        LOG_ERR("No response to public key exchange");
        return false;
    }

    /* Parse response */
    size_t payload_len = 0;
    const uint8_t *payload = parse_enc_response(resp, (size_t)rlen, &payload_len);
    if (!payload || payload_len < 43) {
        LOG_ERR("Invalid public key response (%d bytes)", rlen);
        return false;
    }

    int ecdh_size = get_ecdh_size(payload[2]);
    const uint8_t *peer_pub = payload + 3;

    /* Compute shared secret */
    if (!ecdh_compute(conn->our_key, peer_pub, (size_t)ecdh_size,
                      conn->shared_key, &conn->shared_key_len)) {
        LOG_ERR("ECDH compute failed");
        return false;
    }

    /* IV = MD5(shared_key) */
    md5_hash(conn->shared_key, conn->shared_key_len, conn->iv);

    /* Truncate shared key to 16 bytes for AES */
    if (conn->shared_key_len > 16)
        conn->shared_key_len = 16;

    LOG_INFO("Shared key established");

    /* Step 2: Request session key */
    LOG_INFO("Step 2: Request session key");
    uint8_t cmd2 = 0x02;
    uint8_t *pkt2 = enc_packet_build(&cmd2, 1, FRAME_TYPE_COMMAND, NULL, NULL, &enc_len);
    if (!pkt2) return false;

    rlen = send_and_poll(conn, pkt2, enc_len, resp, sizeof(resp), 5000);
    free(pkt2);
    if (rlen <= 0) {
        LOG_ERR("No response to key info request");
        return false;
    }

    payload = parse_enc_response(resp, (size_t)rlen, &payload_len);
    if (!payload || payload_len < 2 || payload[0] != 0x02) {
        LOG_ERR("Unexpected key info response");
        return false;
    }

    /* Decrypt payload[1..] with shared_key/iv to get sRand(16) + seed(2) */
    size_t dec_len = 0;
    uint8_t *dec = aes_decrypt(payload + 1, payload_len - 1,
                               conn->shared_key, conn->iv, &dec_len);
    if (!dec || dec_len < 18) {
        LOG_ERR("Failed to decrypt key info");
        free(dec);
        return false;
    }

    uint8_t srand_bytes[16];
    uint8_t seed[2];
    memcpy(srand_bytes, dec, 16);
    memcpy(seed, dec + 16, 2);
    free(dec);

    generate_session_key(seed, srand_bytes, conn->session_key);
    conn->has_session_key = true;
    LOG_INFO("Session key generated");

    /* Step 3: Check auth status */
    LOG_INFO("Step 3: Check auth status");
    Packet p3;
    packet_init(&p3);
    p3.src     = 0x21;
    p3.dst     = 0x35;
    p3.cmd_set = 0x35;
    p3.cmd_id  = 0x89;
    p3.dsrc    = 0x01;
    p3.ddst    = 0x01;

    uint8_t p3buf[64];
    size_t p3len = packet_to_bytes(&p3, p3buf, sizeof(p3buf));

    uint8_t *pkt3 = enc_packet_build(p3buf, p3len, FRAME_TYPE_PROTOCOL,
                                     conn->session_key, conn->iv, &enc_len);
    if (!pkt3) return false;

    /* Just send, don't need to parse response */
    gatt_notify(conn->bus, conn->notify_path, true);
    struct timespec ts50 = {0, 50000000};
    nanosleep(&ts50, NULL);
    gatt_write(conn->bus, conn->write_path, pkt3, enc_len);
    free(pkt3);

    /* Brief wait */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    /* Step 4: Send authentication */
    LOG_INFO("Step 4: Authenticate");
    uint8_t auth_payload[32];
    generate_auth_payload(conn->user_id, conn->device_sn, auth_payload);

    Packet p4;
    packet_init(&p4);
    p4.src         = 0x21;
    p4.dst         = 0x35;
    p4.cmd_set     = 0x35;
    p4.cmd_id      = 0x86;
    p4.dsrc        = 0x01;
    p4.ddst        = 0x01;
    p4.payload     = auth_payload;
    p4.payload_len = 32;

    uint8_t p4buf[128];
    size_t p4len = packet_to_bytes(&p4, p4buf, sizeof(p4buf));

    uint8_t *pkt4 = enc_packet_build(p4buf, p4len, FRAME_TYPE_PROTOCOL,
                                     conn->session_key, conn->iv, &enc_len);
    if (!pkt4) return false;

    /* Notification listener stays on from step 3 */
    gatt_write(conn->bus, conn->write_path, pkt4, enc_len);
    free(pkt4);

    /* Wait for auth confirmation via notifications */
    {
        struct timespec deadline_ts;
        clock_gettime(CLOCK_MONOTONIC, &deadline_ts);
        uint64_t deadline = (uint64_t)deadline_ts.tv_sec * 1000 +
                            (uint64_t)deadline_ts.tv_nsec / 1000000 + 3000;

        while (!conn->authenticated) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            uint64_t now_ms = (uint64_t)now.tv_sec * 1000 +
                              (uint64_t)now.tv_nsec / 1000000;
            if (now_ms >= deadline) break;

            int r = sd_bus_process(conn->bus, NULL);
            if (r < 0) break;
            if (r == 0)
                sd_bus_wait(conn->bus, 100000); /* 100ms */
        }
    }

    return conn->authenticated;
}

/* ── Notification handler ────────────────────────────────────────── */

static void process_buffer(BLEConn *conn)
{
    while (conn->recv_len >= 8 &&
           conn->recv_buf[0] == ENC_PACKET_PREFIX_0 &&
           conn->recv_buf[1] == ENC_PACKET_PREFIX_1) {

        uint16_t plen = (uint16_t)conn->recv_buf[4] |
                        ((uint16_t)conn->recv_buf[5] << 8);
        size_t data_end = 6 + plen;

        if (conn->recv_len < data_end)
            break;

        const uint8_t *enc_payload = conn->recv_buf + 6;
        size_t enc_payload_len = plen - 2; /* subtract CRC */

        /* Consume from buffer */
        size_t remaining = conn->recv_len - data_end;
        if (remaining > 0)
            memmove(conn->recv_buf, conn->recv_buf + data_end, remaining);
        conn->recv_len = remaining;

        /* Decrypt */
        if (!conn->has_session_key)
            continue;

        size_t dec_len = 0;
        uint8_t *dec = aes_decrypt(enc_payload, enc_payload_len,
                                   conn->session_key, conn->iv, &dec_len);
        if (!dec) continue;

        /* Parse inner packet */
        Packet pkt;
        if (!packet_from_bytes(dec, dec_len, &pkt)) {
            free(dec);
            continue;
        }
        free(dec);

        /* Auth response */
        if (pkt.src == 0x35 && pkt.cmd_set == 0x35 && pkt.cmd_id == 0x86) {
            if (pkt.payload_len == 1 && pkt.payload[0] == 0x00) {
                LOG_INFO("Auth confirmed!");
                conn->authenticated = true;
            } else {
                LOG_ERR("Auth rejected");
            }
            free(pkt.payload);
            continue;
        }

        /* Skip non-data packets */
        if (pkt.cmd_set != 0xFE || pkt.cmd_id != 0x15) {
            free(pkt.payload);
            continue;
        }

        /* XOR decode */
        uint8_t xor_key = pkt.seq[0];
        if (xor_key != 0 && pkt.payload) {
            for (size_t i = 0; i < pkt.payload_len; i++)
                pkt.payload[i] ^= xor_key;
        }

        /* Only parse the main status packet (starts with field tag 0x08) */
        if (pkt.payload_len < 50 || !pkt.payload || pkt.payload[0] != 0x08) {
            free(pkt.payload);
            continue;
        }

        River3Status status;
        if (parse_river3_status(pkt.payload, pkt.payload_len, &status)) {
            /* Receiving status data means auth succeeded */
            if (!conn->authenticated) {
                LOG_INFO("Auth confirmed (status data received)");
                conn->authenticated = true;
            }
            conn->latest_status = status;
            conn->has_status = true;
            if (conn->status_cb)
                conn->status_cb(&status, conn->status_cb_user);
        }

        free(pkt.payload);
    }
}

static int on_properties_changed(sd_bus_message *msg, void *userdata,
                                 sd_bus_error *err)
{
    (void)err;
    BLEConn *conn = userdata;

    const char *iface = NULL;
    int r = sd_bus_message_read(msg, "s", &iface);
    if (r < 0 || !iface) return 0;
    if (strcmp(iface, GATT_CHAR_IFACE) != 0) return 0;

    /* Enter changed properties dict: a{sv} */
    r = sd_bus_message_enter_container(msg, 'a', "{sv}");
    if (r < 0) return 0;

    while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
        const char *prop = NULL;
        sd_bus_message_read(msg, "s", &prop);

        if (prop && strcmp(prop, "Value") == 0) {
            sd_bus_message_enter_container(msg, 'v', "ay");
            const void *arr = NULL;
            size_t arr_len = 0;
            sd_bus_message_read_array(msg, 'y', &arr, &arr_len);

            if (arr && arr_len > 0) {
                size_t space = sizeof(conn->recv_buf) - conn->recv_len;
                size_t copy = arr_len < space ? arr_len : space;
                memcpy(conn->recv_buf + conn->recv_len, arr, copy);
                conn->recv_len += copy;
                process_buffer(conn);
            }

            sd_bus_message_exit_container(msg);
        } else {
            sd_bus_message_skip(msg, "v");
        }
        sd_bus_message_exit_container(msg);
    }
    sd_bus_message_exit_container(msg);

    return 0;
}

/* ── Scan ────────────────────────────────────────────────────────── */

int ble_scan(EcoFlowDevice *devs, int max_devs, int timeout_sec)
{
    sd_bus *bus = NULL;
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        LOG_ERR("Failed to open system bus: %s", strerror(-r));
        return 0;
    }

    /* Find adapter */
    const char *adapter = "/org/bluez/hci0";

    /* Start discovery */
    sd_bus_error error = SD_BUS_ERROR_NULL;
    r = sd_bus_call_method(bus, BLUEZ_SERVICE, adapter,
                           ADAPTER_IFACE, "StartDiscovery",
                           &error, NULL, "");
    sd_bus_error_free(&error);
    if (r < 0) {
        LOG_ERR("StartDiscovery failed: %s", strerror(-r));
        sd_bus_unref(bus);
        return 0;
    }

    LOG_INFO("Scanning for %d seconds...", timeout_sec);

    /* Wait for scan duration, processing bus events */
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_sec;

    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > end.tv_sec ||
            (now.tv_sec == end.tv_sec && now.tv_nsec >= end.tv_nsec))
            break;

        r = sd_bus_process(bus, NULL);
        if (r < 0) break;
        if (r == 0)
            sd_bus_wait(bus, 500000); /* 500ms */
    }

    /* Stop discovery */
    error = SD_BUS_ERROR_NULL;
    sd_bus_call_method(bus, BLUEZ_SERVICE, adapter,
                       ADAPTER_IFACE, "StopDiscovery",
                       &error, NULL, "");
    sd_bus_error_free(&error);

    /* Enumerate discovered devices via GetManagedObjects */
    sd_bus_message *reply = NULL;
    error = SD_BUS_ERROR_NULL;
    r = sd_bus_call_method(bus, BLUEZ_SERVICE, "/",
                           DBUS_OM_IFACE, "GetManagedObjects",
                           &error, &reply, "");
    sd_bus_error_free(&error);
    if (r < 0) {
        sd_bus_unref(bus);
        return 0;
    }

    int found = 0;

    r = sd_bus_message_enter_container(reply, 'a', "{oa{sa{sv}}}");
    if (r < 0) goto scan_done;

    while (sd_bus_message_enter_container(reply, 'e', "oa{sa{sv}}") > 0) {
        const char *path = NULL;
        sd_bus_message_read(reply, "o", &path);

        char name[64] = "";
        char address[18] = "";
        int16_t rssi = 0;
        uint8_t mfr_data[64];
        size_t mfr_len = 0;
        bool has_ecoflow_mfr = false;

        sd_bus_message_enter_container(reply, 'a', "{sa{sv}}");
        while (sd_bus_message_enter_container(reply, 'e', "sa{sv}") > 0) {
            const char *iface = NULL;
            sd_bus_message_read(reply, "s", &iface);

            if (iface && strcmp(iface, DEVICE_IFACE) == 0) {
                sd_bus_message_enter_container(reply, 'a', "{sv}");
                while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
                    const char *prop = NULL;
                    sd_bus_message_read(reply, "s", &prop);

                    if (prop && strcmp(prop, "Name") == 0) {
                        const char *val = NULL;
                        sd_bus_message_read(reply, "v", "s", &val);
                        if (val) snprintf(name, sizeof(name), "%s", val);
                    } else if (prop && strcmp(prop, "Address") == 0) {
                        const char *val = NULL;
                        sd_bus_message_read(reply, "v", "s", &val);
                        if (val) snprintf(address, sizeof(address), "%s", val);
                    } else if (prop && strcmp(prop, "RSSI") == 0) {
                        sd_bus_message_read(reply, "v", "n", &rssi);
                    } else if (prop && strcmp(prop, "ManufacturerData") == 0) {
                        /* a{qv} - dict of uint16->variant(ay) */
                        sd_bus_message_enter_container(reply, 'v', "a{qv}");
                        sd_bus_message_enter_container(reply, 'a', "{qv}");
                        while (sd_bus_message_enter_container(reply, 'e', "qv") > 0) {
                            uint16_t mfr_id = 0;
                            sd_bus_message_read(reply, "q", &mfr_id);
                            if (mfr_id == ECOFLOW_MFR_ID) {
                                sd_bus_message_enter_container(reply, 'v', "ay");
                                const void *arr = NULL;
                                size_t arr_len = 0;
                                sd_bus_message_read_array(reply, 'y', &arr, &arr_len);
                                if (arr && arr_len > 0) {
                                    mfr_len = arr_len < sizeof(mfr_data) ? arr_len : sizeof(mfr_data);
                                    memcpy(mfr_data, arr, mfr_len);
                                    has_ecoflow_mfr = true;
                                }
                                sd_bus_message_exit_container(reply);
                            } else {
                                sd_bus_message_skip(reply, "v");
                            }
                            sd_bus_message_exit_container(reply);
                        }
                        sd_bus_message_exit_container(reply);
                        sd_bus_message_exit_container(reply);
                    } else {
                        sd_bus_message_skip(reply, "v");
                    }
                    sd_bus_message_exit_container(reply);
                }
                sd_bus_message_exit_container(reply);
            } else {
                sd_bus_message_skip(reply, "a{sv}");
            }
            sd_bus_message_exit_container(reply);
        }
        sd_bus_message_exit_container(reply);
        sd_bus_message_exit_container(reply);

        if (!has_ecoflow_mfr || found >= max_devs)
            continue;

        /* Extract serial from manufacturer data */
        char serial[32] = "Unknown";
        if (mfr_len >= 17)
            snprintf(serial, sizeof(serial), "%.*s", 16, (char *)mfr_data + 1);

        /* Check if River 3 */
        bool is_river3 = false;
        for (int i = 0; RIVER3_PREFIXES[i]; i++) {
            if (strncmp(serial, RIVER3_PREFIXES[i], strlen(RIVER3_PREFIXES[i])) == 0) {
                is_river3 = true;
                break;
            }
        }
        if (!is_river3) {
            const char *name_patterns[] = {"EF-R3", "R3PM", "R3P", NULL};
            for (int i = 0; name_patterns[i]; i++) {
                if (strstr(name, name_patterns[i])) {
                    is_river3 = true;
                    break;
                }
            }
        }
        if (!is_river3)
            continue;

        snprintf(devs[found].name, sizeof(devs[found].name), "%s",
                 name[0] ? name : "EcoFlow");
        snprintf(devs[found].address, sizeof(devs[found].address), "%s", address);
        snprintf(devs[found].serial, sizeof(devs[found].serial), "%s", serial);
        devs[found].rssi = rssi;
        if (path)
            snprintf(devs[found].obj_path, sizeof(devs[found].obj_path), "%s", path);
        found++;
    }

scan_done:
    sd_bus_message_unref(reply);
    sd_bus_unref(bus);
    return found;
}

/* ── Connect ─────────────────────────────────────────────────────── */

static bool wait_services_resolved(sd_bus *bus, const char *dev_path,
                                   int timeout_sec)
{
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_sec;

    while (1) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        int val = 0;
        int r = sd_bus_get_property_trivial(bus, BLUEZ_SERVICE, dev_path,
                                            DEVICE_IFACE, "ServicesResolved",
                                            &error, 'b', &val);
        sd_bus_error_free(&error);
        if (r >= 0 && val)
            return true;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > end.tv_sec ||
            (now.tv_sec == end.tv_sec && now.tv_nsec >= end.tv_nsec))
            return false;

        r = sd_bus_process(bus, NULL);
        if (r < 0) return false;
        if (r == 0)
            sd_bus_wait(bus, 500000);
    }
}

BLEConn *ble_connect(const char *device_address,
                     const char *device_sn,
                     const char *user_id,
                     ble_status_cb cb, void *cb_user)
{
    BLEConn *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    snprintf(conn->device_sn, sizeof(conn->device_sn), "%s", device_sn);
    snprintf(conn->user_id, sizeof(conn->user_id), "%s", user_id);
    conn->status_cb = cb;
    conn->status_cb_user = cb_user;
    snprintf(conn->adapter_path, sizeof(conn->adapter_path),
             "/org/bluez/hci0");

    int r = sd_bus_open_system(&conn->bus);
    if (r < 0) {
        LOG_ERR("Failed to open system bus: %s", strerror(-r));
        free(conn);
        return NULL;
    }

    /* Build device path */
    char dev_comp[64];
    addr_to_path(device_address, dev_comp);
    snprintf(conn->device_path, sizeof(conn->device_path),
             "%s/%s", conn->adapter_path, dev_comp);

    LOG_INFO("Connecting to %s (%s)...", device_address, conn->device_path);

    /* Start discovery so BlueZ creates the device object if needed */
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_call_method(conn->bus, BLUEZ_SERVICE, conn->adapter_path,
                       ADAPTER_IFACE, "StartDiscovery",
                       &error, NULL, "");
    sd_bus_error_free(&error);

    /* Wait for the device object to appear */
    {
        struct timespec disc_end;
        clock_gettime(CLOCK_MONOTONIC, &disc_end);
        disc_end.tv_sec += 10;

        while (1) {
            /* Check if device path exists by reading a property */
            sd_bus_error e2 = SD_BUS_ERROR_NULL;
            sd_bus_message *prop_msg = NULL;
            r = sd_bus_get_property(conn->bus, BLUEZ_SERVICE,
                                    conn->device_path, DEVICE_IFACE,
                                    "Address", &e2, &prop_msg, "s");
            sd_bus_error_free(&e2);
            sd_bus_message_unref(prop_msg);
            if (r >= 0)
                break;

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > disc_end.tv_sec ||
                (now.tv_sec == disc_end.tv_sec &&
                 now.tv_nsec >= disc_end.tv_nsec)) {
                LOG_ERR("Device not found within discovery timeout");
                error = SD_BUS_ERROR_NULL;
                sd_bus_call_method(conn->bus, BLUEZ_SERVICE,
                                   conn->adapter_path, ADAPTER_IFACE,
                                   "StopDiscovery", &error, NULL, "");
                sd_bus_error_free(&error);
                ble_disconnect(conn);
                return NULL;
            }

            r = sd_bus_process(conn->bus, NULL);
            if (r < 0) break;
            if (r == 0) sd_bus_wait(conn->bus, 500000);
        }
    }

    /* Stop discovery before connecting */
    error = SD_BUS_ERROR_NULL;
    sd_bus_call_method(conn->bus, BLUEZ_SERVICE, conn->adapter_path,
                       ADAPTER_IFACE, "StopDiscovery",
                       &error, NULL, "");
    sd_bus_error_free(&error);

    /* Connect */
    error = SD_BUS_ERROR_NULL;
    r = sd_bus_call_method(conn->bus, BLUEZ_SERVICE, conn->device_path,
                           DEVICE_IFACE, "Connect",
                           &error, NULL, "");
    if (r < 0) {
        LOG_ERR("Connect failed: %s", error.message ? error.message : strerror(-r));
        sd_bus_error_free(&error);
        ble_disconnect(conn);
        return NULL;
    }
    sd_bus_error_free(&error);

    LOG_INFO("Connected, waiting for services...");

    if (!wait_services_resolved(conn->bus, conn->device_path, 15)) {
        LOG_ERR("Timed out waiting for ServicesResolved");
        ble_disconnect(conn);
        return NULL;
    }

    LOG_INFO("Services resolved, finding characteristics...");

    /* Find GATT characteristic paths */
    if (!find_char_path(conn->bus, conn->device_path, NOTIFY_UUID,
                        conn->notify_path, sizeof(conn->notify_path))) {
        LOG_ERR("Notify characteristic not found");
        ble_disconnect(conn);
        return NULL;
    }
    if (!find_char_path(conn->bus, conn->device_path, WRITE_UUID,
                        conn->write_path, sizeof(conn->write_path))) {
        LOG_ERR("Write characteristic not found");
        ble_disconnect(conn);
        return NULL;
    }

    LOG_INFO("Characteristics found, authenticating...");

    /* Register PropertiesChanged handler for the notify characteristic */
    char match[512];
    snprintf(match, sizeof(match),
             "type='signal',sender='" BLUEZ_SERVICE "',"
             "interface='" DBUS_PROP_IFACE "',"
             "member='PropertiesChanged',"
             "path='%s'", conn->notify_path);

    r = sd_bus_add_match(conn->bus, &conn->prop_slot, match,
                         on_properties_changed, conn);
    if (r < 0) {
        LOG_ERR("Failed to add signal match: %s", strerror(-r));
        ble_disconnect(conn);
        return NULL;
    }

    if (!authenticate(conn)) {
        LOG_ERR("Authentication failed");
        ble_disconnect(conn);
        return NULL;
    }

    LOG_INFO("Authentication successful!");
    return conn;
}

/* ── Event loop ──────────────────────────────────────────────────── */

int ble_run(BLEConn *conn, int timeout_sec)
{
    if (!conn) return -1;
    conn->running = true;

    /* Make sure notifications are on */
    gatt_notify(conn->bus, conn->notify_path, true);

    uint64_t deadline = 0;
    if (timeout_sec > 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000
                   + (uint64_t)timeout_sec * 1000;
    }

    while (conn->running) {
        int r = sd_bus_process(conn->bus, NULL);
        if (r < 0) return r;
        if (r > 0) continue;

        if (timeout_sec > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            uint64_t now_ms = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
            if (now_ms >= deadline)
                break;
        }

        sd_bus_wait(conn->bus, 1000000); /* 1s */
    }

    return 0;
}

void ble_stop(BLEConn *conn)
{
    if (conn) conn->running = false;
}

const River3Status *ble_latest_status(const BLEConn *conn)
{
    return (conn && conn->has_status) ? &conn->latest_status : NULL;
}

bool ble_is_authenticated(const BLEConn *conn)
{
    return conn && conn->authenticated;
}

/* ── Disconnect ──────────────────────────────────────────────────── */

void ble_disconnect(BLEConn *conn)
{
    if (!conn) return;

    if (conn->prop_slot) {
        sd_bus_slot_unref(conn->prop_slot);
        conn->prop_slot = NULL;
    }

    if (conn->bus && conn->notify_path[0])
        gatt_notify(conn->bus, conn->notify_path, false);

    if (conn->bus && conn->device_path[0]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_call_method(conn->bus, BLUEZ_SERVICE, conn->device_path,
                           DEVICE_IFACE, "Disconnect",
                           &error, NULL, "");
        sd_bus_error_free(&error);
    }

    if (conn->our_key) {
        EVP_PKEY_free(conn->our_key);
        conn->our_key = NULL;
    }

    if (conn->bus) {
        sd_bus_unref(conn->bus);
        conn->bus = NULL;
    }

    free(conn);
}
