#include "ble.h"
#include "crypto.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btstack.h"

#define LOG_INFO(...)  printf("[INFO] " __VA_ARGS__), printf("\n")
#define LOG_ERR(...)   printf("[ERROR] " __VA_ARGS__), printf("\n")

enum ble_state {
    BLE_IDLE,
    BLE_SCANNING,
    BLE_CONNECTING,
    BLE_DISC_CHARS,
    BLE_AUTH_PUBKEY,
    BLE_AUTH_SESSION_KEY,
    BLE_AUTH_CHECK,
    BLE_AUTH_PAYLOAD,
    BLE_AUTHENTICATED,
};

static struct {
    enum ble_state state;
    hci_con_handle_t conn_handle;

    char address[18], serial[64], user_id[64];
    bd_addr_t target_addr;

    gatt_client_service_t         service;
    gatt_client_characteristic_t  notify_char, write_char;
    gatt_client_notification_t    notify_listener;
    bool found_notify, found_write;

    uint8_t our_pubkey[40], our_privkey[20];
    uint8_t shared_key[20]; size_t shared_key_len;
    uint8_t iv[16], session_key[16];
    bool has_session_key, authenticated;

    uint8_t recv_buf[4096]; size_t recv_len;
    ble_status_cb cb; void *cb_user;
} g;

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

static void parse_addr(const char *str, bd_addr_t addr)
{
    unsigned int a[6];
    sscanf(str, "%x:%x:%x:%x:%x:%x",
           &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);
    for (int i = 0; i < 6; i++) addr[i] = (uint8_t)a[i];
}

static void reset_state(void)
{
    g.state = BLE_IDLE;
    g.conn_handle = HCI_CON_HANDLE_INVALID;
    g.found_notify = false;
    g.found_write = false;
    g.has_session_key = false;
    g.authenticated = false;
    g.recv_len = 0;
    memset(&g.service, 0, sizeof(g.service));
    memset(&g.notify_char, 0, sizeof(g.notify_char));
    memset(&g.write_char, 0, sizeof(g.write_char));
}

static void start_scan(void)
{
    g.state = BLE_SCANNING;
    gap_set_scan_params(1, 0x0030, 0x0030, 0);
    gap_start_scan();
    LOG_INFO("Scanning for %s...", g.address);
}

static void ble_packet_handler(uint8_t packet_type, uint16_t channel,
                               uint8_t *packet, uint16_t size);

static void gatt_write_value(const uint8_t *data, size_t len)
{
    gatt_client_write_value_of_characteristic(
        ble_packet_handler, g.conn_handle, g.write_char.value_handle,
        (uint16_t)len, (uint8_t *)data);
}

static void send_auth_pubkey(void)
{
    g.state = BLE_AUTH_PUBKEY;
    LOG_INFO("Step 1: Public key exchange");

    if (!ecdh_generate_keypair(g.our_pubkey, g.our_privkey)) {
        LOG_ERR("Failed to generate ECDH key");
        return;
    }

    uint8_t cmd[42];
    cmd[0] = 0x01;
    cmd[1] = 0x00;
    memcpy(cmd + 2, g.our_pubkey, 40);

    size_t enc_len = 0;
    uint8_t *pkt = enc_packet_build(cmd, 42, FRAME_TYPE_COMMAND,
                                    NULL, NULL, &enc_len);
    if (!pkt) return;
    gatt_write_value(pkt, enc_len);
    free(pkt);
}

static void send_session_key_request(void)
{
    g.state = BLE_AUTH_SESSION_KEY;
    LOG_INFO("Step 2: Request session key");

    uint8_t cmd = 0x02;
    size_t enc_len = 0;
    uint8_t *pkt = enc_packet_build(&cmd, 1, FRAME_TYPE_COMMAND,
                                    NULL, NULL, &enc_len);
    if (!pkt) return;
    gatt_write_value(pkt, enc_len);
    free(pkt);
}

static void send_auth_check(void)
{
    g.state = BLE_AUTH_CHECK;
    LOG_INFO("Step 3: Check auth status");

    Packet p;
    packet_init(&p);
    p.src     = 0x21;
    p.dst     = 0x35;
    p.cmd_set = 0x35;
    p.cmd_id  = 0x89;
    p.dsrc    = 0x01;
    p.ddst    = 0x01;

    uint8_t buf[64];
    size_t len = packet_to_bytes(&p, buf, sizeof(buf));

    size_t enc_len = 0;
    uint8_t *pkt = enc_packet_build(buf, len, FRAME_TYPE_PROTOCOL,
                                    g.session_key, g.iv, &enc_len);
    if (!pkt) return;
    gatt_write_value(pkt, enc_len);
    free(pkt);
}

static void send_auth_payload_pkt(void)
{
    g.state = BLE_AUTH_PAYLOAD;
    LOG_INFO("Step 4: Authenticate");

    uint8_t auth_payload[32];
    generate_auth_payload(g.user_id, g.serial, auth_payload);

    Packet p;
    packet_init(&p);
    p.src         = 0x21;
    p.dst         = 0x35;
    p.cmd_set     = 0x35;
    p.cmd_id      = 0x86;
    p.dsrc        = 0x01;
    p.ddst        = 0x01;
    p.payload     = auth_payload;
    p.payload_len = 32;

    uint8_t buf[128];
    size_t len = packet_to_bytes(&p, buf, sizeof(buf));

    size_t enc_len = 0;
    uint8_t *pkt = enc_packet_build(buf, len, FRAME_TYPE_PROTOCOL,
                                    g.session_key, g.iv, &enc_len);
    if (!pkt) return;
    gatt_write_value(pkt, enc_len);
    free(pkt);
}

static const uint8_t *parse_enc_response(const uint8_t *data, size_t len,
                                         size_t *payload_len)
{
    if (len < 8) return NULL;
    uint16_t plen = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    size_t data_end = 6 + plen;
    if (data_end > len) return NULL;

    const uint8_t *payload = data + 6;
    size_t pl = plen - 2;

    uint16_t stored_crc = (uint16_t)data[data_end - 2] |
                          ((uint16_t)data[data_end - 1] << 8);
    if (crc16_arc(data, data_end - 2) != stored_crc)
        return NULL;

    *payload_len = pl;
    return payload;
}

static void handle_pubkey_response(const uint8_t *data, size_t len)
{
    size_t payload_len = 0;
    const uint8_t *payload = parse_enc_response(data, len, &payload_len);
    if (!payload || payload_len < 43) {
        LOG_ERR("Invalid public key response");
        return;
    }

    (void)get_ecdh_size(payload[2]);
    const uint8_t *peer_pub = payload + 3;

    if (!ecdh_compute_shared(peer_pub, g.our_privkey,
                             g.shared_key, &g.shared_key_len)) {
        LOG_ERR("ECDH compute failed");
        return;
    }

    md5_hash(g.shared_key, g.shared_key_len, g.iv);
    if (g.shared_key_len > 16)
        g.shared_key_len = 16;

    LOG_INFO("Shared key established");
    send_session_key_request();
}

static void handle_session_key_response(const uint8_t *data, size_t len)
{
    size_t payload_len = 0;
    const uint8_t *payload = parse_enc_response(data, len, &payload_len);
    if (!payload || payload_len < 2 || payload[0] != 0x02) {
        LOG_ERR("Unexpected key info response");
        return;
    }

    size_t dec_len = 0;
    uint8_t *dec = aes_decrypt(payload + 1, payload_len - 1,
                               g.shared_key, g.iv, &dec_len);
    if (!dec || dec_len < 18) {
        LOG_ERR("Failed to decrypt key info");
        free(dec);
        return;
    }

    uint8_t srand_bytes[16];
    uint8_t seed[2];
    memcpy(srand_bytes, dec, 16);
    memcpy(seed, dec + 16, 2);
    free(dec);

    generate_session_key(seed, srand_bytes, g.session_key);
    g.has_session_key = true;
    LOG_INFO("Session key generated");

    send_auth_check();
}

static void process_buffer(void)
{
    while (g.recv_len >= 8 &&
           g.recv_buf[0] == ENC_PACKET_PREFIX_0 &&
           g.recv_buf[1] == ENC_PACKET_PREFIX_1) {

        uint16_t plen = (uint16_t)g.recv_buf[4] |
                        ((uint16_t)g.recv_buf[5] << 8);
        size_t data_end = 6 + plen;

        if (g.recv_len < data_end)
            break;

        /* During auth handshake, route raw frames to auth handlers */
        if (g.state == BLE_AUTH_PUBKEY) {
            handle_pubkey_response(g.recv_buf, data_end);
            size_t remaining = g.recv_len - data_end;
            if (remaining > 0)
                memmove(g.recv_buf, g.recv_buf + data_end, remaining);
            g.recv_len = remaining;
            continue;
        }

        if (g.state == BLE_AUTH_SESSION_KEY) {
            handle_session_key_response(g.recv_buf, data_end);
            size_t remaining = g.recv_len - data_end;
            if (remaining > 0)
                memmove(g.recv_buf, g.recv_buf + data_end, remaining);
            g.recv_len = remaining;
            continue;
        }

        size_t enc_payload_len = plen - 2;
        uint8_t enc_copy[4096];
        memcpy(enc_copy, g.recv_buf + 6, enc_payload_len);

        size_t remaining = g.recv_len - data_end;
        if (remaining > 0)
            memmove(g.recv_buf, g.recv_buf + data_end, remaining);
        g.recv_len = remaining;

        if (!g.has_session_key)
            continue;

        size_t dec_len = 0;
        uint8_t *dec = aes_decrypt(enc_copy, enc_payload_len,
                                   g.session_key, g.iv, &dec_len);
        if (!dec) continue;

        Packet pkt;
        if (!packet_from_bytes(dec, dec_len, &pkt)) {
            free(dec);
            continue;
        }
        free(dec);

        if (pkt.src == 0x35 && pkt.cmd_set == 0x35 && pkt.cmd_id == 0x86) {
            if (pkt.payload_len == 1 && pkt.payload[0] == 0x00) {
                LOG_INFO("Auth confirmed!");
                g.authenticated = true;
                g.state = BLE_AUTHENTICATED;
            } else {
                LOG_ERR("Auth rejected");
            }
            free(pkt.payload);
            continue;
        }

        if (pkt.cmd_set != 0xFE || pkt.cmd_id != 0x15) {
            free(pkt.payload);
            continue;
        }

        uint8_t xor_key = pkt.seq[0];
        if (xor_key != 0 && pkt.payload) {
            for (size_t i = 0; i < pkt.payload_len; i++)
                pkt.payload[i] ^= xor_key;
        }

        if (pkt.payload_len < 50 || !pkt.payload || pkt.payload[0] != 0x08) {
            free(pkt.payload);
            continue;
        }

        River3Status status;
        if (parse_river3_status(pkt.payload, pkt.payload_len, &status)) {
            if (!g.authenticated) {
                LOG_INFO("Auth confirmed (status data received)");
                g.authenticated = true;
                g.state = BLE_AUTHENTICATED;
            }
            if (g.cb)
                g.cb(&status, g.cb_user);
        }

        free(pkt.payload);
    }
}

static btstack_timer_source_t auth_payload_timer;

static void auth_payload_timer_handler(btstack_timer_source_t *ts)
{
    (void)ts;
    send_auth_payload_pkt();
}

static void schedule_auth_payload(void)
{
    btstack_run_loop_set_timer(&auth_payload_timer, 1000);
    btstack_run_loop_set_timer_handler(&auth_payload_timer,
                                       auth_payload_timer_handler);
    btstack_run_loop_add_timer(&auth_payload_timer);
}

static btstack_timer_source_t reconnect_timer;

static void reconnect_timer_handler(btstack_timer_source_t *ts)
{
    (void)ts;
    start_scan();
}

static void schedule_reconnect(void)
{
    LOG_INFO("Will reconnect in 2s...");
    btstack_run_loop_set_timer(&reconnect_timer, 2000);
    btstack_run_loop_set_timer_handler(&reconnect_timer,
                                       reconnect_timer_handler);
    btstack_run_loop_add_timer(&reconnect_timer);
}

static btstack_packet_callback_registration_t hci_event_cb_reg;

static void ble_packet_handler(uint8_t packet_type, uint16_t channel,
                               uint8_t *packet, uint16_t size)
{
    (void)channel;
    (void)size;

    if (packet_type == HCI_EVENT_PACKET) {
        uint8_t event = hci_event_packet_get_type(packet);

        switch (event) {

        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING)
                start_scan();
            break;

        case GAP_EVENT_ADVERTISING_REPORT: {
            bd_addr_t addr;
            gap_event_advertising_report_get_address(packet, addr);
            if (memcmp(addr, g.target_addr, 6) != 0) break;

            LOG_INFO("Found device, connecting...");
            gap_stop_scan();
            g.state = BLE_CONNECTING;
            gap_connect(addr, (bd_addr_type_t)
                        gap_event_advertising_report_get_address_type(packet));
            break;
        }

        case HCI_EVENT_LE_META:
            switch (hci_event_le_meta_get_subevent_code(packet)) {
            case HCI_SUBEVENT_LE_CONNECTION_COMPLETE: {
                if (hci_subevent_le_connection_complete_get_status(packet) != 0) {
                    LOG_ERR("Connection failed (0x%02x)",
                            hci_subevent_le_connection_complete_get_status(packet));
                    schedule_reconnect();
                    break;
                }
                g.conn_handle =
                    hci_subevent_le_connection_complete_get_connection_handle(packet);
                LOG_INFO("Connected (handle 0x%04x)", g.conn_handle);

                /* Discover all characteristics over the full handle range
                 * instead of per-service, to avoid missing descriptors when
                 * the wrong service end_handle clips the CCCD search. */
                g.state = BLE_DISC_CHARS;
                g.service.start_group_handle = 0x0001;
                g.service.end_group_handle   = 0xFFFF;
                gatt_client_discover_characteristics_for_service(
                    ble_packet_handler, g.conn_handle, &g.service);
                break;
            }
            default:
                break;
            }
            break;

        case HCI_EVENT_DISCONNECTION_COMPLETE:
            LOG_INFO("Disconnected");
            reset_state();
            schedule_reconnect();
            break;

        case GATT_EVENT_SERVICE_QUERY_RESULT:
            /* Not used — we discover chars over full handle range */
            break;

        case GATT_EVENT_CHARACTERISTIC_QUERY_RESULT: {
            gatt_client_characteristic_t ch;
            gatt_event_characteristic_query_result_get_characteristic(packet, &ch);
            LOG_INFO("  char uuid16=0x%04x handle=%u-%u props=0x%02x",
                     ch.uuid16, ch.value_handle, ch.end_handle, ch.properties);
            if (ch.uuid16 == 0x0003) {
                g.notify_char = ch;
                g.found_notify = true;
            }
            if (ch.uuid16 == 0x0002) {
                g.write_char = ch;
                g.found_write = true;
            }
            break;
        }

        case GATT_EVENT_QUERY_COMPLETE: {
            uint8_t status = gatt_event_query_complete_get_att_status(packet);
            if (status != ATT_ERROR_SUCCESS) {
                LOG_ERR("GATT query failed (0x%02x)", status);
                break;
            }

            switch (g.state) {
            case BLE_DISC_CHARS:
                if (!g.found_notify || !g.found_write) {
                    LOG_ERR("Required characteristics not found");
                    gap_disconnect(g.conn_handle);
                    break;
                }
                LOG_INFO("Characteristics found, starting auth...");
                /* No CCCD on this device — it auto-notifies.
                 * Just register the listener and proceed. */
                gatt_client_listen_for_characteristic_value_updates(
                    &g.notify_listener, ble_packet_handler,
                    g.conn_handle, &g.notify_char);
                send_auth_pubkey();
                break;

            case BLE_AUTH_CHECK:
                schedule_auth_payload();
                break;

            default:
                break;
            }
            break;
        }

        case GATT_EVENT_NOTIFICATION: {
            uint16_t vlen = gatt_event_notification_get_value_length(packet);
            const uint8_t *val = gatt_event_notification_get_value(packet);

            size_t space = sizeof(g.recv_buf) - g.recv_len;
            size_t copy = vlen < space ? vlen : space;
            if (copy > 0) {
                memcpy(g.recv_buf + g.recv_len, val, copy);
                g.recv_len += copy;
            }
            process_buffer();
            break;
        }

        default:
            break;
        }
    }
}

void ble_init(const char *address, const char *serial,
              const char *user_id, ble_status_cb cb, void *cb_user)
{
    memset(&g, 0, sizeof(g));
    g.conn_handle = HCI_CON_HANDLE_INVALID;

    snprintf(g.address, sizeof(g.address), "%s", address);
    snprintf(g.serial, sizeof(g.serial), "%s", serial);
    snprintf(g.user_id, sizeof(g.user_id), "%s", user_id);
    g.cb = cb;
    g.cb_user = cb_user;

    parse_addr(address, g.target_addr);

    hci_event_cb_reg.callback = ble_packet_handler;
    hci_add_event_handler(&hci_event_cb_reg);
}
