#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Protocol constants ──────────────────────────────────────────── */

#define PACKET_PREFIX       0xAA
#define ENC_PACKET_PREFIX_0 0x5A
#define ENC_PACKET_PREFIX_1 0x5A

#define FRAME_TYPE_COMMAND  0x00
#define FRAME_TYPE_PROTOCOL 0x01

/* ── Inner packet ────────────────────────────────────────────────── */

typedef struct {
    uint8_t  src;
    uint8_t  dst;
    uint8_t  cmd_set;
    uint8_t  cmd_id;
    uint8_t  dsrc;
    uint8_t  ddst;
    uint8_t  version;
    uint8_t  seq[4];
    int      product_id;
    uint8_t *payload;
    size_t   payload_len;
} Packet;

/* Defaults: src=0x21 dst=0x01 dsrc=1 ddst=1 version=3 product_id=0 */
void packet_init(Packet *p);

/*
 * Serialize packet to caller-provided buffer.
 * Returns number of bytes written, or 0 on error.
 * buf must be large enough (payload_len + 22 is safe).
 */
size_t packet_to_bytes(const Packet *p, uint8_t *buf, size_t buf_size);

/*
 * Deserialize packet from bytes.
 * Payload is malloc'd; caller must free p->payload when done.
 * Returns true on success.
 */
bool packet_from_bytes(const uint8_t *data, size_t len, Packet *p);

/* ── Encrypted packet wrapper ────────────────────────────────────── */

/*
 * Build an encrypted packet.
 * inner      – raw payload (for COMMAND) or serialized Packet (for PROTOCOL)
 * inner_len  – length of inner
 * frame_type – FRAME_TYPE_COMMAND or FRAME_TYPE_PROTOCOL
 * enc_key/iv – if both non-NULL, AES-encrypt the inner payload
 *
 * Returns malloc'd buffer; caller must free(). *out_len set to total size.
 */
uint8_t *enc_packet_build(const uint8_t *inner, size_t inner_len,
                          uint8_t frame_type,
                          const uint8_t *enc_key, const uint8_t *iv,
                          size_t *out_len);

/* ── River 3 device status ───────────────────────────────────────── */

typedef struct {
    int     battery_level;       /* percentage */
    float   battery_temp;

    float   ac_input_power;      /* watts */
    float   ac_input_voltage;    /* volts */
    bool    ac_plugged_in;

    float   ac_output_power;
    bool    ac_output_enabled;

    float   dc_input_power;
    float   usb_output_power;
} River3Status;

static inline bool river3_grid_available(const River3Status *s)
{
    return s->ac_plugged_in || s->ac_input_power > 5.0f ||
           s->ac_input_voltage > 100.0f;
}

static inline bool river3_on_battery(const River3Status *s)
{
    return !river3_grid_available(s) && s->ac_output_power > 0;
}

/* ── Protobuf decoder ────────────────────────────────────────────── */

typedef struct {
    uint32_t field_num;
    uint8_t  wire_type; /* 0=varint, 1=fixed64, 5=fixed32 */
    union {
        uint64_t u64;
        float    f32;
        double   f64;
    } value;
} PBField;

/*
 * Decode protobuf fields from data.
 * fields must point to an array of at least max_fields entries.
 * Returns number of decoded fields (only varint/fixed32/fixed64 are kept).
 */
size_t protobuf_decode(const uint8_t *data, size_t len,
                       PBField *fields, size_t max_fields);

/*
 * Parse River3Status from protobuf-encoded payload.
 * Returns true if at least one field was parsed.
 */
bool parse_river3_status(const uint8_t *data, size_t len, River3Status *out);

#endif /* PROTOCOL_H */
