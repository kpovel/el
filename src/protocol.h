#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PACKET_PREFIX       0xAA
#define ENC_PACKET_PREFIX_0 0x5A
#define ENC_PACKET_PREFIX_1 0x5A

#define FRAME_TYPE_COMMAND  0x00
#define FRAME_TYPE_PROTOCOL 0x01

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

void packet_init(Packet *p);
size_t packet_to_bytes(const Packet *p, uint8_t *buf, size_t buf_size);
bool packet_from_bytes(const uint8_t *data, size_t len, Packet *p);

uint8_t *enc_packet_build(const uint8_t *inner, size_t inner_len,
                          uint8_t frame_type,
                          const uint8_t *enc_key, const uint8_t *iv,
                          size_t *out_len);

typedef struct {
    int     battery_level;
    float   battery_temp;
    float   ac_input_power;
    float   ac_input_voltage;
    bool    ac_plugged_in;
    float   ac_output_power;
    bool    ac_output_enabled;
    float   dc_input_power;
    float   usb_output_power;
} River3Status;

static inline bool river3_grid_available(const River3Status *s)
{
    return s->ac_input_power > 5.0f;
}

static inline bool river3_on_battery(const River3Status *s)
{
    return !river3_grid_available(s) && s->ac_output_power > 0;
}

typedef struct {
    uint32_t field_num;
    uint8_t  wire_type;
    union {
        uint64_t u64;
        float    f32;
        double   f64;
    } value;
} PBField;

size_t protobuf_decode(const uint8_t *data, size_t len,
                       PBField *fields, size_t max_fields);

bool parse_river3_status(const uint8_t *data, size_t len, River3Status *out);

#endif
