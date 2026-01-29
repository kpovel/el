#include "protocol.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>

void packet_init(Packet *p)
{
    memset(p, 0, sizeof(*p));
    p->src     = 0x21;
    p->dst     = 0x01;
    p->dsrc    = 1;
    p->ddst    = 1;
    p->version = 3;
}

size_t packet_to_bytes(const Packet *p, uint8_t *buf, size_t buf_size)
{
    size_t need = 18 + (p->version >= 3 ? 2 : 0) + p->payload_len + 2;
    if (buf_size < need)
        return 0;

    size_t pos = 0;

    buf[pos++] = PACKET_PREFIX;
    buf[pos++] = p->version;
    buf[pos++] = (uint8_t)(p->payload_len & 0xFF);
    buf[pos++] = (uint8_t)((p->payload_len >> 8) & 0xFF);

    buf[pos] = crc8_ccitt(buf, 4);
    pos++;

    buf[pos++] = (p->product_id >= 0) ? 0x0D : 0x0C;

    memcpy(buf + pos, p->seq, 4);
    pos += 4;

    buf[pos++] = 0x00;
    buf[pos++] = 0x00;

    buf[pos++] = p->src;
    buf[pos++] = p->dst;

    if (p->version >= 3) {
        buf[pos++] = p->dsrc;
        buf[pos++] = p->ddst;
    }

    buf[pos++] = p->cmd_set;
    buf[pos++] = p->cmd_id;

    if (p->payload_len > 0 && p->payload)
        memcpy(buf + pos, p->payload, p->payload_len);
    pos += p->payload_len;

    uint16_t crc = crc16_arc(buf, pos);
    buf[pos++] = (uint8_t)(crc & 0xFF);
    buf[pos++] = (uint8_t)((crc >> 8) & 0xFF);

    return pos;
}

bool packet_from_bytes(const uint8_t *data, size_t len, Packet *p)
{
    if (len < 4 || data[0] != PACKET_PREFIX)
        return false;

    uint8_t version = data[1];
    size_t min_len = (version == 2) ? 18 : 20;
    if (len < min_len)
        return false;

    uint16_t payload_length = (uint16_t)data[2] | ((uint16_t)data[3] << 8);

    if (version == 2 || version == 3 || version == 4) {
        uint16_t stored_crc = (uint16_t)data[len - 2] |
                              ((uint16_t)data[len - 1] << 8);
        if (crc16_arc(data, len - 2) != stored_crc)
            return false;
    }

    if (crc8_ccitt(data, 4) != data[4])
        return false;

    memset(p, 0, sizeof(*p));
    p->version = version;
    memcpy(p->seq, data + 6, 4);
    p->src = data[12];
    p->dst = data[13];

    size_t payload_start;
    if (version == 2) {
        p->dsrc = 0;
        p->ddst = 0;
        p->cmd_set = data[14];
        p->cmd_id  = data[15];
        payload_start = 16;
    } else {
        p->dsrc    = data[14];
        p->ddst    = data[15];
        p->cmd_set = data[16];
        p->cmd_id  = data[17];
        payload_start = 18;
    }

    p->payload_len = payload_length;
    p->payload = NULL;

    if (payload_length > 0) {
        p->payload = malloc(payload_length);
        if (!p->payload)
            return false;
        memcpy(p->payload, data + payload_start, payload_length);
    }

    return true;
}

uint8_t *enc_packet_build(const uint8_t *inner, size_t inner_len,
                          uint8_t frame_type,
                          const uint8_t *enc_key, const uint8_t *iv,
                          size_t *out_len)
{
    const uint8_t *payload = inner;
    size_t payload_len = inner_len;
    uint8_t *encrypted = NULL;

    if (enc_key && iv) {
        encrypted = aes_encrypt(inner, inner_len, enc_key, iv, &payload_len);
        if (!encrypted)
            return NULL;
        payload = encrypted;
    }

    size_t total = 6 + payload_len + 2;
    uint8_t *buf = malloc(total);
    if (!buf) {
        free(encrypted);
        return NULL;
    }

    size_t pos = 0;
    buf[pos++] = ENC_PACKET_PREFIX_0;
    buf[pos++] = ENC_PACKET_PREFIX_1;
    buf[pos++] = (uint8_t)(frame_type << 4);
    buf[pos++] = 0x01;
    uint16_t plen = (uint16_t)(payload_len + 2);
    buf[pos++] = (uint8_t)(plen & 0xFF);
    buf[pos++] = (uint8_t)((plen >> 8) & 0xFF);

    memcpy(buf + pos, payload, payload_len);
    pos += payload_len;

    uint16_t crc = crc16_arc(buf, pos);
    buf[pos++] = (uint8_t)(crc & 0xFF);
    buf[pos++] = (uint8_t)((crc >> 8) & 0xFF);

    free(encrypted);
    *out_len = pos;
    return buf;
}

static bool read_varint(const uint8_t *data, size_t len, size_t *pos,
                        uint64_t *val)
{
    *val = 0;
    int shift = 0;
    while (*pos < len) {
        uint8_t b = data[(*pos)++];
        *val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80))
            return true;
        shift += 7;
        if (shift >= 64)
            return false;
    }
    return false;
}

size_t protobuf_decode(const uint8_t *data, size_t len,
                       PBField *fields, size_t max_fields)
{
    size_t pos = 0, count = 0;

    while (pos < len && count < max_fields) {
        uint64_t tag;
        if (!read_varint(data, len, &pos, &tag))
            break;

        uint32_t field_num = (uint32_t)(tag >> 3);
        uint8_t  wire_type = (uint8_t)(tag & 0x07);

        if (wire_type == 0) {
            uint64_t val;
            if (!read_varint(data, len, &pos, &val))
                break;
            fields[count].field_num = field_num;
            fields[count].wire_type = 0;
            fields[count].value.u64 = val;
            count++;
        } else if (wire_type == 5) {
            if (pos + 4 > len) break;
            float fval;
            memcpy(&fval, data + pos, 4);
            pos += 4;
            fields[count].field_num = field_num;
            fields[count].wire_type = 5;
            fields[count].value.f32 = fval;
            count++;
        } else if (wire_type == 1) {
            if (pos + 8 > len) break;
            double dval;
            memcpy(&dval, data + pos, 8);
            pos += 8;
            fields[count].field_num = field_num;
            fields[count].wire_type = 1;
            fields[count].value.f64 = dval;
            count++;
        } else if (wire_type == 2) {
            uint64_t length;
            if (!read_varint(data, len, &pos, &length))
                break;
            pos += (size_t)length;
        } else {
            break;
        }
    }

    return count;
}

static const PBField *find_field(const PBField *fields, size_t count,
                                 uint32_t num)
{
    const PBField *last = NULL;
    for (size_t i = 0; i < count; i++) {
        if (fields[i].field_num == num)
            last = &fields[i];
    }
    return last;
}

static float field_float(const PBField *fields, size_t count, uint32_t num)
{
    const PBField *f = find_field(fields, count, num);
    if (!f) return 0.0f;
    if (f->wire_type == 5)
        return f->value.f32;
    return (float)f->value.u64;
}

bool parse_river3_status(const uint8_t *data, size_t len, River3Status *out)
{
    PBField fields[128];
    size_t count = protobuf_decode(data, len, fields, 128);
    if (count == 0)
        return false;

    memset(out, 0, sizeof(*out));

    out->ac_input_voltage = field_float(fields, count, 227);
    out->ac_input_power   = field_float(fields, count, 54);
    out->ac_output_power  = field_float(fields, count, 4);
    out->ac_plugged_in    = field_float(fields, count, 227) > 0;

    float batt = field_float(fields, count, 262);
    if (batt == 0)
        batt = field_float(fields, count, 4);
    out->battery_level = (int)batt;

    out->battery_temp     = field_float(fields, count, 258);
    out->dc_input_power   = field_float(fields, count, 11);
    out->usb_output_power = field_float(fields, count, 12);

    return true;
}
