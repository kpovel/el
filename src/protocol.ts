import { crc8Ccitt, crc16Arc, aesEncrypt } from "./crypto.js";

const PACKET_PREFIX = 0xaa;
const ENC_PACKET_PREFIX_0 = 0x5a;
const ENC_PACKET_PREFIX_1 = 0x5a;

export const FRAME_TYPE_COMMAND = 0x00;
export const FRAME_TYPE_PROTOCOL = 0x01;

export interface Packet {
  src: number;
  dst: number;
  cmdSet: number;
  cmdId: number;
  dsrc: number;
  ddst: number;
  version: number;
  seq: Uint8Array;
  productId: number;
  payload: Uint8Array;
}

export function packetInit(): Packet {
  return {
    src: 0x21,
    dst: 0x01,
    dsrc: 1,
    ddst: 1,
    version: 3,
    seq: new Uint8Array(4),
    productId: 0,
    payload: new Uint8Array(0),
    cmdSet: 0,
    cmdId: 0,
  };
}

export function packetToBytes(p: Packet): Uint8Array {
  const hasExtraAddr = p.version >= 3;
  const need = 18 + (hasExtraAddr ? 2 : 0) + p.payload.length + 2;
  const buf = new Uint8Array(need);
  let pos = 0;

  buf[pos++] = PACKET_PREFIX;
  buf[pos++] = p.version;
  buf[pos++] = p.payload.length & 0xff;
  buf[pos++] = (p.payload.length >> 8) & 0xff;

  buf[pos] = crc8Ccitt(buf.subarray(0, 4));
  pos++;

  buf[pos++] = p.productId >= 0 ? 0x0d : 0x0c;

  buf.set(p.seq, pos);
  pos += 4;

  buf[pos++] = 0x00;
  buf[pos++] = 0x00;

  buf[pos++] = p.src;
  buf[pos++] = p.dst;

  if (hasExtraAddr) {
    buf[pos++] = p.dsrc;
    buf[pos++] = p.ddst;
  }

  buf[pos++] = p.cmdSet;
  buf[pos++] = p.cmdId;

  if (p.payload.length > 0) {
    buf.set(p.payload, pos);
  }
  pos += p.payload.length;

  const crc = crc16Arc(buf.subarray(0, pos));
  buf[pos++] = crc & 0xff;
  buf[pos++] = (crc >> 8) & 0xff;

  return buf.subarray(0, pos);
}

export function packetFromBytes(data: Uint8Array): Packet | null {
  if (data.length < 4 || data[0] !== PACKET_PREFIX) return null;

  const version = data[1];
  const minLen = version === 2 ? 18 : 20;
  if (data.length < minLen) return null;

  const payloadLength = data[2] | (data[3] << 8);

  if (version === 2 || version === 3 || version === 4) {
    const storedCrc = data[data.length - 2] | (data[data.length - 1] << 8);
    if (crc16Arc(data.subarray(0, data.length - 2)) !== storedCrc) return null;
  }

  if (crc8Ccitt(data.subarray(0, 4)) !== data[4]) return null;

  const seq = new Uint8Array(data.subarray(6, 10));
  const src = data[12];
  const dst = data[13];

  let dsrc: number, ddst: number, cmdSet: number, cmdId: number;
  let payloadStart: number;

  if (version === 2) {
    dsrc = 0;
    ddst = 0;
    cmdSet = data[14];
    cmdId = data[15];
    payloadStart = 16;
  } else {
    dsrc = data[14];
    ddst = data[15];
    cmdSet = data[16];
    cmdId = data[17];
    payloadStart = 18;
  }

  const payload = new Uint8Array(
    data.subarray(payloadStart, payloadStart + payloadLength),
  );

  return {
    version,
    seq,
    src,
    dst,
    dsrc,
    ddst,
    cmdSet,
    cmdId,
    productId: 0,
    payload,
  };
}

export function encPacketBuild(
  inner: Uint8Array,
  frameType: number,
  encKey?: Uint8Array,
  iv?: Uint8Array,
): Uint8Array {
  let payload = inner;
  if (encKey && iv) {
    payload = aesEncrypt(inner, encKey, iv);
  }

  const total = 6 + payload.length + 2;
  const buf = new Uint8Array(total);
  let pos = 0;

  buf[pos++] = ENC_PACKET_PREFIX_0;
  buf[pos++] = ENC_PACKET_PREFIX_1;
  buf[pos++] = frameType << 4;
  buf[pos++] = 0x01;
  const plen = payload.length + 2;
  buf[pos++] = plen & 0xff;
  buf[pos++] = (plen >> 8) & 0xff;

  buf.set(payload, pos);
  pos += payload.length;

  const crc = crc16Arc(buf.subarray(0, pos));
  buf[pos++] = crc & 0xff;
  buf[pos++] = (crc >> 8) & 0xff;

  return buf.subarray(0, pos);
}

interface PBField {
  fieldNum: number;
  wireType: number;
  value: number | bigint;
}

function readVarint(
  data: Uint8Array,
  pos: { v: number },
): bigint | null {
  let val = 0n;
  let shift = 0;
  while (pos.v < data.length) {
    const b = data[pos.v++];
    val |= BigInt(b & 0x7f) << BigInt(shift);
    if (!(b & 0x80)) return val;
    shift += 7;
    if (shift >= 64) return null;
  }
  return null;
}

function protobufDecode(data: Uint8Array): PBField[] {
  const fields: PBField[] = [];
  const pos = { v: 0 };

  while (pos.v < data.length) {
    const tag = readVarint(data, pos);
    if (tag === null) break;

    const fieldNum = Number(tag >> 3n);
    const wireType = Number(tag & 7n);

    if (wireType === 0) {
      const val = readVarint(data, pos);
      if (val === null) break;
      fields.push({ fieldNum, wireType, value: val });
    } else if (wireType === 5) {
      if (pos.v + 4 > data.length) break;
      const dv = new DataView(data.buffer, data.byteOffset + pos.v, 4);
      fields.push({ fieldNum, wireType, value: dv.getFloat32(0, true) });
      pos.v += 4;
    } else if (wireType === 1) {
      if (pos.v + 8 > data.length) break;
      const dv = new DataView(data.buffer, data.byteOffset + pos.v, 8);
      fields.push({ fieldNum, wireType, value: dv.getFloat64(0, true) });
      pos.v += 8;
    } else if (wireType === 2) {
      const length = readVarint(data, pos);
      if (length === null) break;
      pos.v += Number(length);
    } else {
      break;
    }
  }

  return fields;
}

export interface River3Status {
  batteryLevel: number;
  batteryTemp: number;
  acInputPower: number;
  acInputVoltage: number;
  acPluggedIn: boolean;
  acOutputPower: number;
  dcInputPower: number;
  usbOutputPower: number;
}

function findField(fields: PBField[], num: number): PBField | undefined {
  let last: PBField | undefined;
  for (const f of fields) {
    if (f.fieldNum === num) last = f;
  }
  return last;
}

function fieldFloat(fields: PBField[], num: number): number {
  const f = findField(fields, num);
  if (!f) return 0;
  return Number(f.value);
}

export function parseRiver3Status(data: Uint8Array): River3Status | null {
  const fields = protobufDecode(data);
  if (fields.length === 0) return null;

  const acInputVoltage = fieldFloat(fields, 227);
  const acInputPower = fieldFloat(fields, 54);
  const acOutputPower = fieldFloat(fields, 4);

  let batteryLevel = fieldFloat(fields, 262);
  if (batteryLevel === 0) batteryLevel = fieldFloat(fields, 4);

  return {
    acInputVoltage,
    acInputPower,
    acOutputPower,
    acPluggedIn: acInputPower > 0,
    batteryLevel,
    batteryTemp: fieldFloat(fields, 258),
    dcInputPower: fieldFloat(fields, 11),
    usbOutputPower: fieldFloat(fields, 12),
  };
}

export function gridAvailable(s: River3Status): boolean {
  return s.acInputPower > 1;
}

export {
  PACKET_PREFIX,
  ENC_PACKET_PREFIX_0,
  ENC_PACKET_PREFIX_1,
};
