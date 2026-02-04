import { createCipheriv, createDecipheriv, createHash } from "crypto";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { Field } from "@noble/curves/abstract/modular.js";
import { ecdh, weierstrass } from "@noble/curves/abstract/weierstrass.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const keydataPath = resolve(__dirname, "keydata.bin");
let keydataCache: Uint8Array | null = null;

const CURVE = {
  p: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"),
  n: BigInt("0x0100000000000000000001F4C8F927AED3CA752257"),
  h: BigInt(1),
  a: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC"),
  b: BigInt("0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45"),
  Gx: BigInt("0x4A96B5688EF573284664698968C38BB913CBFC82"),
  Gy: BigInt("0x23A628553168947D59DCC912042351377AC5FB32"),
};

const Fp = Field(CURVE.p);
const Point = weierstrass(CURVE, { Fp });
const { getPublicKey, getSharedSecret, utils } = ecdh(Point);

async function getKeydata(): Promise<Uint8Array> {
  if (!keydataCache) {
    keydataCache = new Uint8Array(await Bun.file(keydataPath).arrayBuffer());
  }
  return keydataCache;
}

export function crc8Ccitt(data: Uint8Array): number {
  let crc = 0x00;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let b = 0; b < 8; b++) {
      if (crc & 0x80) crc = ((crc << 1) ^ 0x07) & 0xff;
      else crc = (crc << 1) & 0xff;
    }
  }
  return crc;
}

export function crc16Arc(data: Uint8Array): number {
  let crc = 0x0000;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let b = 0; b < 8; b++) {
      if (crc & 1) crc = (crc >>> 1) ^ 0xa001;
      else crc >>>= 1;
    }
  }
  return crc & 0xffff;
}

export function md5(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("md5").update(data).digest());
}

export function aesEncrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return new Uint8Array(Buffer.concat([cipher.update(data), cipher.final()]));
}

export function aesDecrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  return new Uint8Array(
    Buffer.concat([decipher.update(data), decipher.final()]),
  );
}

export async function generateSessionKey(
  seed: Uint8Array,
  srandBytes: Uint8Array,
): Promise<Uint8Array> {
  const keydata = await getKeydata();
  const buf = new Uint8Array(32);

  const pos = seed[0] * 0x10 + ((seed[1] - 1) & 0xff) * 0x100;
  buf.set(keydata.subarray(pos, pos + 8), 0);
  buf.set(keydata.subarray(pos + 8, pos + 16), 8);
  buf.set(srandBytes.subarray(0, 16), 16);

  return md5(buf);
}

export function generateAuthPayload(
  userId: string,
  deviceSn: string,
): Uint8Array {
  const combined = new TextEncoder().encode(userId + deviceSn);
  const hash = md5(combined);
  const hex = Array.from(hash)
    .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
    .join("");
  return new TextEncoder().encode(hex);
}

export async function ecdhGenerateKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const privateKey = utils.randomSecretKey();
  const pub = getPublicKey(privateKey, false);
  const publicKey = pub.subarray(1);
  return { publicKey, privateKey };
}

export async function ecdhComputeShared(
  peerPublicRaw: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const point = new Uint8Array(41);
  point[0] = 0x04;
  point.set(peerPublicRaw.subarray(0, 40), 1);
  const shared = getSharedSecret(privateKey, point, false);
  return shared.subarray(1, 21);
}
