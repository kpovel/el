import dbus from "dbus-next";
import {
  md5,
  aesDecrypt,
  crc16Arc,
  ecdhGenerateKeypair,
  ecdhComputeShared,
  generateSessionKey,
  generateAuthPayload,
} from "./crypto.js";
import {
  type Packet,
  type River3Status,
  packetInit,
  packetToBytes,
  packetFromBytes,
  encPacketBuild,
  parseRiver3Status,
  FRAME_TYPE_COMMAND,
  FRAME_TYPE_PROTOCOL,
  ENC_PACKET_PREFIX_0,
  ENC_PACKET_PREFIX_1,
} from "./protocol.js";

const BLUEZ_SERVICE = "org.bluez";
const ADAPTER_IFACE = "org.bluez.Adapter1";
const DEVICE_IFACE = "org.bluez.Device1";
const GATT_CHAR_IFACE = "org.bluez.GattCharacteristic1";
const DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager";
const DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties";

const NOTIFY_UUID = "00000003-0000-1000-8000-00805f9b34fb";
const WRITE_UUID = "00000002-0000-1000-8000-00805f9b34fb";

const log = (msg: string) => process.stderr.write(`[INFO] ${msg}\n`);
const logErr = (msg: string) => process.stderr.write(`[ERROR] ${msg}\n`);

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function getEcdhSize(curveNum: number): number {
  switch (curveNum) {
    case 1: return 52;
    case 2: return 56;
    case 3: return 64;
    case 4: return 64;
    default: return 40;
  }
}

async function findCharPath(
  bus: dbus.MessageBus,
  devicePath: string,
  uuid: string,
): Promise<string | null> {
  const managed = await getManagedObjects(bus);

  for (const [path, ifaces] of Object.entries(managed)) {
    if (!path.startsWith(devicePath)) continue;
    const charIface = ifaces[GATT_CHAR_IFACE];
    if (!charIface) continue;
    const charUuid = charIface.UUID?.value as string | undefined;
    if (charUuid && charUuid.toLowerCase() === uuid.toLowerCase()) {
      return path;
    }
  }
  return null;
}

async function getManagedObjects(
  bus: dbus.MessageBus,
): Promise<Record<string, Record<string, Record<string, dbus.Variant>>>> {
  const obj = await bus.getProxyObject(BLUEZ_SERVICE, "/");
  const om = obj.getInterface(DBUS_OM_IFACE);
  return await om.GetManagedObjects();
}

function findDevicePathByAddress(
  managed: Record<string, Record<string, Record<string, dbus.Variant>>>,
  address: string,
): string | null {
  const target = address.toUpperCase();
  for (const [path, ifaces] of Object.entries(managed)) {
    const dev = ifaces[DEVICE_IFACE];
    if (!dev) continue;
    const addr = dev.Address?.value as string | undefined;
    if (addr && addr.toUpperCase() === target) return path;
  }
  return null;
}

async function getAdapterPath(bus: dbus.MessageBus): Promise<string | null> {
  const managed = await getManagedObjects(bus);
  for (const [path, ifaces] of Object.entries(managed)) {
    if (ifaces[ADAPTER_IFACE]) return path;
  }
  return null;
}

async function ensureAdapterPowered(
  bus: dbus.MessageBus,
  adapterPath: string,
): Promise<void> {
  const obj = await bus.getProxyObject(BLUEZ_SERVICE, adapterPath);
  const props = obj.getInterface(DBUS_PROP_IFACE);
  try {
    const powered: dbus.Variant = await props.Get(ADAPTER_IFACE, "Powered");
    if (powered.value === true) return;
  } catch {}
  await props.Set(ADAPTER_IFACE, "Powered", new dbus.Variant("b", true));
}

async function ensureDevicePath(
  bus: dbus.MessageBus,
  adapterPath: string,
  address: string,
  timeoutMs: number,
): Promise<string | null> {
  const managed = await getManagedObjects(bus);
  const existing = findDevicePathByAddress(managed, address);
  if (existing) return existing;

  const adapterObj = await bus.getProxyObject(BLUEZ_SERVICE, adapterPath);
  const adapter = adapterObj.getInterface(ADAPTER_IFACE);

  await adapter.StartDiscovery();
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const updated = await getManagedObjects(bus);
    const found = findDevicePathByAddress(updated, address);
    if (found) {
      try { await adapter.StopDiscovery(); } catch {}
      return found;
    }
    await sleep(500);
  }

  try { await adapter.StopDiscovery(); } catch {}
  return null;
}

async function gattWrite(
  bus: dbus.MessageBus,
  charPath: string,
  data: Uint8Array,
): Promise<void> {
  const obj = await bus.getProxyObject(BLUEZ_SERVICE, charPath);
  const char = obj.getInterface(GATT_CHAR_IFACE);
  await char.WriteValue(Array.from(data), {});
}

async function gattNotify(
  bus: dbus.MessageBus,
  charPath: string,
  start: boolean,
): Promise<void> {
  const obj = await bus.getProxyObject(BLUEZ_SERVICE, charPath);
  const char = obj.getInterface(GATT_CHAR_IFACE);
  if (start) await char.StartNotify();
  else await char.StopNotify();
}

async function waitServicesResolved(
  bus: dbus.MessageBus,
  devicePath: string,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const obj = await bus.getProxyObject(BLUEZ_SERVICE, devicePath);
      const props = obj.getInterface(DBUS_PROP_IFACE);
      const val: dbus.Variant = await props.Get(DEVICE_IFACE, "ServicesResolved");
      if (val.value === true) return true;
    } catch {}
    await sleep(500);
  }
  return false;
}

function parseEncResponse(
  data: Uint8Array,
): { payload: Uint8Array } | null {
  if (data.length < 8) return null;
  const plen = data[4] | (data[5] << 8);
  if (plen < 2) return null;
  const dataEnd = 6 + plen;
  if (dataEnd > data.length) return null;

  const storedCrc = data[dataEnd - 2] | (data[dataEnd - 1] << 8);
  const calcCrc = crc16Arc(data.subarray(0, dataEnd - 2));
  if (storedCrc !== calcCrc) return null;

  const payload = data.subarray(6, 6 + plen - 2);
  return { payload };
}

interface AuthState {
  sessionKey: Uint8Array;
  iv: Uint8Array;
}

async function sendAndPoll(
  bus: dbus.MessageBus,
  notifyPath: string,
  writePath: string,
  data: Uint8Array,
  timeoutMs: number,
): Promise<Uint8Array | null> {
  return new Promise(async (resolve) => {
    let resolved = false;
    const done = (result: Uint8Array | null) => {
      if (resolved) return;
      resolved = true;
      resolve(result);
    };

    const timer = setTimeout(() => done(null), timeoutMs);

    try {
      const notifyObj = await bus.getProxyObject(BLUEZ_SERVICE, notifyPath);
      const notifyProps = notifyObj.getInterface(DBUS_PROP_IFACE);

      const onChanged = (
        iface: string,
        changed: Record<string, dbus.Variant>,
      ) => {
        if (iface !== GATT_CHAR_IFACE) return;
        const val = changed.Value;
        if (!val) return;
        const bytes = val.value as number[];
        if (bytes && bytes.length > 0) {
          clearTimeout(timer);
          notifyProps.removeListener("PropertiesChanged", onChanged);
          done(new Uint8Array(bytes));
        }
      };

      notifyProps.on("PropertiesChanged", onChanged);
      await gattNotify(bus, notifyPath, true);
      await sleep(50);
      await gattWrite(bus, writePath, data);
    } catch (e) {
      clearTimeout(timer);
      done(null);
    }
  });
}

async function authenticate(
  bus: dbus.MessageBus,
  notifyPath: string,
  writePath: string,
  deviceSn: string,
  userId: string,
): Promise<AuthState | null> {
  log("Step 1: Public key exchange");
  const { publicKey: ourPub, privateKey } = await ecdhGenerateKeypair();

  const cmd1 = new Uint8Array(42);
  cmd1[0] = 0x01;
  cmd1[1] = 0x00;
  cmd1.set(ourPub, 2);

  const pkt1 = encPacketBuild(cmd1, FRAME_TYPE_COMMAND);
  const resp1 = await sendAndPoll(bus, notifyPath, writePath, pkt1, 5000);
  if (!resp1) {
    logErr("No response to public key exchange");
    return null;
  }

  const parsed1 = parseEncResponse(resp1);
  if (!parsed1 || parsed1.payload.length < 43) {
    logErr(`Invalid public key response (${resp1.length} bytes)`);
    return null;
  }

  const ecdhSize = getEcdhSize(parsed1.payload[2]);
  const peerPub = parsed1.payload.subarray(3, 3 + ecdhSize);

  const sharedSecret = await ecdhComputeShared(peerPub, privateKey);
  const iv = md5(sharedSecret);
  const sharedKey = sharedSecret.subarray(0, 16);

  log("Shared key established");

  log("Step 2: Request session key");
  const cmd2 = new Uint8Array([0x02]);
  const pkt2 = encPacketBuild(cmd2, FRAME_TYPE_COMMAND);
  const resp2 = await sendAndPoll(bus, notifyPath, writePath, pkt2, 5000);
  if (!resp2) {
    logErr("No response to key info request");
    return null;
  }

  const parsed2 = parseEncResponse(resp2);
  if (!parsed2 || parsed2.payload.length < 2 || parsed2.payload[0] !== 0x02) {
    logErr("Unexpected key info response");
    return null;
  }

  const decrypted = aesDecrypt(parsed2.payload.subarray(1), sharedKey, iv);
  if (decrypted.length < 18) {
    logErr("Failed to decrypt key info");
    return null;
  }

  const srandBytes = decrypted.subarray(0, 16);
  const seed = decrypted.subarray(16, 18);
  const sessionKey = await generateSessionKey(seed, srandBytes);
  log("Session key generated");

  log("Step 3: Check auth status");
  const p3 = packetInit();
  p3.src = 0x21;
  p3.dst = 0x35;
  p3.cmdSet = 0x35;
  p3.cmdId = 0x89;
  p3.dsrc = 0x01;
  p3.ddst = 0x01;

  const p3bytes = packetToBytes(p3);
  const pkt3 = encPacketBuild(p3bytes, FRAME_TYPE_PROTOCOL, sessionKey, iv);
  await gattWrite(bus, writePath, pkt3);

  await sleep(1000);

  log("Step 4: Authenticate");
  const authPayload = generateAuthPayload(userId, deviceSn);

  const p4 = packetInit();
  p4.src = 0x21;
  p4.dst = 0x35;
  p4.cmdSet = 0x35;
  p4.cmdId = 0x86;
  p4.dsrc = 0x01;
  p4.ddst = 0x01;
  p4.payload = authPayload;

  const p4bytes = packetToBytes(p4);
  const pkt4 = encPacketBuild(p4bytes, FRAME_TYPE_PROTOCOL, sessionKey, iv);

  const resp4 = await sendAndPoll(bus, notifyPath, writePath, pkt4, 5000);
  if (!resp4) {
    logErr("No auth response");
    return null;
  }

  const enc4 = parseEncResponse(resp4);
  if (enc4) {
    try {
      const dec4 = aesDecrypt(enc4.payload, sessionKey, iv);
      const innerPkt = packetFromBytes(dec4);
      if (
        innerPkt &&
        innerPkt.src === 0x35 &&
        innerPkt.cmdSet === 0x35 &&
        innerPkt.cmdId === 0x86
      ) {
        if (innerPkt.payload.length === 1 && innerPkt.payload[0] === 0x00) {
          log("Auth confirmed!");
          return { sessionKey, iv };
        } else {
          logErr("Auth rejected");
          return null;
        }
      }
    } catch {}
  }

  log("Auth response not parsed, continuing anyway...");
  return { sessionKey, iv };
}

function processBuffer(
  recvBuf: Uint8Array,
  recvLen: { v: number },
  auth: AuthState,
): River3Status | null {
  while (
    recvLen.v >= 8 &&
    recvBuf[0] === ENC_PACKET_PREFIX_0 &&
    recvBuf[1] === ENC_PACKET_PREFIX_1
  ) {
    const plen = recvBuf[4] | (recvBuf[5] << 8);
    const dataEnd = 6 + plen;

    if (recvLen.v < dataEnd) break;

    const encPayload = recvBuf.subarray(6, 6 + plen - 2);

    const remaining = recvLen.v - dataEnd;
    if (remaining > 0) {
      recvBuf.copyWithin(0, dataEnd, dataEnd + remaining);
    }
    recvLen.v = remaining;

    let dec: Uint8Array;
    try {
      dec = aesDecrypt(encPayload, auth.sessionKey, auth.iv);
    } catch {
      continue;
    }

    const pkt = packetFromBytes(dec);
    if (!pkt) continue;

    if (pkt.cmdSet !== 0xfe || pkt.cmdId !== 0x15) continue;

    const xorKey = pkt.seq[0];
    if (xorKey !== 0) {
      for (let i = 0; i < pkt.payload.length; i++) {
        pkt.payload[i] ^= xorKey;
      }
    }

    if (pkt.payload.length < 50 || pkt.payload[0] !== 0x08) continue;

    const status = parseRiver3Status(pkt.payload);
    if (status) return status;
  }
  return null;
}

export async function monitorGrid(
  address: string,
  serial: string,
  userId: string,
  onStatus: (status: River3Status) => void,
): Promise<void> {
  const bus = dbus.systemBus();
  const adapterPath = await getAdapterPath(bus);
  if (!adapterPath) throw new Error("No Bluetooth adapter found");
  await ensureAdapterPowered(bus, adapterPath);

  const devicePath = await ensureDevicePath(bus, adapterPath, address, 15000);
  if (!devicePath) throw new Error("Device not found during discovery");

  log(`Connecting to ${address}...`);

  const devObj = await bus.getProxyObject(BLUEZ_SERVICE, devicePath);
  const device = devObj.getInterface(DEVICE_IFACE);

  try {
    await device.Connect();
  } catch (e: any) {
    if (!e.message?.includes("Already Connected")) {
      throw new Error(`Connect failed: ${e.message}`);
    }
  }

  log("Connected, waiting for services...");

  if (!(await waitServicesResolved(bus, devicePath, 15000))) {
    throw new Error("Timed out waiting for ServicesResolved");
  }

  log("Services resolved, finding characteristics...");

  const notifyPath = await findCharPath(bus, devicePath, NOTIFY_UUID);
  if (!notifyPath) throw new Error("Notify characteristic not found");

  const writePath = await findCharPath(bus, devicePath, WRITE_UUID);
  if (!writePath) throw new Error("Write characteristic not found");

  log("Characteristics found, authenticating...");

  const auth = await authenticate(bus, notifyPath, writePath, serial, userId);
  if (!auth) throw new Error("Authentication failed");

  log("Monitoring for status...");

  const recvBuf = new Uint8Array(4096);
  const recvLen = { v: 0 };

  return new Promise(async (resolve, reject) => {
    let notifyObj: dbus.ProxyObject;
    let notifyProps: dbus.ClientInterface;
    let devProps: dbus.ClientInterface;
    let cleaned = false;

    const cleanup = async () => {
      if (cleaned) return;
      cleaned = true;
      try {
        notifyProps?.removeAllListeners("PropertiesChanged");
        devProps?.removeAllListeners("PropertiesChanged");
        await gattNotify(bus, notifyPath, false);
      } catch {}
      try {
        await device.Disconnect();
      } catch {}
      bus.disconnect();
    };

    const onDisconnect = (
      iface: string,
      changed: Record<string, dbus.Variant>,
    ) => {
      if (iface !== DEVICE_IFACE) return;
      const conn = changed.Connected;
      if (conn && conn.value === false) {
        log("Device disconnected");
        cleanup().then(() => resolve());
      }
    };

    const onNotify = (
      iface: string,
      changed: Record<string, dbus.Variant>,
    ) => {
      if (iface !== GATT_CHAR_IFACE) return;
      const val = changed.Value;
      if (!val) return;
      const bytes = val.value as number[];
      if (!bytes || bytes.length === 0) return;

      const space = recvBuf.length - recvLen.v;
      const copy = Math.min(bytes.length, space);
      for (let i = 0; i < copy; i++) {
        recvBuf[recvLen.v + i] = bytes[i];
      }
      recvLen.v += copy;

      const status = processBuffer(recvBuf, recvLen, auth);
      if (status) onStatus(status);
    };

    try {
      devProps = devObj.getInterface(DBUS_PROP_IFACE);
      devProps.on("PropertiesChanged", onDisconnect);

      notifyObj = await bus.getProxyObject(BLUEZ_SERVICE, notifyPath);
      notifyProps = notifyObj.getInterface(DBUS_PROP_IFACE);
      notifyProps.on("PropertiesChanged", onNotify);
      await gattNotify(bus, notifyPath, true);
    } catch (e: any) {
      await cleanup();
      reject(new Error(`Failed to start notifications: ${e.message}`));
    }
  });
}
