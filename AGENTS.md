# EcoFlow River 3 Grid Monitor

Bun/TypeScript project for **Raspberry Pi 5** (or any Linux with BlueZ) that
checks grid/AC input status via Bluetooth. Outputs `UP` or `DOWN` and exits.

Uses dbus-next to talk to BlueZ over D-Bus, Node crypto for AES/MD5, and
@noble/curves for ECDH secp160r1.

## Run

Requires: `bun`, BlueZ (`bluetoothd`).

```bash
bun install
bun run index.ts --address AA:BB:CC:DD:EE:FF --serial R631xxx --user-id 12345
```

Or via environment variables:

```bash
ECOFLOW_ADDRESS=AA:BB:CC:DD:EE:FF ECOFLOW_SERIAL=R631xxx ECOFLOW_USER_ID=12345 bun run index.ts
```

Exit codes: 0 = success, 1 = bad args, 2 = connection/runtime error.

## Files

- `index.ts` - Entry point, parses args, prints UP/DOWN, exits
- `src/ble.ts` - BLE via D-Bus/BlueZ: connect, auth handshake, status notifications
- `src/crypto.ts` - CRC8/CRC16, AES-128-CBC, MD5, ECDH secp160r1 (via openssl CLI), session key
- `src/protocol.ts` - Packet/EncPacket build/parse, protobuf decoder, River3 status parser
- `src/keydata.bin` - 64KB lookup table for session key generation
