# EcoFlow River 3 Grid Monitor

`bun` + TypeScript tool for Linux (including Raspberry Pi 5) that checks EcoFlow River 3 grid/AC input status over Bluetooth and prints:

- `UP` when grid power is available
- `DOWN` when grid power is lost

The process exits after printing status.

## Requirements

- `bun`
- BlueZ (`bluetoothd`) running on Linux

## Install

```bash
bun install
```

## Usage

Run with CLI args:

```bash
bun run index.ts --address AA:BB:CC:DD:EE:FF --serial R631xxx --user-id 12345
```

Or use environment variables:

```bash
ECOFLOW_ADDRESS=AA:BB:CC:DD:EE:FF \
ECOFLOW_SERIAL=R631xxx \
ECOFLOW_USER_ID=12345 \
bun run index.ts
```

## Exit Codes

- `0`: success
- `1`: invalid arguments
- `2`: connection/runtime error

## Project Structure

- `index.ts` - entry point, argument parsing, outputs `UP`/`DOWN`
- `src/ble.ts` - BLE/BlueZ D-Bus connection, auth handshake, notifications
- `src/crypto.ts` - CRC8/CRC16, AES-128-CBC, MD5, ECDH secp160r1, session key
- `src/protocol.ts` - packet encode/decode, protobuf decode, River 3 status parsing
- `src/keydata.bin` - 64 KB lookup table for session key generation
