# EcoFlow River 3 Grid Monitor

C project for monitoring grid/AC input status via Bluetooth.

Uses sd-bus (systemd) for BLE via BlueZ D-Bus API, and OpenSSL for crypto.

## Build

```bash
make          # produces ./grid_monitor
make clean
```

Dependencies (link flags: `-lsystemd -lssl -lcrypto`):
- libsystemd (sd-bus)
- OpenSSL 3.0+

## Usage

```bash
# Scan for EcoFlow devices
./grid_monitor scan [--timeout N]

# One-time grid check (returns exit code 0=up, 1=down, 2=error)
./grid_monitor check ADDRESS --serial SN --user-id ID [--format text|json]

# Continuous monitoring
./grid_monitor monitor ADDRESS --serial SN --user-id ID [--interval N] [--format text|json]
```

Environment variables: `ECOFLOW_USER_ID`, `ECOFLOW_SERIAL`.

## Files

- `src/main.c` - CLI entry point (scan/check/monitor), signal handling
- `src/ble.h/.c` - BLE scan, connect, auth, notifications via sd-bus/BlueZ D-Bus
- `src/crypto.h/.c` - CRC8/CRC16, AES-128-CBC, MD5, ECDH secp160r1, session key
- `src/protocol.h/.c` - Packet/EncPacket build/parse, protobuf decoder, status parser
- `src/keydata.h/.c` - 64KB lookup table for session key generation
- `Makefile` - Build system
