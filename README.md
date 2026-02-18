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

