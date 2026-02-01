# EcoFlow River 3 Grid Monitor

Bare-metal C project for **Raspberry Pi Pico 2 W** that monitors grid/AC input
status via Bluetooth and drives the onboard LED: **LED ON = grid power
available, LED OFF = grid lost.**

Uses btstack (in Pico SDK) for BLE, mbedtls for AES/MD5, and micro-ecc for
ECDH secp160r1.

## Build

Requires: `cmake`, `arm-none-eabi-gcc`, `arm-none-eabi-newlib`.

```bash
make ADDRESS=AA:BB:CC:DD:EE:FF SERIAL=R631xxx USER_ID=12345
make clean
```

First build fetches the Pico SDK and micro-ecc via CMake FetchContent.

## Flash

Hold BOOTSEL on the Pico, plug USB, then:

```bash
make flash
```

Copies `build/grid_monitor.uf2` to the RP2350 mass-storage device.

## Serial monitor (optional)

```bash
minicom -D /dev/ttyACM0 -b 115200
```

## Files

- `src/main.c` - Entry point, CYW43 init, btstack run loop, LED via cyw43 GPIO
- `src/ble.h/.c` - BLE connect, auth, notifications via btstack state machine
- `src/crypto.h/.c` - CRC8/CRC16, AES-128-CBC (mbedtls), MD5 (mbedtls), ECDH secp160r1 (micro-ecc), session key
- `src/protocol.h/.c` - Packet/EncPacket build/parse, protobuf decoder, status parser
- `src/keydata.h/.c` - 64KB lookup table for session key generation
- `CMakeLists.txt` - CMake build (Pico SDK, btstack, mbedtls, micro-ecc)
- `Makefile` - Wrapper that invokes CMake with device config
- `flash.sh` - UF2 flash script for BOOTSEL mode
- `btstack_config.h` - btstack LE Central configuration
- `pico_sdk_import.cmake` - Standard Pico SDK import helper
