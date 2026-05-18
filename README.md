# Plain-C DESFire + RC522 Core

This repository is a plain-C reference package for DESFire and NTAG 424 DNA
workflows over an RC522 transport.

## Layout

- `lib/desfire/` - MCU-agnostic DESFire command and crypto layer.
- `examples/c_desfire_demo/` - Pure C example showing the callback-based API.
- `ports/libdriver_mfrc522/` - Notes for a plain-C RC522 backend.
- `ports/libdriver_mfrc522/rc522_port.c` - Generic plain-C RC522 adapter.
- `ports/libdriver_mfrc522/libdriver_backend.c` - LibDriver binding scaffold.

## Goals

- Keep DESFire and NTAG 424 DNA handling in portable C.
- Push all hardware access behind callbacks.
- Allow any MCU to supply its own ISO 14443-4 transceiver, RNG, delay, and log
  hooks.

## Quick start

1. Read [`lib/desfire/README.md`](lib/desfire/README.md).
2. Open [`examples/c_desfire_demo/main.c`](examples/c_desfire_demo/main.c).
3. Implement the `platform_*` hooks in that example for your RC522 driver.
4. Use the wrappers:
   - `df_setup_desfire()`
   - `df_setup_dna()`
   - `df_write_data()`
   - `df_read_data()`
   - `df_change_key()`
   - `df_change_file_settings()`

## Notes

- The repository is intentionally plain C.
- The DESFire core is callback-driven and does not depend on Arduino.
- The example uses LibDriver MFRC522 automatically when
  `driver_mfrc522_basic.h` is available.
- For a plain-C RC522 backend, see the notes in `ports/libdriver_mfrc522/`.
- The RC522 adapter is intentionally generic so you can bind any plain-C
  driver into the same DESFire core.
- The main example runs the full loop:
  - wait for card
  - activate RC522 transport
  - provision DESFire
  - write/read a file
  - provision DNA
  - blank DNA payload

## Publishing

The repository is already tracked in git. Add a GitHub remote and push when
you are ready to publish changes.
