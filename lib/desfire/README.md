# DESFire Portable Library

This library is structured so the DESFire command layer is independent of the
microcontroller. The only hardware-specific part is the transport callback
that sends ISO 14443-4 APDUs to the card.

## What the library does

- Authenticate at PICC or application level.
- Format a DESFire card.
- Create applications and standard data files.
- Change keys and file settings.
- Read and write data in EV2 secure messaging.
- Handle NTAG 424 DNA setup and file clearing through the same API surface.

## What the library does not do

- SPI setup.
- RC522 hardware control.
- Card discovery / anticollision / RATS.
- Wi-Fi or HTTP.
- UI.

Those are supplied by your application through callbacks.

## Core callback model

The library needs four app-provided hooks:

- `transceive`: send an APDU and receive the response.
- `random`: provide entropy for auth/session values.
- `delay`: sleep for a number of milliseconds.
- `log`: print APDU traces and debug messages.

If you do not provide `random`, the library falls back to a small portable
PRNG. That keeps the code building on any platform, but it is not a secure
entropy source.

## Minimal integration

```c
DFContext ctx;
df_ctx_init_full(
    &ctx,
    my_transceive,
    my_user_ptr,
    my_log,
    my_random,
    my_random_user,
    my_delay,
    my_delay_user);
```

If you want to attach callbacks later:

```c
df_ctx_init(&ctx, my_transceive, my_user_ptr, my_log);
df_ctx_set_random(&ctx, my_random, my_random_user);
df_ctx_set_delay(&ctx, my_delay, my_delay_user);
df_ctx_set_log(&ctx, my_log);
```

## DESFire vs NTAG 424 DNA

DESFire and DNA are separate workflows:

- DESFire:
  - Select PICC.
  - Authenticate the PICC master key.
  - Format.
  - Create application.
  - Create file.
  - Change keys as needed.
  - Read/write selected file.

- NTAG 424 DNA:
  - ISO-select the fixed NDEF AID.
  - Authenticate to the existing DNA application.
  - Update file 03 settings.
  - Write the DNA payload file.
  - Optionally blank the DNA payload and restore the key back to zero.

## Defaults used in this project

These are the defaults used by the ESP32 demo app, and they are good starting
points for examples:

- DESFire app ID: `0x010203`
- DESFire file number: `0x02`
- DESFire file size: `128`
- DESFire access rights: `0x2222`
- DNA file number: `0x03`
- DNA file size: `128`
- DNA file 03 rights: `0x0330`
- Default AES key: 16 zero bytes

## Example flows

### DESFire setup

```c
uint8_t piccKey[16] = {0};
uint8_t appMaster[16] = {0x11};
uint8_t appUser[16] = {0x22};

df_setup_desfire(
    &ctx,
    0x010203,
    piccKey,
    appMaster,
    appUser,
    2,          // user key slot
    2,          // file number
    128,        // file size
    0x2222);    // access rights
```

### NTAG 424 DNA setup

```c
uint8_t defaultAes[16] = {0};
uint8_t dnaUser[16] = {0x22};

df_setup_dna(
    &ctx,
    dnaUser,
    0,          // user key slot (factory zero)
    0x03,
    0x0330);
```

### Write and read

```c
const uint8_t msg[] = { 'H', 'e', 'l', 'l', 'o' };
df_write_data(&ctx, 0x02, 0, msg, sizeof(msg));

uint8_t out[32];
df_read_data(&ctx, 0x02, 0, sizeof(msg), out);
```

## Logging

The log callback receives APDU hex strings and debug labels. You can route it
to:

- `Serial.printf` on Arduino.
- `printf` on a desktop build.
- A ring buffer in firmware.

This is intentionally kept as a callback rather than a dependency on any
specific logging framework.

## Porting checklist

When moving this library to another MCU:

1. Keep `lib/desfire/` unchanged.
2. Implement the `transceive` callback with your NFC frontend.
3. Provide `random`, `delay`, and `log` callbacks.
4. Initialize `DFContext`.
5. Reuse the same setup/write/read wrappers in your app.

## Notes

- DESFire full-mode write and read are implemented in the library.
- NTAG DNA blanking clears the payload header and restores the key slot to the
  default zero AES key.
- The RC522-specific code in the ESP32 demo app is not part of the DESFire
  core; it is just one possible transport backend.
