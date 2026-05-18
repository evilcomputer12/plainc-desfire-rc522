# Plain-C RC522 Transport Adapter

This folder now contains a small adapter contract for plain-C RC522 stacks.
It is intentionally generic so you can wire in either of the C-first drivers
found during the search:

- [`libdriver/mfrc522`](https://github.com/libdriver/mfrc522)
- [`litehacker/rfrc522-spi-c`](https://github.com/litehacker/rfrc522-spi-c)

## Why this exists

The DESFire core is portable, but the RF front-end is not. Different MCUs
usually already have a plain-C NFC stack or a driver layer for RC522. This
adapter lets you keep that code separate from the DESFire crypto and command
logic.

## Adapter contract

The adapter exposes four hooks:

- `present` - return whether a card is currently visible
- `activate` - perform the ISO14443-3/4 activation sequence
- `send_apdu` - exchange an ISO14443-4 APDU with the card
- `sleep_ms` - optional delay hook for settle time

Those hooks are wrapped by `rc522_port_transceive()` and
`rc522_port_delay()`, which can then be passed directly into `DFContext`.

## Minimal flow

1. Use your RC522 driver to detect the card.
2. Call `rc522_port_activate_card()`.
3. Build `DFContext` with `df_ctx_init_full()`.
4. Use `rc522_port_transceive()` as the DESFire transport callback.
5. Use `df_setup_desfire()`, `df_setup_dna()`, `df_write_data()`, and
   `df_read_data()` as needed.

## Concrete LibDriver binding

`libdriver_backend.c` shows the shape of a concrete LibDriver-backed adapter.
It is intentionally conservative because the LibDriver project exposes a full
reader stack, and the exact integration points depend on whether you use the
basic example layer or the lower-level driver primitives.

`libdriver_basic_binding.c` is the more concrete path. It references the
documented LibDriver basic API directly:

- `mfrc522_basic_init()`
- `mfrc522_basic_deinit()`
- `mfrc522_basic_transceiver()`
- `mfrc522_basic_calculate_crc()`
- `mfrc522_basic_generate_random()`

The intended flow is:

- initialize LibDriver MFRC522 in your app
- fill `rc522_port_ops_t` with the LibDriver-backed hooks
- call `libdriver_mfrc522_backend_init()`
- pass `libdriver_mfrc522_backend_transceive()` into `df_ctx_init_full()`

If you want a production backend, replace the stub functions in
`libdriver_binding_example.c` with your actual LibDriver integration.

## Example binding

```c
rc522_port_t port;
rc522_port_ops_t ops = {
    .user = my_rc522_driver,
    .present = my_rc522_card_present,
    .activate = my_rc522_activate,
    .send_apdu = my_rc522_transceive,
    .sleep_ms = my_delay_ms,
};

rc522_port_init(&port, &ops);
df_ctx_init_full(&ctx,
                 rc522_port_transceive,
                 &port,
                 my_log,
                 my_random,
                 my_random_user,
                 rc522_port_delay,
                 &port);
```

## Notes

- This adapter is transport-only.
- It does not implement DESFire itself.
- It does not require Arduino.
- It does not assume ESP32.
