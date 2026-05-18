# Examples

This folder contains portable usage examples for the DESFire library.

## `c_desfire_demo`

Plain C end-to-end version of the same idea:

- no Arduino headers
- callback-driven transport
- platform hooks for RC522 present/activate/transceive
- portable logging / RNG / delay hooks
- full DESFire setup, write, and read flow
- full DNA setup and blanking flow

The example is designed to show the complete wiring chain from an MCU RC522
driver into the DESFire core. See `ports/libdriver_mfrc522/rc522_port.c` for a
generic RC522 adapter contract and `ports/libdriver_mfrc522/libdriver_basic_binding.c`
for the LibDriver-shaped binding path.
