# Examples

This folder contains portable usage examples for the DESFire library.

## `c_desfire_demo`

Plain C version of the same idea:

- no Arduino headers
- callback-driven transport
- portable logging / RNG / delay hooks
- sample DESFire and DNA wrapper calls

The transport callback is intentionally left abstract. See
`ports/libdriver_mfrc522/rc522_port.c` for a generic RC522 adapter contract.
