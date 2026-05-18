#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "rc522_port.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Concrete adapter scaffold for the LibDriver MFRC522 package.
 *
 * This does not ship the LibDriver sources. It provides a small binding layer
 * so an app can connect LibDriver's RC522 stack to the portable DESFire core.
 */

typedef struct {
    void *driver;
    rc522_port_t port;
} libdriver_mfrc522_backend_t;

void libdriver_mfrc522_backend_init(libdriver_mfrc522_backend_t *backend,
                                    void *driver,
                                    const rc522_port_ops_t *ops);

bool libdriver_mfrc522_backend_card_present(libdriver_mfrc522_backend_t *backend);
DFStatus libdriver_mfrc522_backend_activate(libdriver_mfrc522_backend_t *backend);
DFStatus libdriver_mfrc522_backend_transceive(void *user,
                                              const uint8_t *tx,
                                              uint8_t tx_len,
                                              uint8_t *rx,
                                              uint8_t *rx_len);

#ifdef __cplusplus
}
#endif
