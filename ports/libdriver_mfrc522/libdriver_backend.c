#include "libdriver_backend.h"

/*
 * The exact LibDriver MFRC522 entry points depend on how the upstream package
 * is integrated, so this binding keeps the shape explicit and conservative.
 *
 * Populate rc522_port_ops_t with the concrete LibDriver-backed functions from
 * your MCU project, then call libdriver_mfrc522_backend_init().
 */

void libdriver_mfrc522_backend_init(libdriver_mfrc522_backend_t *backend,
                                    void *driver,
                                    const rc522_port_ops_t *ops) {
    if (!backend) {
        return;
    }
    backend->driver = driver;
    rc522_port_init(&backend->port, ops);
    backend->port.ops.user = driver;
}

bool libdriver_mfrc522_backend_card_present(libdriver_mfrc522_backend_t *backend) {
    if (!backend) {
        return false;
    }
    return rc522_port_card_present(&backend->port);
}

DFStatus libdriver_mfrc522_backend_activate(libdriver_mfrc522_backend_t *backend) {
    if (!backend) {
        return DF_ERR_PARAM;
    }
    return rc522_port_activate_card(&backend->port);
}

DFStatus libdriver_mfrc522_backend_transceive(void *user,
                                              const uint8_t *tx,
                                              uint8_t tx_len,
                                              uint8_t *rx,
                                              uint8_t *rx_len) {
    return rc522_port_transceive(user, tx, tx_len, rx, rx_len);
}
