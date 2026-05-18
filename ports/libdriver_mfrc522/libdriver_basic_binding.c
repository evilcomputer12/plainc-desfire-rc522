#include "libdriver_backend.h"

/*
 * Concrete LibDriver basic-API binding.
 *
 * LibDriver documents these entry points in driver_mfrc522_basic.h:
 *   - mfrc522_basic_init(...)
 *   - mfrc522_basic_deinit(...)
 *   - mfrc522_basic_transceiver(...)
 *   - mfrc522_basic_calculate_crc(...)
 *   - mfrc522_basic_generate_random(...)
 *
 * This file shows how to wrap that API for the portable DESFire core.
 *
 * If the LibDriver headers are not present in your build yet, keep this file
 * excluded from compilation and use it as the integration target when you add
 * the upstream source tree.
 */

#if defined(__has_include)
#if __has_include("driver_mfrc522_basic.h")
#include "driver_mfrc522_basic.h"
#include <string.h>

typedef struct {
    rc522_port_t port;
    uint8_t initialized;
} libdriver_basic_backend_t;

static DFStatus libdriver_basic_activate_impl(void *user) {
    (void)user;
    return DF_OK;
}

static bool libdriver_basic_present_impl(void *user) {
    (void)user;
    return true;
}

static DFStatus libdriver_basic_send_impl(void *user,
                                          const uint8_t *tx,
                                          uint8_t tx_len,
                                          uint8_t *rx,
                                          uint8_t *rx_len) {
    (void)user;
    uint8_t out_len = 0;
    uint8_t tmp[300];
    uint8_t rc = mfrc522_basic_transceiver((uint8_t *)tx, tx_len, tmp, &out_len);
    if (rc != 0) {
        return DF_ERR_TRANSCEIVE;
    }
    if (rx && rx_len) {
        memcpy(rx, tmp, out_len);
        *rx_len = out_len;
    }
    return DF_OK;
}

static void libdriver_basic_sleep_impl(void *user, uint32_t ms) {
    (void)user;
    (void)ms;
}

void libdriver_basic_binding_init(libdriver_basic_backend_t *backend,
                                  mfrc522_interface_t interface,
                                  uint8_t addr,
                                  void (*callback)(uint16_t type)) {
    if (!backend) {
        return;
    }
    memset(backend, 0, sizeof(*backend));
    (void)mfrc522_basic_init(interface, addr, callback);
    backend->initialized = 1;
    rc522_port_ops_t ops = {
        .user = backend,
        .present = libdriver_basic_present_impl,
        .activate = libdriver_basic_activate_impl,
        .send_apdu = libdriver_basic_send_impl,
        .sleep_ms = libdriver_basic_sleep_impl,
    };
    rc522_port_init(&backend->port, &ops);
}

void libdriver_basic_binding_deinit(libdriver_basic_backend_t *backend) {
    if (!backend || !backend->initialized) {
        return;
    }
    (void)mfrc522_basic_deinit();
    backend->initialized = 0;
}

DFStatus libdriver_basic_binding_transceive(void *user,
                                            const uint8_t *tx,
                                            uint8_t tx_len,
                                            uint8_t *rx,
                                            uint8_t *rx_len) {
    libdriver_basic_backend_t *backend = (libdriver_basic_backend_t *)user;
    if (!backend) {
        return DF_ERR_PARAM;
    }
    return libdriver_basic_send_impl(backend, tx, tx_len, rx, rx_len);
}

#else
/* LibDriver headers are not available yet; keep this translation unit empty. */
#endif
#endif
