#include "libdriver_backend.h"

/*
 * Example-only wiring skeleton.
 *
 * Replace the stub hooks with the concrete LibDriver MFRC522 functions used in
 * your target project. This file documents the intended shape without forcing
 * one specific LibDriver integration strategy.
 */

static bool stub_present(void *user) {
    (void)user;
    return false;
}

static DFStatus stub_activate(void *user) {
    (void)user;
    return DF_ERR_TRANSCEIVE;
}

static DFStatus stub_send(void *user,
                          const uint8_t *tx,
                          uint8_t tx_len,
                          uint8_t *rx,
                          uint8_t *rx_len) {
    (void)user;
    (void)tx;
    (void)tx_len;
    (void)rx;
    (void)rx_len;
    return DF_ERR_TRANSCEIVE;
}

static void stub_sleep(void *user, uint32_t ms) {
    (void)user;
    (void)ms;
}

void libdriver_binding_example(void *libdriver_instance) {
    libdriver_mfrc522_backend_t backend;
    rc522_port_ops_t ops = {
        .user = libdriver_instance,
        .present = stub_present,
        .activate = stub_activate,
        .send_apdu = stub_send,
        .sleep_ms = stub_sleep,
    };

    libdriver_mfrc522_backend_init(&backend, libdriver_instance, &ops);

    /*
     * Typical binding:
     *
     * DFContext ctx;
     * df_ctx_init_full(&ctx,
     *                  libdriver_mfrc522_backend_transceive,
     *                  &backend.port,
     *                  my_log,
     *                  my_random,
     *                  my_random_user,
     *                  rc522_port_delay,
     *                  &backend.port);
     */
}
