#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../lib/desfire/desfire_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic plain-C RC522 adapter contract.
 *
 * This file does not depend on any specific RC522 driver. It defines the
 * minimum set of hooks needed to connect a plain-C RC522 stack to the portable
 * DESFire core.
 *
 * The intent is:
 *   1. use your RC522 driver to detect cards and perform ISO14443-3/4 setup
 *   2. pass ISO14443-4 APDUs through rc522_port_transceive()
 *   3. feed that transceive callback into df_ctx_init_full()
 */

typedef struct rc522_port rc522_port_t;

typedef bool (*rc522_port_present_fn)(void *user);
typedef DFStatus (*rc522_port_activate_fn)(void *user);
typedef DFStatus (*rc522_port_send_fn)(void *user,
                                       const uint8_t *tx,
                                       uint8_t tx_len,
                                       uint8_t *rx,
                                       uint8_t *rx_len);
typedef void (*rc522_port_sleep_fn)(void *user, uint32_t ms);

typedef struct {
    void *user;
    rc522_port_present_fn present;
    rc522_port_activate_fn activate;
    rc522_port_send_fn send_apdu;
    rc522_port_sleep_fn sleep_ms;
} rc522_port_ops_t;

struct rc522_port {
    rc522_port_ops_t ops;
    bool card_active;
};

void rc522_port_init(rc522_port_t *port, const rc522_port_ops_t *ops);
bool rc522_port_card_present(rc522_port_t *port);
DFStatus rc522_port_activate_card(rc522_port_t *port);
DFStatus rc522_port_transceive(void *user,
                               const uint8_t *send,
                               uint8_t send_len,
                               uint8_t *resp,
                               uint8_t *resp_len);
void rc522_port_delay(void *user, uint32_t ms);

#ifdef __cplusplus
}
#endif
