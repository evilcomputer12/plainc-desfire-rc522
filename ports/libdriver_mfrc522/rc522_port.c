#include "rc522_port.h"

void rc522_port_init(rc522_port_t *port, const rc522_port_ops_t *ops) {
    if (!port) {
        return;
    }
    port->card_active = false;
    if (ops) {
        port->ops = *ops;
    } else {
        port->ops.user = NULL;
        port->ops.present = NULL;
        port->ops.activate = NULL;
        port->ops.send_apdu = NULL;
        port->ops.sleep_ms = NULL;
    }
}

bool rc522_port_card_present(rc522_port_t *port) {
    if (!port || !port->ops.present) {
        return false;
    }
    return port->ops.present(port->ops.user);
}

DFStatus rc522_port_activate_card(rc522_port_t *port) {
    if (!port || !port->ops.activate) {
        return DF_ERR_PARAM;
    }
    DFStatus st = port->ops.activate(port->ops.user);
    port->card_active = (st == DF_OK);
    return st;
}

DFStatus rc522_port_transceive(void *user,
                               const uint8_t *send,
                               uint8_t send_len,
                               uint8_t *resp,
                               uint8_t *resp_len) {
    rc522_port_t *port = (rc522_port_t *)user;
    if (!port || !port->ops.send_apdu) {
        return DF_ERR_TRANSCEIVE;
    }
    return port->ops.send_apdu(port->ops.user, send, send_len, resp, resp_len);
}

void rc522_port_delay(void *user, uint32_t ms) {
    rc522_port_t *port = (rc522_port_t *)user;
    if (!port || !port->ops.sleep_ms) {
        return;
    }
    port->ops.sleep_ms(port->ops.user, ms);
}
