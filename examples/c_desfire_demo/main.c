#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../lib/desfire/desfire_cmd.h"

/*
 * Plain-C DESFire demo
 *
 * This file is intentionally MCU-agnostic. Replace the transport callback
 * with your own ISO 14443-4 stack, then reuse the wrapper calls below.
 */

typedef struct {
    void *user;
    df_transceive_fn transceive;
} DemoTransport;

static DFContext g_ctx;

static DFStatus demo_transceive(void *user, const uint8_t *send,
                                uint8_t send_len, uint8_t *resp,
                                uint8_t *resp_len) {
    DemoTransport *tp = (DemoTransport *)user;
    if (!tp || !tp->transceive) {
        return DF_ERR_TRANSCEIVE;
    }
    return tp->transceive(tp->user, send, send_len, resp, resp_len);
}

static void demo_random(void *user, uint8_t *buf, size_t len) {
    (void)user;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u));
    }
}

static void demo_delay(void *user, uint32_t ms) {
    (void)user;
    (void)ms;
}

static void demo_log(const char *label, const char *apdu_hex,
                     const char *resp_hex) {
    if (label && label[0]) {
        printf("[%s]\n", label);
    }
    if (apdu_hex && apdu_hex[0]) {
        printf("  APDU: %s\n", apdu_hex);
    }
    if (resp_hex && resp_hex[0]) {
        printf("  RESP: %s\n", resp_hex);
    }
}

static const uint8_t PICC_KEY_DEFAULT[16] = {0x00};
static const uint8_t APP_MASTER_KEY[16] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
static const uint8_t APP_USER_KEY[16] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};
static const uint8_t DNA_KEY_NEW[16] = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
};

static void desfire_init(DemoTransport *transport) {
    df_ctx_init_full(&g_ctx, demo_transceive, transport, demo_log,
                     demo_random, NULL, demo_delay, NULL);
}

static DFStatus desfire_setup_example(void) {
    const uint32_t app_id = 0x010203u;
    const uint8_t file_no = 0x02u;
    const uint32_t file_size = 128u;
    const uint16_t file_rights = 0x2222u;
    return df_setup_desfire(&g_ctx, app_id, PICC_KEY_DEFAULT,
                            APP_MASTER_KEY, APP_USER_KEY,
                            2, file_no, file_size, file_rights);
}

static DFStatus dna_setup_example(void) {
    return df_setup_dna(&g_ctx, DNA_KEY_NEW, 0, 0x03u, 0x0330u);
}

static DFStatus write_example(void) {
    const uint8_t payload[] = { 'H', 'e', 'l', 'l', 'o' };
    return df_write_data(&g_ctx, 0x02u, 0, payload, (uint32_t)sizeof(payload));
}

static DFStatus read_example(uint32_t len) {
    uint8_t out[64];
    if (len > sizeof(out)) {
        return DF_ERR_PARAM;
    }
    return df_read_data(&g_ctx, 0x02u, 0, len, out);
}

int main(void) {
    DemoTransport transport = {
        .user = NULL,
        .transceive = NULL,
    };

    desfire_init(&transport);

    printf("Portable plain-C DESFire demo\n");
    printf("Replace DemoTransport.transceive with your NFC backend.\n");
    printf("Then call the wrappers below in response to card-present events.\n\n");
    printf("Wrappers available:\n");
    printf("  df_setup_desfire()\n");
    printf("  df_setup_dna()\n");
    printf("  df_write_data()\n");
    printf("  df_read_data()\n");
    printf("  df_change_key()\n");
    printf("  df_change_file_settings()\n\n");

    (void)desfire_setup_example;
    (void)dna_setup_example;
    (void)write_example;
    (void)read_example;

    return 0;
}
