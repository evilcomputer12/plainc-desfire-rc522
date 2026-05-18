#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../lib/desfire/desfire_cmd.h"
#include "../../ports/libdriver_mfrc522/rc522_port.h"

#if defined(__has_include)
#if __has_include("driver_mfrc522_basic.h")
#include "driver_mfrc522_basic.h"
#define HAVE_LIBDRIVER_MFRC522 1
#endif
#endif

#ifndef HAVE_LIBDRIVER_MFRC522
#define HAVE_LIBDRIVER_MFRC522 0
#endif

/*
 * Plain-C DESFire + RC522 end-to-end example
 *
 * This example shows the full wiring chain:
 *   platform RC522 driver -> rc522_port_t -> DFContext -> DESFire wrappers
 *
 * Replace the platform_* functions with your own MCU/RC522 implementation.
 * The DESFire library itself remains unchanged.
 */

typedef struct {
    void *driver;
    rc522_port_t port;
    DFContext ctx;
    bool initialized;
} AppState;

static const uint32_t DESFIRE_APP_ID = 0x010203u;
static const uint8_t DESFIRE_FILE_NO = 0x02u;
static const uint32_t DESFIRE_FILE_SIZE = 128u;
static const uint16_t DESFIRE_ACCESS_RIGHTS = 0x2222u;
static const uint8_t DESFIRE_PICC_KEY[16] = {0x00};
static const uint8_t DESFIRE_APP_MASTER_KEY[16] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
static const uint8_t DESFIRE_APP_USER_KEY[16] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

static const uint8_t DNA_NEW_KEY[16] = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
};
static const uint8_t DNA_AUTH_KEY_DEFAULT[16] = {0x00};
static const uint8_t DNA_FILE_NO = 0x03u;
static const uint16_t DNA_FILE_RIGHTS = 0x0330u;

static void log_hex_bytes(const char *prefix, const uint8_t *buf, size_t len) {
    size_t i;
    printf("%s", prefix);
    for (i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if (i + 1 < len) {
            printf(" ");
        }
    }
    printf("\n");
}

static bool platform_card_present(void *user) {
    AppState *app = (AppState *)user;
    uint8_t probe[] = { 0x90, 0x60, 0x00, 0x00, 0x00 };
    uint8_t resp[32];
    uint8_t out_len = 0;

    if (!app) {
        return false;
    }

#if HAVE_LIBDRIVER_MFRC522
    if (mfrc522_basic_transceiver(probe, (uint8_t)sizeof(probe), resp, &out_len) == 0 &&
        out_len >= 2 &&
        resp[out_len - 2] == 0x91) {
        return true;
    }
#else
    (void)probe;
    (void)resp;
    (void)out_len;
#endif
    return false;
}

static DFStatus platform_activate_card(void *user) {
    AppState *app = (AppState *)user;
    uint8_t probe[] = { 0x90, 0x60, 0x00, 0x00, 0x00 };
    uint8_t resp[32];
    uint8_t out_len = 0;

    if (!app) {
        return DF_ERR_PARAM;
    }

#if HAVE_LIBDRIVER_MFRC522
    if (mfrc522_basic_transceiver(probe, (uint8_t)sizeof(probe), resp, &out_len) != 0) {
        return DF_ERR_TRANSCEIVE;
    }
    if (out_len < 2 || resp[out_len - 2] != 0x91) {
        return DF_ERR_TRANSCEIVE;
    }
    return DF_OK;
#else
    (void)probe;
    (void)resp;
    (void)out_len;
    return DF_ERR_TRANSCEIVE;
#endif
}

static DFStatus platform_send_apdu(void *user,
                                   const uint8_t *tx,
                                   uint8_t tx_len,
                                   uint8_t *rx,
                                   uint8_t *rx_len) {
    (void)user;
#if HAVE_LIBDRIVER_MFRC522
    if (mfrc522_basic_transceiver((uint8_t *)tx, tx_len, rx, rx_len) != 0) {
        return DF_ERR_TRANSCEIVE;
    }
    return DF_OK;
#else
    (void)tx;
    (void)tx_len;
    (void)rx;
    (void)rx_len;
    return DF_ERR_TRANSCEIVE;
#endif
}

static void platform_sleep_ms(void *user, uint32_t ms) {
    (void)user;
    (void)ms;
    /*
     * Replace with your MCU delay function.
     */
}

static void platform_random(void *user, uint8_t *buf, size_t len) {
    (void)user;
#if HAVE_LIBDRIVER_MFRC522
    {
        uint8_t tmp[25];
        if (mfrc522_basic_generate_random(tmp) == 0) {
            size_t copy_len = len < sizeof(tmp) ? len : sizeof(tmp);
            memcpy(buf, tmp, copy_len);
            if (copy_len < len) {
                memset(buf + copy_len, 0, len - copy_len);
            }
            return;
        }
    }
#endif
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u));
    }
}

static void platform_log(const char *label, const char *apdu_hex,
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

static void app_init(AppState *app) {
#if HAVE_LIBDRIVER_MFRC522
    if (mfrc522_basic_init(MFRC522_INTERFACE_SPI, 0x00, NULL) != 0) {
        app->initialized = false;
        return;
    }
#endif
    rc522_port_ops_t ops = {
        .user = app->driver,
        .present = platform_card_present,
        .activate = platform_activate_card,
        .send_apdu = platform_send_apdu,
        .sleep_ms = platform_sleep_ms,
    };

    rc522_port_init(&app->port, &ops);
    df_ctx_init_full(&app->ctx,
                     rc522_port_transceive,
                     &app->port,
                     platform_log,
                     platform_random,
                     app,
                     rc522_port_delay,
                     &app->port);
    app->initialized = true;
}

static DFStatus wait_for_card(AppState *app) {
    int retries = 0;
    while (retries++ < 1000) {
        if (rc522_port_card_present(&app->port)) {
            return rc522_port_activate_card(&app->port);
        }
        platform_sleep_ms(app, 10);
    }
    return DF_ERR_NO_CARD;
}

static DFStatus run_desfire_workflow(AppState *app) {
    DFStatus st;
    const uint8_t write_payload[] = {
        'H', 'e', 'l', 'l', 'o', ' ', 'D', 'E', 'S', 'F', 'i', 'r', 'e'
    };
    uint8_t read_back[32];

    printf("DESFire workflow:\n");
    st = df_setup_desfire(&app->ctx,
                          DESFIRE_APP_ID,
                          DESFIRE_PICC_KEY,
                          DESFIRE_APP_MASTER_KEY,
                          DESFIRE_APP_USER_KEY,
                          2,
                          DESFIRE_FILE_NO,
                          DESFIRE_FILE_SIZE,
                          DESFIRE_ACCESS_RIGHTS);
    if (st != DF_OK) {
        printf("  setup failed: %d\n", (int)st);
        return st;
    }

    st = df_select_application(&app->ctx, DESFIRE_APP_ID);
    if (st != DF_OK) {
        printf("  select failed: %d\n", (int)st);
        return st;
    }

    st = df_authenticate_ev2_first(&app->ctx, 2, DESFIRE_APP_USER_KEY);
    if (st != DF_OK) {
        printf("  auth failed: %d\n", (int)st);
        return st;
    }

    st = df_write_data(&app->ctx, DESFIRE_FILE_NO, 0,
                       write_payload, (uint32_t)sizeof(write_payload));
    if (st != DF_OK) {
        printf("  write failed: %d\n", (int)st);
        return st;
    }

    memset(read_back, 0, sizeof(read_back));
    st = df_read_data(&app->ctx, DESFIRE_FILE_NO, 0,
                      (uint32_t)sizeof(write_payload), read_back);
    if (st != DF_OK) {
        printf("  read failed: %d\n", (int)st);
        return st;
    }

    log_hex_bytes("  data=", read_back, sizeof(write_payload));
    return DF_OK;
}

static DFStatus run_dna_workflow(AppState *app) {
    DFStatus st;
    const uint8_t blank_payload[2] = {0x00, 0x00};

    printf("NTAG 424 DNA workflow:\n");
    st = df_setup_dna(&app->ctx, DNA_NEW_KEY, 0, DNA_FILE_NO, DNA_FILE_RIGHTS);
    if (st != DF_OK) {
        printf("  setup failed: %d\n", (int)st);
        return st;
    }

    st = df_select_application(&app->ctx, 0x000001u);
    if (st != DF_OK) {
        printf("  select failed: %d\n", (int)st);
        return st;
    }

    st = df_authenticate_ev2_first(&app->ctx, 0, DNA_AUTH_KEY_DEFAULT);
    if (st != DF_OK) {
        printf("  auth failed: %d\n", (int)st);
        return st;
    }

    /*
     * DNA file 03 is treated as the payload file. This example clears the
     * first bytes to show the blanking flow.
     */
    st = df_write_data(&app->ctx, DNA_FILE_NO, 0,
                       blank_payload, (uint32_t)sizeof(blank_payload));
    if (st != DF_OK) {
        printf("  blank failed: %d\n", (int)st);
        return st;
    }

    return DF_OK;
}

int main(void) {
    AppState app;
    memset(&app, 0, sizeof(app));

    app_init(&app);

    printf("Plain-C DESFire + RC522 reference\n");
    printf("Connect your MCU RC522 driver to platform_* callbacks in this file.\n");
    printf("Then use the complete setup/write/read workflows below.\n\n");
    printf("Flow:\n");
    printf("  1) wait_for_card()\n");
    printf("  2) run_desfire_workflow()\n");
    printf("  3) run_dna_workflow()\n\n");

    if (!app.initialized) {
        return 1;
    }

    while (1) {
        if (wait_for_card(&app) == DF_OK) {
            if (run_desfire_workflow(&app) == DF_OK) {
                printf("DESFire workflow complete\n");
            }
            if (run_dna_workflow(&app) == DF_OK) {
                printf("DNA workflow complete\n");
            }
        }
        platform_sleep_ms(&app, 50);
    }

    return 0;
}
