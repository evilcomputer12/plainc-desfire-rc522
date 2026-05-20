#include "desfire.h"

/*
 * Plain-C DESFire + RC522 end-to-end example
 *
 * This example shows the full wiring chain:
 *   platform RC522 driver -> rc522_port_t -> DFContext -> DESFire wrappers
 *
 * Replace the platform_* functions with your own MCU/RC522 implementation.
 * The DESFire library itself remains unchanged.
 */



static const uint32_t DESFIRE_APP_ID = 0x010203u;
static const uint8_t DESFIRE_FILE_NO = 0x02u;
static const uint32_t DESFIRE_FILE_SIZE = 128u;
static const uint16_t DESFIRE_ACCESS_RIGHTS = 0x2220u;
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

#ifndef DESFIRE_VERBOSE
#define DESFIRE_VERBOSE 0
#endif

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

static void dump_rc522_state(const char *reason) {
    uint8_t cmd = Read_MFRC522(CommandReg);
    uint8_t irq = Read_MFRC522(CommIrqReg);
    uint8_t err = Read_MFRC522(ErrorReg);
    uint8_t s1 = Read_MFRC522(Status1Reg);
    uint8_t s2 = Read_MFRC522(Status2Reg);
    uint8_t fifo = Read_MFRC522(FIFOLevelReg);
    uint8_t rf = Read_MFRC522(RFCfgReg);

    printf("[NFC] rc522[%s]: CMD=%02X IRQ=%02X ERR=%02X S1=%02X S2=%02X FIFO=%02X RF=%02X\n",
           reason ? reason : "?", cmd, irq, err, s1, s2, fifo, rf);
}

static bool platform_card_present(void *user) {
    AppState *app = (AppState *)user;
    uint8_t tag_type[MAX_LEN] = {0};
    uchar rc;

    if (!app) {
        return false;
    }

    rc = MFRC522_Request(PICC_REQIDL, tag_type);
    if (rc != MI_OK) {
        rc = MFRC522_Request(PICC_REQALL, tag_type);
    }
    return rc == MI_OK;
}

static DFStatus platform_activate_card(void *user) {
    AppState *app = (AppState *)user;
    uint8_t uid1[MAX_LEN] = {0};
    uint8_t uid2[MAX_LEN] = {0};
    uchar rc;
    uint8_t sak;

    if (!app) {
        return DF_ERR_PARAM;
    }

    rc = MFRC522_AnticollCascade(PICC_ANTICOLL, uid1);
    printf("[NFC] activate: anticoll cl1 rc=%u uid=%02X %02X %02X %02X %02X\n",
           (unsigned)rc, uid1[0], uid1[1], uid1[2], uid1[3], uid1[4]);
    if (rc != MI_OK) {
        dump_rc522_state("activate-anticoll-fail");
        return DF_ERR_TRANSCEIVE;
    }
    platform_sleep_ms(app, 1);

    sak = MFRC522_SelectTagCascade(PICC_SElECTTAG, uid1);
    printf("[NFC] activate: select cl1 sak=0x%02X\n", sak);
    if (sak == 0) {
        dump_rc522_state("activate-select-fail");
        return DF_ERR_TRANSCEIVE;
    }
    platform_sleep_ms(app, 1);

    if (sak & 0x04u) {
        rc = MFRC522_AnticollCascade(PICC_ANTICOLL2, uid2);
        printf("[NFC] activate: anticoll cl2 rc=%u uid=%02X %02X %02X %02X %02X\n",
               (unsigned)rc, uid2[0], uid2[1], uid2[2], uid2[3], uid2[4]);
        if (rc != MI_OK) {
            dump_rc522_state("activate-anticoll2-fail");
            return DF_ERR_TRANSCEIVE;
        }
        platform_sleep_ms(app, 1);

        sak = MFRC522_SelectTagCascade(PICC_SElECTTAG2, uid2);
        printf("[NFC] activate: select cl2 sak=0x%02X\n", sak);
        if (sak == 0) {
            dump_rc522_state("activate-select2-fail");
            return DF_ERR_TRANSCEIVE;
        }
        platform_sleep_ms(app, 1);
    }

    platform_sleep_ms(app, 2);
    rc = MFRC522_RATS();
    printf("[NFC] activate: rats rc=%u\n", (unsigned)rc);
    if (rc != MI_OK) {
        dump_rc522_state("activate-rats-fail");
        return DF_ERR_TRANSCEIVE;
    }
    return DF_OK;
}

static DFStatus platform_send_apdu(void *user,
                                    const uint8_t *tx,
                                    uint8_t tx_len,
                                    uint8_t *rx,
                                    uint8_t *rx_len) {
    AppState *app = (AppState *)user;
    if (app && tx_len > 0 && rx && rx_len) {
        uint8_t rx_buf[256];
        uint32_t rx_buf_len = sizeof(rx_buf);   /* len = sizeof(data_buff) */
        uint8_t ins = (tx_len >= 2u) ? tx[1] : 0u;
        printf("[NFC] APDU TX len=%u ins=0x%02X FSC=%u\n",
               (unsigned)tx_len, (unsigned)ins, (unsigned)MFRC522_GetIsoFsc());
        uint8_t status = MFRC522_14443P4_Transceive((uint8_t *)tx, tx_len,
                                                     rx_buf, &rx_buf_len);
        if (status == MI_OK) {
            uint8_t n = (rx_buf_len > 255u) ? 255u : (uint8_t)rx_buf_len;
            memcpy(rx, rx_buf, n);
            *rx_len = n;
            printf("[NFC] APDU RX len=%u", (unsigned)n);
            if (n >= 2u) {
                printf(" SW=%02X%02X", rx[n - 2], rx[n - 1]);
            }
            printf("\n");
        } else {
            *rx_len = 0;
            printf("[NFC] APDU RX fail (MI_ERR=%u)\n", (unsigned)status);
            MFRC522_DumpRegs("apdu-fail");
        }
        return (status == MI_OK) ? DF_OK : DF_ERR_TRANSCEIVE;
    }
    return DF_ERR_PARAM;
}


void platform_sleep_ms(void *user, uint32_t ms) {
    (void)user;
    (void)ms;
    HAL_Delay(ms);
}

void platform_random(void *user, uint8_t *buf, size_t len) {
    (void)user;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u)) ^ (uint8_t)rand();
    }
}

void platform_log(const char *label, const char *apdu_hex,
                  const char *resp_hex) {
    bool has_tx = apdu_hex && apdu_hex[0];
    bool has_rx = resp_hex && resp_hex[0];

    if (label && label[0]) {
        if (has_tx) {
            printf("\n[%s]\n", label);
        } else {
            printf("  %s\n", label);
        }
    }
    if (has_tx) {
        printf("  TX: %s\n", apdu_hex);
    }
    if (has_rx) {
        printf("  RX: %s\n", resp_hex);
    }
}

void app_init(AppState *app) {
    static const uint8_t df_master_default[16] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
    };
    static const uint8_t df_user_default[16] = {
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
    };
    static const uint8_t dna_default_key[16] = {0x00};

    MFRC522_Init();
    df_ctx_init_full(&app->ctx,
                     platform_send_apdu,
                     app,
                     platform_log,
                     platform_random,
                     app,
                     platform_sleep_ms,
                     app);
    app->df.configured = true;
    app->df.appId = 0x010203u;
    app->df.userKeyNo = 2;
    memcpy(app->df.appMasterKey, df_master_default, sizeof(df_master_default));
    memcpy(app->df.appUserKey, df_user_default, sizeof(df_user_default));
    app->df.fileNo = 0x02u;
    app->df.fileSize = 256u;
    app->df.accessRights = 0x2220u;

    app->dna.configured = true;
    app->dna.userKeyNo = 0;
    memcpy(app->dna.appUserKey, dna_default_key, sizeof(dna_default_key));
    app->dna.fileNo = 0x03u;
    app->dna.fileSize = 128u;
    app->dna.accessRights = 0x0330u;

    app->initialized = true;
    uart_rx_start();
}

DFStatus wait_for_card(AppState *app) {
    int retries = 0;
    while (retries++ < 100) {
        bool present = platform_card_present(app);
        if (present) {
            printf("[NFC] card present\n");
            DFStatus st = platform_activate_card(app);
            printf("[NFC] wait: activate status=%d\n", (int)st);
            return st;
        }
        platform_sleep_ms(app, 25);
    }
    printf("[NFC] no card detected after %d ms\n", 100 * 25);
    return DF_ERR_NO_CARD;
}

DFStatus run_desfire_workflow(AppState *app) {
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

DFStatus run_select_only_test(AppState *app) {
    if (!app) {
        return DF_ERR_PARAM;
    }

    printf("Select-only probe:\n");
    return platform_activate_card(app);
}

DFStatus run_dna_workflow(AppState *app) {
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
