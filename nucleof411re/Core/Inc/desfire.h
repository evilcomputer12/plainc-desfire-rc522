#ifndef DESFIRE_APP_H
#define DESFIRE_APP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "desfire_cmd.h"
#include "RC522.h"


typedef struct {
    DFContext ctx;
    bool initialized;
    struct {
        bool configured;
        uint32_t appId;
        uint8_t userKeyNo;
        uint8_t appMasterKey[16];
        uint8_t appUserKey[16];
        uint8_t fileNo;
        uint32_t fileSize;
        uint16_t accessRights;
    } df;
    struct {
        bool configured;
        uint8_t userKeyNo;
        uint8_t appUserKey[16];
        uint8_t fileNo;
        uint32_t fileSize;
        uint16_t accessRights;
    } dna;
} AppState;

void platform_sleep_ms(void *user, uint32_t ms);
void platform_random(void *user, uint8_t *buf, size_t len);
void platform_log(const char *label, const char *apdu_hex,
                  const char *resp_hex);

void app_init(AppState *app);
void run_app_shell(AppState *app);
void run_interactive_shell(AppState *app);

DFStatus wait_for_card(AppState *app);

DFStatus run_select_only_test(AppState *app);

DFStatus run_desfire_workflow(AppState *app);

DFStatus run_dna_workflow(AppState *app);

#endif /* DESFIRE_APP_H */
