#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────────────────── */
typedef enum {
    DF_OK              = 0x00,
    DF_ERR_NO_CARD     = -1,
    DF_ERR_TRANSCEIVE  = -2,
    DF_ERR_AUTH        = -3,
    DF_ERR_CMD         = -4,   /* card returned non-OK status word */
    DF_ERR_LEN         = -5,
    DF_ERR_CMAC        = -6,
    DF_ERR_PARAM       = -7,
} DFStatus;

/* ── Card type ───────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  vendorId;
    uint8_t  hwType;
    uint8_t  hwSubType;
    uint8_t  hwMajor;
    uint8_t  hwMinor;
    uint8_t  hwStorage;
    uint8_t  hwProtocol;
    char     name[32];         /* human-readable product name */
    bool     isDNA;
} DFVersionInfo;

/* ── Session state ───────────────────────────────────────────────────── */
typedef struct {
    uint8_t  sessKeyEnc[16];
    uint8_t  sessKeyMac[16];
    uint8_t  ti[4];
    uint16_t cmdCounter;
    uint8_t  authKeyNo;
    bool     active;
} DFSession;

/* ── Log callback ────────────────────────────────────────────────────── */
/* Called after every APDU exchange. apdu/resp are hex strings. */
typedef void (*df_log_fn)(const char *label, const char *apdu_hex,
                          const char *resp_hex);
typedef void (*df_random_fn)(void *user, uint8_t *buf, size_t len);
typedef void (*df_delay_fn)(void *user, uint32_t ms);

/* ── Context ─────────────────────────────────────────────────────────── */
typedef struct DFContext DFContext;

/* transceive function pointer — wraps TCL_Transceive */
typedef DFStatus (*df_transceive_fn)(void *user, const uint8_t *send,
                                     uint8_t send_len, uint8_t *resp,
                                     uint8_t *resp_len);

struct DFContext {
    df_transceive_fn  transceive;
    void             *user;          /* passed to transceive */
    df_random_fn      random;        /* optional random source */
    void             *random_user;   /* passed to random */
    df_delay_fn       delay;        /* optional timing hook */
    void             *delay_user;    /* passed to delay */
    df_log_fn         log;           /* optional, may be NULL */
    DFSession         session;
    bool              isDNA;
};

typedef struct {
    uint8_t keySettings1;
    uint8_t keySettings2;
    uint8_t numKeys;
} DFKeySettings;

/* ── Init ────────────────────────────────────────────────────────────── */
void df_ctx_init(DFContext *ctx, df_transceive_fn transceive, void *user,
                 df_log_fn log);

/* Convenience initializer for portable apps that want to bind all callbacks
   in one call. Any optional callback may be NULL. */
void df_ctx_init_full(DFContext *ctx, df_transceive_fn transceive, void *user,
                      df_log_fn log,
                      df_random_fn random, void *random_user,
                      df_delay_fn delay, void *delay_user);

void df_ctx_set_random(DFContext *ctx, df_random_fn random, void *user);
void df_ctx_set_delay(DFContext *ctx, df_delay_fn delay, void *user);
void df_ctx_set_log(DFContext *ctx, df_log_fn log);

/* Random bytes for DESFire auth/session use. Falls back to a portable PRNG
   if the app does not provide a hardware entropy callback. */
void df_random_bytes(DFContext *ctx, uint8_t *buf, size_t len);

/* ── Commands ────────────────────────────────────────────────────────── */

/* GetVersion — fills DFVersionInfo, sets ctx->isDNA */
DFStatus df_get_version(DFContext *ctx, DFVersionInfo *out);

/* SelectApplication — appId is 3-byte little-endian (pass as uint32, low 24 bits) */
DFStatus df_select_application(DFContext *ctx, uint32_t appId);

/* GetKeySettings — returns the two key-setting bytes for the selected app */
DFStatus df_get_key_settings(DFContext *ctx, DFKeySettings *out);

/* AuthenticateLegacy (0x0A) — 3DES/DES, for PICC master key on factory cards.
   Does NOT set ctx->session (legacy session has no EV2 MAC/counter).
   key16: 16-byte 2K3DES key (factory = all zeros). */
DFStatus df_authenticate_legacy(DFContext *ctx, uint8_t keyNo,
                                 const uint8_t key16[16]);

/* AuthenticateISO (0x1A) — ISO 3K3DES PICC auth. */
DFStatus df_authenticate_iso(DFContext *ctx, uint8_t keyNo,
                             const uint8_t key24[24]);

/* AuthenticateEV2First — AES-128, sets ctx->session on success */
DFStatus df_authenticate_ev2_first(DFContext *ctx, uint8_t keyNo,
                                   const uint8_t key[16]);

/* FormatPICC — requires auth on PICC master (app 0x000000, key 0) */
DFStatus df_format_picc(DFContext *ctx);

/* CreateApplication — KS2 = 0x80|(numKeys&0x0F), KS1=0xEF */
DFStatus df_create_application(DFContext *ctx, uint32_t appId, uint8_t numKeys);

/* CreateStdDataFile */
DFStatus df_create_std_data_file(DFContext *ctx, uint8_t fileNo,
                                 uint8_t commMode, uint16_t accessRights,
                                 uint32_t fileSize);

/* ChangeKey — keyNo 0..N, oldKey/newKey are 16-byte AES keys */
DFStatus df_change_key(DFContext *ctx, uint8_t keyNo,
                       const uint8_t oldKey[16], const uint8_t newKey[16],
                       uint8_t keyVersion);

/* ChangeFileSettings */
DFStatus df_change_file_settings(DFContext *ctx, uint8_t fileNo,
                                 uint8_t commMode, uint16_t accessRights);

/* WriteData (CommMode.Full, EV2 secure messaging) */
DFStatus df_write_data(DFContext *ctx, uint8_t fileNo,
                       uint32_t offset, const uint8_t *data, uint32_t len);

/* ReadData (CommMode.Full, EV2 secure messaging), out must hold len bytes */
DFStatus df_read_data(DFContext *ctx, uint8_t fileNo,
                      uint32_t offset, uint32_t len, uint8_t *out);

/* Convenience: select app 0 + auth key 0, then FormatPICC */
DFStatus df_full_format(DFContext *ctx, const uint8_t masterKey[16]);

/* Convenience: format + create app + create file + optionally change keys */
DFStatus df_setup_desfire(DFContext *ctx, uint32_t appId,
                          const uint8_t piccMasterKey[16],
                          const uint8_t appMasterKey[16],
                          const uint8_t appUserKey[16],
                          uint8_t userKeyNo,
                          uint8_t fileNo, uint32_t fileSize,
                          uint16_t fileAccessRights);

/* For NTAG 424 DNA: no format/createApp. The caller must ISO-select the
   NDEF AID first, then this helper updates file 03 and key material in-place.
   The card is expected to be factory-fresh (key 0 = all zeros). */
DFStatus df_setup_dna(DFContext *ctx,
                      const uint8_t appUserKey[16],
                      uint8_t userKeyNo,
                      uint8_t fileNo,
                      uint16_t fileAccessRights);

/* Status word → human readable */
const char *df_sw_describe(uint8_t sw);

#ifdef __cplusplus
}
#endif
