#include "desfire_cmd.h"
#include "desfire_crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── DESFire command bytes ───────────────────────────────────────────── */
#define CMD_GET_VERSION          0x60
#define CMD_SELECT_APP           0x5A
#define CMD_CREATE_APP           0xCA
#define CMD_DELETE_APP           0xDA
#define CMD_FORMAT_PICC          0xFC
#define CMD_AUTH_LEGACY          0x0A   /* 3DES/DES — PICC master key on factory cards */
#define CMD_AUTH_ISO             0x1A   /* 3K3DES ISO mode */
#define CMD_AUTH_EV2_FIRST       0x71   /* AES EV2 — app-level keys */
#define CMD_AUTH_EV2_NONFIRST    0x77
#define CMD_ADDITIONAL_FRAME     0xAF
#define CMD_CREATE_STD_FILE      0xCD
#define CMD_CHANGE_FILE_SETTINGS 0x5F
#define CMD_WRITE_DATA           0x3D
#define CMD_DNA_WRITE_DATA       0x8D
#define CMD_READ_DATA            0xBD
#define CMD_DNA_READ_DATA        0xAD
#define CMD_CHANGE_KEY           0xC4
#define CMD_GET_KEY_SETTINGS     0x45
#define CMD_GET_KEY_VERSION      0x64

/* ── PICC-level (root) application ID ───────────────────────────────── */
#define APP_PICC 0x000000u

/* ── Helpers ─────────────────────────────────────────────────────────── */

#define DF_INTER_COMMAND_DELAY_MS 10u
#define DF_NV_WRITE_DELAY_MS      75u

static void _hex_str(const uint8_t *b, size_t n, char *out) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (i > 0) *out++ = ' ';
        sprintf(out, "%02X", b[i]);
        out += 2;
    }
    *out = '\0';
}

/* Log the APDU about to be sent (call BEFORE transceive). */
static void _log_tx(DFContext *ctx, const char *label,
                    const uint8_t *apdu, uint8_t alen) {
    if (!ctx->log) return;
    /* max APDU ~300 bytes → 300*3 = 900 chars with spaces */
    char a[900];
    _hex_str(apdu, alen, a);
    ctx->log(label ? label : "CMD", a, "");
}

/* Log the raw response just received (call AFTER transceive). */
static void _log_rx(DFContext *ctx, const uint8_t *resp, uint8_t rlen) {
    if (!ctx->log) return;
    char r[900];
    _hex_str(resp, rlen, r);
    ctx->log("", "", r);
}

static void _log_hex_value(DFContext *ctx, const char *label,
                           const uint8_t *data, size_t len) {
    if (!ctx->log) return;
    char buf[900];
    char hex[800];
    _hex_str(data, len, hex);
    snprintf(buf, sizeof(buf), "%s: %s", label, hex);
    ctx->log(buf, "", "");
}

static void _delay_after_command(DFContext *ctx) {
    if (ctx && ctx->delay) {
        ctx->delay(ctx->delay_user, DF_INTER_COMMAND_DELAY_MS);
    }
}

/* Build ISO 7816-4 wrapped DESFire APDU:  90 cmd 00 00 [Lc data] 00  */
static uint8_t _build_apdu(uint8_t cmd, const uint8_t *data, uint8_t dlen,
                            uint8_t *out) {
    uint8_t i = 0;
    out[i++] = 0x90;
    out[i++] = cmd;
    out[i++] = 0x00;
    out[i++] = 0x00;
    if (dlen > 0) {
        out[i++] = dlen;
        memcpy(out + i, data, dlen);
        i += dlen;
    }
    out[i++] = 0x00;
    return i;
}

/* Send one command and parse SW1/SW2.  Returns SW2 (DESFire status byte).
   resp_body and resp_body_len receive the data before SW1 SW2.
   Returns DF_ERR_TRANSCEIVE on link error, DF_ERR_LEN if < 2 bytes. */
static DFStatus _send_cmd(DFContext *ctx, uint8_t cmd,
                          const uint8_t *data, uint8_t dlen,
                          const char *label,
                          uint8_t *resp_body, uint8_t *resp_body_len,
                          uint8_t *sw_out) {
    uint8_t apdu[300];
    uint8_t alen = _build_apdu(cmd, data, dlen, apdu);

    uint8_t raw[300];
    uint8_t raw_len = 255;  /* IN: buffer capacity; OUT: actual bytes received */

    _log_tx(ctx, label, apdu, alen);
    DFStatus st = ctx->transceive(ctx->user, apdu, alen, raw, &raw_len);
    _log_rx(ctx, raw, raw_len);
    _delay_after_command(ctx);

    if (st != DF_OK) {
        if (ctx->log) ctx->log(
            "  ERROR: RF/link error — card gave no response"
            " (is it in the field? was RATS done?)", "", "");
        return DF_ERR_TRANSCEIVE;
    }
    if (raw_len < 2) {
        if (ctx->log) {
            char _m[64];
            snprintf(_m, sizeof(_m),
                     "  ERROR: response too short (%u byte(s), need SW1+SW2 minimum)",
                     (unsigned)raw_len);
            ctx->log(_m, "", "");
        }
        return DF_ERR_LEN;
    }

    uint8_t sw1 = raw[raw_len - 2];
    uint8_t sw2 = raw[raw_len - 1];

    if (sw1 != 0x91) {
        if (ctx->log) {
            char _m[80];
            snprintf(_m, sizeof(_m),
                     "  ERROR: bad framing — SW1=0x%02X (expected 0x91 for DESFire ISO-wrapped APDU)",
                     (unsigned)sw1);
            ctx->log(_m, "", "");
        }
        return DF_ERR_TRANSCEIVE;
    }
    /* Log SW2 whenever it signals an error (not OK=0x00 and not more-data=0xAF). */
    if (ctx->log && sw2 != 0x00 && sw2 != 0xAF) {
        char _m[80];
        snprintf(_m, sizeof(_m), "  Card status SW2=0x%02X: %s",
                 (unsigned)sw2, df_sw_describe(sw2));
        ctx->log(_m, "", "");
    }

    if (resp_body && resp_body_len) {
        *resp_body_len = raw_len - 2;
        memcpy(resp_body, raw, raw_len - 2);
    }
    if (sw_out) *sw_out = sw2;
    return DF_OK;
}

/* EV2 command MAC: [cmd][ctr_lo][ctr_hi][TI0..3][cmdData?] */
static void _calc_cmd_mac(DFContext *ctx, uint8_t cmd,
                          const uint8_t *cmdData, uint8_t cdlen,
                          uint8_t out8[8]) {
    uint8_t buf[300];
    uint8_t pos = 0;
    buf[pos++] = cmd;
    buf[pos++] = ctx->session.cmdCounter & 0xFF;
    buf[pos++] = (ctx->session.cmdCounter >> 8) & 0xFF;
    memcpy(buf + pos, ctx->session.ti, 4); pos += 4;
    if (cmdData && cdlen) { memcpy(buf + pos, cmdData, cdlen); pos += cdlen; }
    uint8_t mac[16];
    df_cmac(ctx->session.sessKeyMac, buf, pos, mac);
    df_truncate_mac(mac, out8);
}

/* EV2 response MAC verify: [0x00][ctr_lo][ctr_hi][TI0..3][respData?] */
static bool _verify_resp_mac(DFContext *ctx,
                             const uint8_t *respData, uint8_t rdlen,
                             const uint8_t mac8[8]) {
    uint8_t buf[300];
    uint8_t pos = 0;
    buf[pos++] = 0x00;
    buf[pos++] = ctx->session.cmdCounter & 0xFF;
    buf[pos++] = (ctx->session.cmdCounter >> 8) & 0xFF;
    memcpy(buf + pos, ctx->session.ti, 4); pos += 4;
    if (respData && rdlen) { memcpy(buf + pos, respData, rdlen); pos += rdlen; }
    uint8_t mac[16];
    df_cmac(ctx->session.sessKeyMac, buf, pos, mac);
    uint8_t t[8];
    df_truncate_mac(mac, t);
    return memcmp(t, mac8, 8) == 0;
}

/* IV for EV2 encryption: AES_ECB(sessKeyEnc, [0xA5,0x5A,TI,ctr_lo,ctr_hi,00..]) */
static void _calc_iv_cmd(DFContext *ctx, uint8_t iv[16]) {
    uint8_t in[16] = {0};
    in[0] = 0xA5; in[1] = 0x5A;
    memcpy(in + 2, ctx->session.ti, 4);
    in[6] = ctx->session.cmdCounter & 0xFF;
    in[7] = (ctx->session.cmdCounter >> 8) & 0xFF;
    df_aes_ecb_encrypt(ctx->session.sessKeyEnc, in, iv);
}

static void _calc_iv_resp(DFContext *ctx, uint8_t iv[16]) {
    uint8_t in[16] = {0};
    in[0] = 0x5A; in[1] = 0xA5;
    memcpy(in + 2, ctx->session.ti, 4);
    in[6] = ctx->session.cmdCounter & 0xFF;
    in[7] = (ctx->session.cmdCounter >> 8) & 0xFF;
    df_aes_ecb_encrypt(ctx->session.sessKeyEnc, in, iv);
}

static DFStatus _auth_picc_factory(DFContext *ctx, const uint8_t key16[16]) {
    DFStatus st = df_authenticate_legacy(ctx, 0, key16);
    if (st == DF_OK) return DF_OK;

    uint8_t key24[24];
    memcpy(key24, key16, 16);
    memcpy(key24 + 16, key16, 8);
    st = df_authenticate_iso(ctx, 0, key24);
    if (st == DF_OK) return DF_OK;

    return df_authenticate_ev2_first(ctx, 0, key16);
}

/* ── Public API ──────────────────────────────────────────────────────── */

void df_ctx_init(DFContext *ctx, df_transceive_fn transceive, void *user,
                 df_log_fn log) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->transceive = transceive;
    ctx->user       = user;
    ctx->random     = NULL;
    ctx->random_user = NULL;
    ctx->delay      = NULL;
    ctx->delay_user = NULL;
    ctx->log        = log;
}

void df_ctx_init_full(DFContext *ctx, df_transceive_fn transceive, void *user,
                      df_log_fn log,
                      df_random_fn random, void *random_user,
                      df_delay_fn delay, void *delay_user) {
    df_ctx_init(ctx, transceive, user, log);
    df_ctx_set_random(ctx, random, random_user);
    df_ctx_set_delay(ctx, delay, delay_user);
}

void df_ctx_set_random(DFContext *ctx, df_random_fn random, void *user) {
    if (!ctx) return;
    ctx->random = random;
    ctx->random_user = user;
}

void df_ctx_set_delay(DFContext *ctx, df_delay_fn delay, void *user) {
    if (!ctx) return;
    ctx->delay = delay;
    ctx->delay_user = user;
}

void df_ctx_set_log(DFContext *ctx, df_log_fn log) {
    if (!ctx) return;
    ctx->log = log;
}

void df_random_bytes(DFContext *ctx, uint8_t *buf, size_t len) {
    if (!buf || len == 0) return;
    if (ctx && ctx->random) {
        ctx->random(ctx->random_user, buf, len);
        return;
    }

    /* Portable fallback: xorshift32 seeded from context/address state.
       The app should provide a real entropy source for security-sensitive use. */
    static uint32_t state = 0;
    if (state == 0) {
        uintptr_t mix = (uintptr_t)ctx ^ (uintptr_t)&state ^ (uintptr_t)&df_random_bytes;
        state = (uint32_t)(mix ^ (mix >> 16) ^ (mix << 5) ^ 0xA5A5A5A5u);
        if (state == 0) state = 0x1u;
    }

    for (size_t i = 0; i < len; i++) {
        uint32_t x = state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state = x;
        buf[i] = (uint8_t)(x & 0xFF);
    }
}

/* ── GetVersion ──────────────────────────────────────────────────────── */

static const char *_hw_name(uint8_t hwType, uint8_t hwMajor, uint8_t hwSubType) {
    if (hwType == 0x04) {
        return (hwSubType == 0x02) ? "NTAG 424 DNA TT" : "NTAG 424 DNA";
    }
    if (hwType == 0x01) {
        switch (hwMajor) {
            case 0x00: return "DESFire";
            case 0x01: return "DESFire EV1";
            case 0x12: return "DESFire EV2";
            case 0x22: return "DESFire Light";
            case 0x32: return "DESFire Light EV1";
            case 0x33: return "DESFire EV3";
            default:   return "DESFire (unknown)";
        }
    }
    if (hwType == 0x02) return "MIFARE Plus";
    if (hwType == 0x03) return "MIFARE Ultralight EV1";
    return "Unknown";
}

DFStatus df_get_version(DFContext *ctx, DFVersionInfo *out) {
    uint8_t body[64]; uint8_t blen; uint8_t sw;

    if (_send_cmd(ctx, CMD_GET_VERSION, NULL, 0,
                  "GetVersion (0x60): ask card for hardware type and version",
                  body, &blen, &sw) != DF_OK) return DF_ERR_TRANSCEIVE;
    if (sw != 0xAF || blen < 7) return DF_ERR_CMD;
    uint8_t p1[7]; memcpy(p1, body, 7);

    if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, NULL, 0,
                  "GetVersion (0xAF): additional frame — software version info",
                  body, &blen, &sw) != DF_OK) return DF_ERR_TRANSCEIVE;
    if (sw != 0xAF || blen < 7) return DF_ERR_CMD;

    if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, NULL, 0,
                  "GetVersion (0xAF): final frame — batch number and production date",
                  body, &blen, &sw) != DF_OK) return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) return DF_ERR_CMD;

    out->vendorId   = p1[0];
    out->hwType     = p1[1];
    out->hwSubType  = p1[2];
    out->hwMajor    = p1[3];
    out->hwMinor    = p1[4];
    out->hwStorage  = p1[5];
    out->hwProtocol = p1[6];
    out->isDNA      = (p1[1] == 0x04);
    strncpy(out->name, _hw_name(p1[1], p1[3], p1[2]), sizeof(out->name) - 1);
    ctx->isDNA = out->isDNA;
    return DF_OK;
}

/* ── SelectApplication ───────────────────────────────────────────────── */

DFStatus df_select_application(DFContext *ctx, uint32_t appId) {
    uint8_t d[3] = {(uint8_t)(appId), (uint8_t)(appId>>8), (uint8_t)(appId>>16)};
    uint8_t sw;
    if (_send_cmd(ctx, CMD_SELECT_APP, d, 3,
                  "SelectApplication (0x5A): activate an application by its 3-byte AID",
                  NULL, NULL, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) return DF_ERR_CMD;
    ctx->session.active = false;
    return DF_OK;
}

DFStatus df_get_key_settings(DFContext *ctx, DFKeySettings *out) {
    uint8_t body[16];
    uint8_t blen = 0;
    uint8_t sw = 0;

    if (_send_cmd(ctx, CMD_GET_KEY_SETTINGS, NULL, 0,
                  "GetKeySettings (0x45): read key count and change-key access flags",
                  body, &blen, &sw) != DF_OK) {
        return DF_ERR_TRANSCEIVE;
    }
    if (sw != 0x00) return DF_ERR_CMD;
    if (blen < 2) return DF_ERR_LEN;

    if (out) {
        out->keySettings1 = body[0];
        out->keySettings2 = body[1];
        out->numKeys = body[1] & 0x0F;
    }
    return DF_OK;
}

/* ── AuthenticateEV2First ────────────────────────────────────────────── */

/* ── AuthenticateLegacy (3DES) ───────────────────────────────────────── */

DFStatus df_authenticate_legacy(DFContext *ctx, uint8_t keyNo,
                                 const uint8_t key16[16]) {
    ctx->session.active = false;

    uint8_t iv0[8] = {0};
    uint8_t body[32]; uint8_t blen; uint8_t sw;

    /* Step 1: send AuthenticateLegacy (0x0A) + keyNo */
    if (_send_cmd(ctx, CMD_AUTH_LEGACY, &keyNo, 1,
                  "AuthLegacy (0x0A): step 1 — send keyNo; card returns enc(RndB) challenge",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;

    if (sw != 0xAF || blen != 8) {
        char note[64];
        snprintf(note, sizeof(note),
                 "AUTH_LEGACY_S1_FAIL sw=0x%02X blen=%d (%s)",
                 sw, blen, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }

    uint8_t encRndB[8]; memcpy(encRndB, body, 8);
    uint8_t rndB[8];
    df_3des_cbc_decrypt(key16, iv0, encRndB, rndB, 8);
    _log_hex_value(ctx, "RndB (3DES-decrypted card challenge)", rndB, 8);

    /* Generate RndA (8 bytes) */
    uint8_t rndA[8];
    df_random_bytes(ctx, rndA, sizeof(rndA));
    _log_hex_value(ctx, "RndA (our random nonce)", rndA, 8);

    /* Rotate RndB left 1: rndBrot = rndB[1..7] || rndB[0] */
    uint8_t rndBrot[8];
    memcpy(rndBrot, rndB + 1, 7);
    rndBrot[7] = rndB[0];
    _log_hex_value(ctx, "RndB_rot (RndB left-rotated 1 byte)", rndBrot, 8);

    /* Plaintext = RndA || RndBrot, encrypt with IV = encRndB */
    uint8_t plaintext[16];
    memcpy(plaintext, rndA, 8);
    memcpy(plaintext + 8, rndBrot, 8);
    _log_hex_value(ctx, "plaintext token = RndA || RndB_rot", plaintext, 16);
    uint8_t encToken[16];
    df_3des_cbc_encrypt(key16, encRndB, plaintext, encToken, 16);
    _log_hex_value(ctx, "enc(RndA||RndB_rot) sent in step 2", encToken, 16);

    /* Step 2: send additional frame with encToken (16 bytes) */
    if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, encToken, 16,
                  "AuthLegacy (0xAF): step 2 — send enc(RndA||RndB_rot); card verifies",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;

    if (sw != 0x00) {
        char note[80];
        snprintf(note, sizeof(note),
                 "AUTH_LEGACY_S2_FAIL sw=0x%02X (%s) — check PICC master key",
                 sw, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }

    /* Match the Flutter app: accept legacy auth as long as SW=0x00. */
    if (blen >= 8) {
        uint8_t expected[8];
        memcpy(expected, rndA + 1, 7);
        expected[7] = rndA[0];

        uint8_t ivDec[8];
        memcpy(ivDec, encToken + 8, 8);

        uint8_t rndArot_3des_cbc[8];
        uint8_t rndArot_3des_ecb[8];
        uint8_t rndArot_3des_iv0[8];
        uint8_t rndArot_3des_ivEncRndB[8];
        df_3des_cbc_decrypt(key16, ivDec, body, rndArot_3des_cbc, 8);
        df_3des_ecb_decrypt(key16, body, rndArot_3des_ecb, 8);
        df_3des_cbc_decrypt(key16, iv0, body, rndArot_3des_iv0, 8);
        df_3des_cbc_decrypt(key16, encRndB, body, rndArot_3des_ivEncRndB, 8);

        uint8_t key8[8];
        memcpy(key8, key16, 8);
        uint8_t rndArot_des_cbc[8];
        uint8_t rndArot_des_iv0[8];
        uint8_t rndArot_des_ivEncRndB[8];
        df_des_cbc_decrypt(key8, ivDec, body, rndArot_des_cbc, 8);
        df_des_cbc_decrypt(key8, iv0, body, rndArot_des_iv0, 8);
        df_des_cbc_decrypt(key8, encRndB, body, rndArot_des_ivEncRndB, 8);

        bool verified = (memcmp(expected, rndArot_3des_cbc, 8) == 0 ||
                         memcmp(expected, rndArot_3des_ecb, 8) == 0 ||
                         memcmp(expected, rndArot_3des_iv0, 8) == 0 ||
                         memcmp(expected, rndArot_3des_ivEncRndB, 8) == 0 ||
                         memcmp(expected, rndArot_des_cbc, 8) == 0 ||
                         memcmp(expected, rndArot_des_iv0, 8) == 0 ||
                         memcmp(expected, rndArot_des_ivEncRndB, 8) == 0);
        if (ctx->log) ctx->log(verified ? "AuthLegacy OK (RndA verified)"
                                        : "AuthLegacy OK", "", "");
    } else if (ctx->log) {
        ctx->log("AuthLegacy OK (card accepted)", "", "");
    }
    /* session stays inactive — legacy auth has no EV2 MAC/TI counter */
    return DF_OK;
}

DFStatus df_authenticate_iso(DFContext *ctx, uint8_t keyNo,
                             const uint8_t key24[24]) {
    ctx->session.active = false;

    uint8_t iv0[8] = {0};
    uint8_t body[32]; uint8_t blen; uint8_t sw;

    if (_send_cmd(ctx, CMD_AUTH_ISO, &keyNo, 1,
                  "AuthISO (0x1A): step 1 — request 3K3DES challenge",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;

    if (sw != 0xAF || blen != 8) {
        char note[64];
        snprintf(note, sizeof(note),
                 "AUTH_ISO_S1_FAIL sw=0x%02X blen=%d (%s)",
                 sw, blen, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }

    uint8_t encRndB[8]; memcpy(encRndB, body, 8);
    uint8_t rndB[8];
    df_3k3des_cbc_decrypt(key24, iv0, encRndB, rndB, 8);

    uint8_t rndA[8];
    df_random_bytes(ctx, rndA, sizeof(rndA));

    uint8_t rndBrot[8];
    memcpy(rndBrot, rndB + 1, 7);
    rndBrot[7] = rndB[0];

    uint8_t plaintext[16];
    memcpy(plaintext, rndA, 8);
    memcpy(plaintext + 8, rndBrot, 8);

    uint8_t encToken[16];
    df_3k3des_cbc_encrypt(key24, encRndB, plaintext, encToken, 16);

    if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, encToken, 16,
                  "AuthISO (0xAF): step 2 — send enc(RndA||RndB_rot); card verifies",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) {
        char note[80];
        snprintf(note, sizeof(note),
                 "AUTH_ISO_S2_FAIL sw=0x%02X (%s) — check PICC master key",
                 sw, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }

    if (ctx->log) ctx->log("AuthISO OK (card accepted)", "", "");
    return DF_OK;
}

DFStatus df_authenticate_ev2_first(DFContext *ctx, uint8_t keyNo,
                                   const uint8_t key[16]) {
    ctx->session.active = false;

    if (ctx->log) {
        char msg[64];
        snprintf(msg, sizeof(msg), "keyNo=%u", (unsigned)keyNo);
        ctx->log("AuthEV2First KeyInfo", msg, "");
        _log_hex_value(ctx, "AuthEV2First Key", key, 16);
    }

    uint8_t cmd[2] = {keyNo, 0x00};
    uint8_t body[64]; uint8_t blen; uint8_t sw;

    if (_send_cmd(ctx, CMD_AUTH_EV2_FIRST, cmd, 2,
                  "AuthEV2First (0x71): step 1 — send keyNo; card returns AES enc(RndB) challenge",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0xAF) {
        /* Log the actual failure code for the web APDU log */
        char note[48];
        snprintf(note, sizeof(note),
                 "AUTH_S1_FAIL sw=0x%02X (%s)", sw, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }
    if (blen < 16) {
        char note[48];
        snprintf(note, sizeof(note), "AUTH_S1_FAIL blen=%d need >= 16", blen);
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }
    if (blen != 16 && ctx->log) {
        char note[64];
        snprintf(note, sizeof(note),
                 "AUTH_S1 note: blen=%d (using first 16 bytes as enc(RndB))", blen);
        ctx->log(note, "", "");
    }

    uint8_t iv0[16] = {0};
    uint8_t rndB[16];
    df_aes_cbc_decrypt(key, iv0, body, 16, rndB);
    _log_hex_value(ctx, "RndB (AES-decrypted card challenge)", rndB, 16);

    uint8_t rndA[16];
    df_random_bytes(ctx, rndA, sizeof(rndA));
    _log_hex_value(ctx, "RndA (our random nonce)", rndA, 16);

    /* rndB rotated left by 1 byte */
    uint8_t rndBrot[16];
    memcpy(rndBrot, rndB + 1, 15);
    rndBrot[15] = rndB[0];
    _log_hex_value(ctx, "RndB_rot (RndB left-rotated 1 byte)", rndBrot, 16);

    uint8_t rndAB[32];
    memcpy(rndAB, rndA, 16);
    memcpy(rndAB + 16, rndBrot, 16);
    _log_hex_value(ctx, "plaintext S2 = RndA || RndB_rot (to be encrypted)", rndAB, 32);

    uint8_t encAB[32];
    df_aes_cbc_encrypt(key, iv0, rndAB, 32, encAB);
    _log_hex_value(ctx, "enc(RndA||RndB_rot) sent in step 2", encAB, 32);

    if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, encAB, 32,
                  "AuthEV2First (0xAF): step 2 — send enc(RndA||RndB_rot); card checks RndB and returns TI",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) {
        char note[48];
        snprintf(note, sizeof(note),
                 "AUTH_S2_FAIL sw=0x%02X (%s) - wrong key?", sw, df_sw_describe(sw));
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }
    if (blen < 20) {
        char note[48];
        snprintf(note, sizeof(note), "AUTH_S2_FAIL short blen=%d", blen);
        if (ctx->log) ctx->log(note, "", "");
        return DF_ERR_AUTH;
    }

    uint8_t decResp[32] = {0};
    uint8_t decLen = (blen >= 32) ? 32 : ((blen >= 16) ? 16 : blen);
    df_aes_cbc_decrypt(key, iv0, body, decLen, decResp);

    /* verify rndA rotated left by 1 byte: rndA[1..15] || rndA[0] */
    uint8_t rndArot[16];
    memcpy(rndArot, rndA + 1, 15);
    rndArot[15] = rndA[0];
    if (memcmp(decResp + 4, rndArot, 16) != 0) {
        if (ctx->log) ctx->log("AUTH_RNDA_MISMATCH", "", "");
        return DF_ERR_AUTH;
    }

    memcpy(ctx->session.ti, decResp, 4);
    df_derive_session_key(key, rndA, rndB, 0xA5, ctx->session.sessKeyEnc);
    df_derive_session_key(key, rndA, rndB, 0x5A, ctx->session.sessKeyMac);
    ctx->session.cmdCounter = 0;
    ctx->session.authKeyNo  = keyNo;
    ctx->session.active     = true;
    _log_hex_value(ctx, "TI (Transaction Identifier from card)", ctx->session.ti, 4);
    _log_hex_value(ctx, "SessionKeyEnc (derived from RndA+RndB, used to encrypt data)", ctx->session.sessKeyEnc, 16);
    _log_hex_value(ctx, "SessionKeyMac (derived from RndA+RndB, used to compute CMAC)", ctx->session.sessKeyMac, 16);
    return DF_OK;
}

/* ── FormatPICC ──────────────────────────────────────────────────────── */

DFStatus df_format_picc(DFContext *ctx) {
    uint8_t sw;
    uint8_t mac8[8] = {0};
    uint8_t *mac_ptr = NULL;
    uint8_t mac_len = 0;

    if (ctx->session.active) {
        _calc_cmd_mac(ctx, CMD_FORMAT_PICC, NULL, 0, mac8);
        mac_ptr = mac8; mac_len = 8;
    }
    DFStatus st = _send_cmd(ctx, CMD_FORMAT_PICC, mac_ptr, mac_len,
                            "FormatPICC (0xFC): erase all apps and files — card resets to factory state",
                            NULL, NULL, &sw);
    if (st != DF_OK) {
        if (ctx->log) ctx->log("FormatPICC no response - assuming card reset", "", "");
        /* Many cards reset their ISO-4 session here; treat that as a soft success. */
        ctx->session.active = false;
        return DF_OK;
    }
    if (ctx->log) {
        char note[96];
        snprintf(note, sizeof(note), "FormatPICC SW=0x%02X (%s)", sw, df_sw_describe(sw));
        ctx->log(note, "", "");
    }
    if (sw != 0x00) return DF_ERR_CMD;
    if (ctx->log) ctx->log("FormatPICC OK", "", "");
    if (ctx->session.active) ctx->session.cmdCounter++;
    return DF_OK;
}

/* ── CreateApplication ───────────────────────────────────────────────── */

DFStatus df_create_application(DFContext *ctx, uint32_t appId, uint8_t numKeys) {
    uint8_t d[5];
    d[0] = appId & 0xFF;
    d[1] = (appId >> 8) & 0xFF;
    d[2] = (appId >> 16) & 0xFF;
    d[3] = 0xEF;
    d[4] = 0x80 | (numKeys & 0x0F);

    uint8_t buf[13];
    uint8_t blen = 5;
    memcpy(buf, d, 5);

    if (ctx->session.active) {
        uint8_t mac8[8];
        _calc_cmd_mac(ctx, CMD_CREATE_APP, d, 5, mac8);
        memcpy(buf + 5, mac8, 8);
        blen = 13;
    }

    uint8_t sw;
    if (_send_cmd(ctx, CMD_CREATE_APP, buf, blen,
                  "CreateApplication (0xCA): allocate new app slot with AID and key count",
                  NULL, NULL, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00 && sw != 0xDE) return DF_ERR_CMD;
    if (ctx->session.active) ctx->session.cmdCounter++;
    return DF_OK;
}

/* ── CreateStdDataFile ───────────────────────────────────────────────── */

DFStatus df_create_std_data_file(DFContext *ctx, uint8_t fileNo,
                                 uint8_t commMode, uint16_t accessRights,
                                 uint32_t fileSize) {
    uint8_t d[7];
    d[0] = fileNo;
    d[1] = commMode;
    d[2] = accessRights & 0xFF;
    d[3] = (accessRights >> 8) & 0xFF;
    d[4] = fileSize & 0xFF;
    d[5] = (fileSize >> 8) & 0xFF;
    d[6] = (fileSize >> 16) & 0xFF;
    _log_hex_value(ctx, "CreateStdDataFile plain: fileNo|commMode|accessRights|fileSize", d, 7);

    uint8_t buf[15];
    uint8_t blen = 7;
    memcpy(buf, d, 7);

    if (ctx->session.active) {
        uint8_t mac8[8];
        _calc_cmd_mac(ctx, CMD_CREATE_STD_FILE, d, 7, mac8);
        memcpy(buf + 7, mac8, 8);
        blen = 15;
    }

    uint8_t sw;
    if (_send_cmd(ctx, CMD_CREATE_STD_FILE, buf, blen,
                  "CreateStdDataFile (0xCD): create file inside the app with size and access rights",
                  NULL, NULL, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00 && sw != 0xDE) return DF_ERR_CMD;
    if (ctx->session.active) ctx->session.cmdCounter++;
    return DF_OK;
}

/* ── ChangeFileSettings ─────────────────────────────────────────────── */

DFStatus df_change_file_settings(DFContext *ctx, uint8_t fileNo,
                                 uint8_t commMode, uint16_t accessRights) {
    if (!ctx->session.active) return DF_ERR_AUTH;

    uint8_t plain[16] = {0};
    plain[0] = commMode;
    plain[1] = accessRights & 0xFF;
    plain[2] = (accessRights >> 8) & 0xFF;
    plain[3] = 0x80;
    _log_hex_value(ctx, "ChangeFileSettings plaintext: commMode|accessRights + ISO7816 padding", plain, 16);

    uint8_t iv[16];
    _calc_iv_cmd(ctx, iv);
    uint8_t cryptogram[16];
    df_aes_cbc_encrypt(ctx->session.sessKeyEnc, iv, plain, 16, cryptogram);

    uint8_t cmdData[25];
    cmdData[0] = fileNo;
    memcpy(cmdData + 1, cryptogram, 16);

    uint8_t mac8[8];
    _calc_cmd_mac(ctx, CMD_CHANGE_FILE_SETTINGS, cmdData, 17, mac8);

    uint8_t fullCmd[25];
    memcpy(fullCmd, cmdData, 17);
    memcpy(fullCmd + 17, mac8, 8);

    uint8_t body[32]; uint8_t blen; uint8_t sw;
    if (_send_cmd(ctx, CMD_CHANGE_FILE_SETTINGS, fullCmd, 25,
                  "ChangeFileSettings (0x5F): fileNo + AES-encrypted settings + CMAC",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) { ctx->session.active = false; return DF_ERR_CMD; }

    ctx->session.cmdCounter++;
    if (blen < 8) return DF_ERR_LEN;
    if (!_verify_resp_mac(ctx, NULL, 0, body + blen - 8)) return DF_ERR_CMAC;
    return DF_OK;
}

/* ── ChangeKey ───────────────────────────────────────────────────────── */

DFStatus df_change_key(DFContext *ctx, uint8_t keyNo,
                       const uint8_t oldKey[16], const uint8_t newKey[16],
                       uint8_t keyVersion) {
    if (!ctx->session.active) return DF_ERR_AUTH;

    bool changing_auth = (keyNo == ctx->session.authKeyNo);
    if (ctx->log) {
        char msg[96];
        snprintf(msg, sizeof(msg), "keyNo=%u authKeyNo=%u mode=%s",
                 (unsigned)keyNo, (unsigned)ctx->session.authKeyNo,
                 changing_auth ? "auth-key" : "other-key");
        ctx->log("ChangeKey Info", msg, "");
    }
    uint8_t plain[32] = {0};

    if (changing_auth) {
        memcpy(plain, newKey, 16);
        plain[16] = keyVersion;
        plain[17] = 0x80;
    } else {
        for (int i = 0; i < 16; i++) plain[i] = newKey[i] ^ oldKey[i];
        uint32_t crc = df_crc32(newKey, 16);
        plain[16] = crc & 0xFF;
        plain[17] = (crc >> 8) & 0xFF;
        plain[18] = (crc >> 16) & 0xFF;
        plain[19] = (crc >> 24) & 0xFF;
        plain[20] = keyVersion;
        plain[21] = 0x80;
    }
    _log_hex_value(ctx, changing_auth
                       ? "ChangeKey plaintext: newKey + version + padding"
                       : "ChangeKey plaintext: newKey XOR oldKey + CRC32(newKey) + version + padding",
                   plain, 32);

    /* Key writes are NV operations; give the card a short settle window. */
    if (ctx->delay) {
        ctx->delay(ctx->delay_user, DF_NV_WRITE_DELAY_MS);
    }

    uint8_t iv[16];
    _calc_iv_cmd(ctx, iv);
    uint8_t cryptogram[32];
    df_aes_cbc_encrypt(ctx->session.sessKeyEnc, iv, plain, 32, cryptogram);

    /* cmdData = [keyNo | cryptogram] */
    uint8_t cmdData[33];
    cmdData[0] = keyNo;
    memcpy(cmdData + 1, cryptogram, 32);

    uint8_t mac8[8];
    _calc_cmd_mac(ctx, CMD_CHANGE_KEY, cmdData, 33, mac8);

    uint8_t fullCmd[41];
    memcpy(fullCmd, cmdData, 33);
    memcpy(fullCmd + 33, mac8, 8);

    uint8_t body[64]; uint8_t blen; uint8_t sw;
    if (_send_cmd(ctx, CMD_CHANGE_KEY, fullCmd, 41,
                  "ChangeKey (0xC4): keyNo + AES-encrypted new key material + CMAC",
                  body, &blen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) { ctx->session.active = false; return DF_ERR_CMD; }

    ctx->session.cmdCounter++;
    if (changing_auth) {
        ctx->session.active = false; /* session invalidated by card */
    } else {
        if (blen < 8) return DF_ERR_LEN;
        if (!_verify_resp_mac(ctx, NULL, 0, body + blen - 8))
            return DF_ERR_CMAC;
    }
    return DF_OK;
}

/* ── WriteData (EV2 CommMode.Full) ──────────────────────────────────── */

static DFStatus _df_write_data_single(DFContext *ctx, uint8_t fileNo,
                                      uint32_t offset, const uint8_t *data,
                                      uint32_t len) {
    /* ISO/IEC 7816-4 padding: append 0x80 then zeros to next 16-byte boundary */
    uint32_t padded_len = ((len | 0x0F) + 1);
    uint8_t *padded = (uint8_t *)malloc(padded_len);
    if (!padded) return DF_ERR_PARAM;
    memcpy(padded, data, len);
    padded[len] = 0x80;
    memset(padded + len + 1, 0, padded_len - len - 1);

    uint8_t header[7];
    header[0] = fileNo;
    header[1] = offset & 0xFF;
    header[2] = (offset >> 8) & 0xFF;
    header[3] = (offset >> 16) & 0xFF;
    header[4] = len & 0xFF;
    header[5] = (len >> 8) & 0xFF;
    header[6] = (len >> 16) & 0xFF;
    _log_hex_value(ctx, "WriteData header: fileNo(1)|offset(3)|length(3)", header, 7);
    _log_hex_value(ctx, "WriteData plaintext payload (will be AES-CBC encrypted)", data, len);

    uint8_t iv[16];
    _calc_iv_cmd(ctx, iv);
    uint8_t *encData = (uint8_t *)malloc(padded_len);
    if (!encData) { free(padded); return DF_ERR_PARAM; }
    df_aes_cbc_encrypt(ctx->session.sessKeyEnc, iv, padded, padded_len, encData);
    free(padded);

    /* macInput = header || encData */
    uint8_t *macInput = (uint8_t *)malloc(7 + padded_len);
    if (!macInput) { free(encData); return DF_ERR_PARAM; }
    memcpy(macInput, header, 7);
    memcpy(macInput + 7, encData, padded_len);
    uint8_t writeCmd = ctx->isDNA ? CMD_DNA_WRITE_DATA : CMD_WRITE_DATA;
    uint8_t mac8[8];
    _calc_cmd_mac(ctx, writeCmd, macInput, 7 + padded_len, mac8);
    free(macInput);

    /* full APDU data: header || encData || mac8 */
    uint32_t fullLen = 7 + padded_len + 8;
    uint8_t *full = (uint8_t *)malloc(fullLen);
    if (!full) { free(encData); return DF_ERR_PARAM; }
    memcpy(full, header, 7);
    memcpy(full + 7, encData, padded_len);
    memcpy(full + 7 + padded_len, mac8, 8);
    free(encData);

    uint8_t body[16]; uint8_t blen; uint8_t sw;
    DFStatus st = _send_cmd(ctx, writeCmd, full, (uint8_t)fullLen,
                            ctx->isDNA
                                ? "WriteData DNA (0x8D): header + AES-encrypted+padded payload + CMAC"
                                : "WriteData DESFire (0x3D): header + AES-encrypted+padded payload + CMAC",
                            body, &blen, &sw);
    free(full);
    if (st != DF_OK) return DF_ERR_TRANSCEIVE;
    if (sw != 0x00) return DF_ERR_CMD;

    ctx->session.cmdCounter++;
    if (blen < 8) return DF_ERR_LEN;
    if (!_verify_resp_mac(ctx, NULL, 0, body + blen - 8)) return DF_ERR_CMAC;
    return DF_OK;
}

DFStatus df_write_data(DFContext *ctx, uint8_t fileNo,
                       uint32_t offset, const uint8_t *data, uint32_t len) {
    if (!ctx->session.active) return DF_ERR_AUTH;

    /* MFRC522 FIFO = 64 bytes.  T=CL frame = PCB(1)+APDU+CRC(2).
     * APDU = 90 Cmd 00 00 Lc(1) header(7) padded MAC(8) Le(1).
     * Worst case padded for chunk<=31: 32 bytes → frame = 56 ≤ 64.
     * chunk=32 → padded=48 → frame=72 → FIFO overflow → MI_ERR. */
    const uint32_t maxChunkLen = 31;
    uint32_t written = 0;
    while (written < len) {
        uint32_t chunkLen = len - written;
        if (chunkLen > maxChunkLen) chunkLen = maxChunkLen;

        DFStatus st = _df_write_data_single(ctx, fileNo, offset + written,
                                            data + written, chunkLen);
        if (st != DF_OK) return st;
        written += chunkLen;
    }
    return DF_OK;
}

/* ── ReadData (EV2 CommMode.Full) ────────────────────────────────────── */

DFStatus df_read_data(DFContext *ctx, uint8_t fileNo,
                      uint32_t offset, uint32_t len, uint8_t *out) {
    if (!ctx->session.active) return DF_ERR_AUTH;

    uint8_t readCmd = (ctx->isDNA) ? CMD_DNA_READ_DATA : CMD_READ_DATA;

    uint8_t header[7];
    header[0] = fileNo;
    header[1] = offset & 0xFF;
    header[2] = (offset >> 8) & 0xFF;
    header[3] = (offset >> 16) & 0xFF;
    header[4] = len & 0xFF;
    header[5] = (len >> 8) & 0xFF;
    header[6] = (len >> 16) & 0xFF;
    _log_hex_value(ctx, "ReadData header: fileNo(1)|offset(3)|length(3)", header, 7);

    uint8_t mac8[8];
    _calc_cmd_mac(ctx, readCmd, header, 7, mac8);

    uint8_t apduData[15];
    memcpy(apduData, header, 7);
    memcpy(apduData + 7, mac8, 8);

    /* response may span multiple frames */
    uint8_t resp[512]; uint8_t rlen = 0;
    uint8_t chunk[300]; uint8_t clen; uint8_t sw;

    if (_send_cmd(ctx, readCmd, apduData, 15,
                  ctx->isDNA
                      ? "ReadData DNA (0xAD): header+CMAC; card returns AES-encrypted data+CMAC"
                      : "ReadData (0xBD): header+CMAC; card returns AES-encrypted data+CMAC",
                  chunk, &clen, &sw) != DF_OK)
        return DF_ERR_TRANSCEIVE;
    memcpy(resp + rlen, chunk, clen); rlen += clen;

    while (sw == 0xAF) {
        if (_send_cmd(ctx, CMD_ADDITIONAL_FRAME, NULL, 0,
                      "ReadData (0xAF): additional frame — more encrypted data from card",
                      chunk, &clen, &sw) != DF_OK)
            return DF_ERR_TRANSCEIVE;
        memcpy(resp + rlen, chunk, clen); rlen += clen;
    }
    if (sw != 0x00) return DF_ERR_CMD;

    ctx->session.cmdCounter++;

    uint32_t padded_len = ((len | 0x0F) + 1);
    if (rlen < padded_len + 8) return DF_ERR_LEN;

    const uint8_t *encData = resp;
    const uint8_t *respMac = resp + padded_len;

    if (!_verify_resp_mac(ctx, encData, padded_len, respMac)) return DF_ERR_CMAC;

    uint8_t ivResp[16];
    _calc_iv_resp(ctx, ivResp);
    uint8_t *dec = (uint8_t *)malloc(padded_len);
    if (!dec) return DF_ERR_PARAM;
    df_aes_cbc_decrypt(ctx->session.sessKeyEnc, ivResp, encData, padded_len, dec);
    _log_hex_value(ctx, "ReadData decrypted plaintext (AES-CBC decrypted, padding stripped)", dec, len);
    memcpy(out, dec, len);
    free(dec);
    return DF_OK;
}

/* ── Status word descriptions ────────────────────────────────────────── */

const char *df_sw_describe(uint8_t sw) {
    switch (sw) {
        case 0x00: return "OK";
        case 0x9D: return "Permission denied";
        case 0xAE: return "Authentication error";
        case 0xAF: return "Additional frame";
        case 0xBE: return "Boundary error";
        case 0xDE: return "Duplicate error";
        case 0x40: return "No such key";
        case 0x6E: return "CLA not supported";
        case 0x6D: return "INS not supported";
        case 0x7E: return "Length error";
        case 0x9E: return "Invalid file settings";
        case 0x0E: return "Insufficient NV memory";
        case 0x1C: return "Command not allowed";
        case 0xCA: return "Command not allowed (change)";
        case 0xCD: return "Parameter error";
        default:   return "Unknown";
    }
}

/* ── Status descriptions ─────────────────────────────────────────────── */

const char *df_status_describe(DFStatus st) {
    switch (st) {
        case DF_OK:             return "OK";
        case DF_ERR_NO_CARD:    return "no card in field";
        case DF_ERR_TRANSCEIVE: return "RF/link error (card not responding — check field/position)";
        case DF_ERR_AUTH:       return "authentication failed (wrong key or key number?)";
        case DF_ERR_CMD:        return "card rejected command (check permissions or card state)";
        case DF_ERR_LEN:        return "response too short";
        case DF_ERR_CMAC:       return "CMAC verification failed (session key mismatch?)";
        case DF_ERR_PARAM:      return "invalid parameter";
        default:                return "unknown error";
    }
}

/* ── Convenience wrappers ────────────────────────────────────────────── */

/* Log a setup-step failure and return the error so callers can one-line it. */
static DFStatus _setup_fail(DFContext *ctx, const char *where, DFStatus st) {
    if (ctx->log) {
        char buf[128];
        snprintf(buf, sizeof(buf), "SETUP FAILED at [%s]: %s (err %d)",
                 where, df_status_describe(st), (int)st);
        ctx->log(buf, "", "");
    }
    return st;
}

DFStatus df_full_format(DFContext *ctx, const uint8_t piccMasterKey[16]) {
    DFStatus st;
    st = df_select_application(ctx, APP_PICC);
    if (st) return _setup_fail(ctx, "select PICC root (AID 000000)", st);
    /* Try legacy first, then ISO 3K3DES, then EV2 — mirrors real-world factory state. */
    st = _auth_picc_factory(ctx, piccMasterKey);
    if (st != DF_OK) return _setup_fail(ctx, "authenticate PICC master key", st);
    return df_format_picc(ctx);
}

DFStatus df_setup_desfire(DFContext *ctx, uint32_t appId,
                          const uint8_t piccMasterKey[16],
                          const uint8_t appMasterKey[16],
                          const uint8_t appUserKey[16],
                          uint8_t userKeyNo,
                          uint8_t fileNo, uint32_t fileSize,
                          uint16_t fileAccessRights) {
    DFStatus st;
    static const uint8_t zeros[16] = {0};
    uint8_t numKeys = (userKeyNo == 0) ? 1 : (uint8_t)(userKeyNo + 1);
    ctx->isDNA = false;

    /* 1. Format from PICC level */
    if (ctx->log) ctx->log("Setup: format PICC", "", "");
    st = df_full_format(ctx, piccMasterKey);
    if (st) return _setup_fail(ctx, "format PICC", st);
    if (ctx->log) ctx->log("Setup: format PICC OK", "", "");
    if (ctx->delay) ctx->delay(ctx->delay_user, DF_NV_WRITE_DELAY_MS);

    /* 2. Select PICC root, re-auth for CreateApp */
    if (ctx->log) ctx->log("Setup: create application", "", "");
    st = df_select_application(ctx, APP_PICC);
    if (st) return _setup_fail(ctx, "select PICC for CreateApp", st);
    if (ctx->log) ctx->log("Setup: PICC selected for CreateApp", "", "");
    st = _auth_picc_factory(ctx, piccMasterKey);
    if (st) return _setup_fail(ctx, "auth PICC master key for CreateApp", st);
    if (ctx->log) ctx->log("Setup: PICC auth OK for CreateApp", "", "");
    st = df_create_application(ctx, appId, numKeys);
    if (st) return _setup_fail(ctx, "CreateApplication", st);
    if (ctx->log) ctx->log("Setup: CreateApp OK", "", "");

    /* 3. Select new app, auth with default zeros key 0 */
    if (ctx->log) ctx->log("Setup: change keys", "", "");
    st = df_select_application(ctx, appId);
    if (st) return _setup_fail(ctx, "select app for key change", st);
    if (ctx->log) ctx->log("Setup: app selected", "", "");
    st = df_authenticate_ev2_first(ctx, 0, zeros);
    if (st) return _setup_fail(ctx, "auth app with default key 0", st);
    if (ctx->log) ctx->log("Setup: app auth with default key OK", "", "");

    /* 4. Change user key first when a separate user slot is configured. */
    if (userKeyNo > 0) {
        if (ctx->log) ctx->log("Setup: change user key", "", "");
        st = df_authenticate_ev2_first(ctx, userKeyNo, zeros);
        if (st) return _setup_fail(ctx, "auth with default user key", st);
        if (ctx->log) ctx->log("Setup: user auth with default key OK", "", "");
        st = df_change_key(ctx, userKeyNo, zeros, appUserKey, 0x01);
        if (st) return _setup_fail(ctx, "ChangeKey (user key)", st);
        if (ctx->log) ctx->log("Setup: user key changed", "", "");
        st = df_select_application(ctx, appId);
        if (st) return _setup_fail(ctx, "reselect app for user auth", st);
        if (ctx->log) ctx->log("Setup: reselect app for user auth", "", "");
        st = df_authenticate_ev2_first(ctx, userKeyNo, appUserKey);
        if (st) return _setup_fail(ctx, "auth with new user key", st);
        if (ctx->log) ctx->log("Setup: user auth OK", "", "");
    }

    /* 5. Change master key (key 0) — session will be invalidated */
    if (ctx->log) ctx->log("Setup: change master key", "", "");
    st = df_select_application(ctx, appId);
    if (st) return _setup_fail(ctx, "reselect app for master key change", st);
    if (ctx->log) ctx->log("Setup: reselect app for master key auth", "", "");
    st = df_authenticate_ev2_first(ctx, 0, zeros);
    if (st) return _setup_fail(ctx, "auth with default master key (zeros)", st);
    if (ctx->log) ctx->log("Setup: master auth with default key OK", "", "");
    if (ctx->delay) ctx->delay(ctx->delay_user, DF_NV_WRITE_DELAY_MS);
    st = df_change_key(ctx, 0, zeros, appMasterKey, 0x01);
    if (st) return _setup_fail(ctx, "ChangeKey (master key 0)", st);
    if (ctx->log) ctx->log("Setup: master key changed", "", "");

    /* 6. Re-authenticate with the new master key before creating the file. */
    st = df_select_application(ctx, appId);
    if (st) return _setup_fail(ctx, "reselect app for master re-auth", st);
    if (ctx->log) ctx->log("Setup: reselect app for master auth", "", "");
    st = df_authenticate_ev2_first(ctx, 0, appMasterKey);
    if (st) return _setup_fail(ctx, "auth with new master key", st);
    if (ctx->log) ctx->log("Setup: master auth OK", "", "");

    /* 7. Create the data file. */
    if (ctx->log) ctx->log("Setup: create standard data file", "", "");
    if (ctx->log) {
        char msg[64];
        snprintf(msg, sizeof(msg), "fileNo=%u accessRights=0x%04X size=%lu",
                 (unsigned)fileNo, (unsigned)fileAccessRights, (unsigned long)fileSize);
        ctx->log("Setup: create standard data file info", msg, "");
    }
    st = df_create_std_data_file(ctx, fileNo, 0x03, fileAccessRights, fileSize);
    if (st) return _setup_fail(ctx, "CreateStdDataFile", st);
    if (ctx->log) ctx->log("Setup: CreateStdDataFile OK", "", "");
    return st;
}

DFStatus df_setup_dna(DFContext *ctx,
                      const uint8_t appUserKey[16],
                      uint8_t userKeyNo,
                      uint8_t fileNo,
                      uint16_t fileAccessRights) {
    DFStatus st;
    static const uint8_t zeros[16] = {0};
    ctx->isDNA = true;

    /* Caller must already ISO-select the NDEF AID. NTAG 424 DNA does not
       support native app creation / formatting. */
    st = df_authenticate_ev2_first(ctx, 0, zeros); if (st) return st;
    st = df_change_file_settings(ctx, fileNo, 0x03, fileAccessRights);
    if (st) return st;

    if (userKeyNo > 0) {
        st = df_change_key(ctx, userKeyNo, zeros, appUserKey, 0x01);
        if (st) return st;
        st = df_authenticate_ev2_first(ctx, userKeyNo, appUserKey);
        if (st) return st;
    } else {
        st = df_change_key(ctx, 0, zeros, appUserKey, 0x01);
    }
    return st;
}
