#include "desfire.h"
#include <ctype.h>

#define SHELL_LINE_MAX        256u
#define SHELL_TEXT_MAX        512u
#define DF_DEFAULT_APP_ID     0x010203u
#define DF_DEFAULT_FILE_NO    0x02u
#define DF_DEFAULT_FILE_SIZE  256u
#define DF_MAX_KEY_NO         13u
#define DNA_APP_ID            0x000001u
#define DNA_DEFAULT_FILE_NO   0x03u
#define DNA_DEFAULT_FILE_SIZE 128u
#define DNA_DEFAULT_RIGHTS    0x0330u
#define CARD_SESSION_RESET_MS 15u
/* Echo from firmware so plain screen/pio monitor always shows typed input. */
#define SHELL_REMOTE_ECHO     1
#define SHELL_HISTORY_DEPTH   8u

static bool g_rc522_ready = false;
static char g_history[SHELL_HISTORY_DEPTH][SHELL_LINE_MAX];
static size_t g_history_count = 0;
static size_t g_redraw_cols = 0;

static void shell_trim(char *s) {
    char *start = s;
    char *end;

    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
}

static void shell_redraw_line(const char *prompt, const char *buf) {
#if SHELL_REMOTE_ECHO
    size_t used = strlen(prompt ? prompt : "") + strlen(buf ? buf : "");
    printf("\r%s%s", prompt ? prompt : "", buf ? buf : "");
    while (g_redraw_cols > used) {
        putchar(' ');
        g_redraw_cols--;
    }
    printf("\r%s%s", prompt ? prompt : "", buf ? buf : "");
    g_redraw_cols = used;
    fflush(stdout);
#else
    (void)prompt;
    (void)buf;
#endif
}

static void shell_history_add(const char *line) {
    if (!line || line[0] == '\0') return;
    if (g_history_count > 0 &&
        strcmp(g_history[g_history_count - 1u], line) == 0) {
        return;
    }
    if (g_history_count < SHELL_HISTORY_DEPTH) {
        strncpy(g_history[g_history_count], line, SHELL_LINE_MAX - 1u);
        g_history[g_history_count][SHELL_LINE_MAX - 1u] = '\0';
        g_history_count++;
        return;
    }
    for (size_t i = 1u; i < SHELL_HISTORY_DEPTH; i++) {
        strcpy(g_history[i - 1u], g_history[i]);
    }
    strncpy(g_history[SHELL_HISTORY_DEPTH - 1u], line, SHELL_LINE_MAX - 1u);
    g_history[SHELL_HISTORY_DEPTH - 1u][SHELL_LINE_MAX - 1u] = '\0';
}

static void shell_history_load(char *buf, size_t size, size_t hist_from_end) {
    if (!buf || size == 0 || hist_from_end >= g_history_count) return;
    const char *src = g_history[g_history_count - 1u - hist_from_end];
    strncpy(buf, src, size - 1u);
    buf[size - 1u] = '\0';
}

static bool shell_read_line_ex(const char *prompt, char *buf, size_t size,
                               bool use_history) {
    size_t pos = 0;
    bool overflow = false;
    int history_index = -1;
    char draft[SHELL_LINE_MAX] = {0};

    if (!buf || size == 0) return false;
    buf[0] = '\0';

    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
        g_redraw_cols = strlen(prompt);
    }

    while (1) {
        int ch = getchar();
        if (ch == EOF) {
            return false;
        }
        if (ch == '\0') {
            continue;
        }
        if (ch == 0x1B) {
            int next = getchar();
            if (next == '[') {
                int code = getchar();
                if (use_history && code == 'A' && g_history_count > 0u) {
                    if (history_index < 0) {
                        strncpy(draft, buf, sizeof(draft) - 1u);
                        draft[sizeof(draft) - 1u] = '\0';
                        history_index = 0;
                    } else if ((size_t)history_index + 1u < g_history_count) {
                        history_index++;
                    }
                    shell_history_load(buf, size, (size_t)history_index);
                    pos = strlen(buf);
                    shell_redraw_line(prompt, buf);
                    continue;
                }
                if (use_history && code == 'B' && history_index >= 0) {
                    if (history_index == 0) {
                        strncpy(buf, draft, size - 1u);
                        buf[size - 1u] = '\0';
                        history_index = -1;
                    } else {
                        history_index--;
                        shell_history_load(buf, size, (size_t)history_index);
                    }
                    pos = strlen(buf);
                    shell_redraw_line(prompt, buf);
                    continue;
                }
                while (code != EOF &&
                       !((code >= 'A' && code <= 'Z') ||
                         (code >= 'a' && code <= 'z') || code == '~')) {
                    code = getchar();
                }
            }
            continue;
        }
        if (ch == '\r' || ch == '\n') {
            putchar('\n');
            fflush(stdout);
            break;
        }
        if (ch == '\b' || ch == 0x7F) {
            if (pos > 0) {
                pos--;
                buf[pos] = '\0';
                history_index = -1;
                if (g_redraw_cols > 0u) {
                    g_redraw_cols--;
                }
#if SHELL_REMOTE_ECHO
                putchar('\b');
                putchar(' ');
                putchar('\b');
                fflush(stdout);
#endif
            }
            continue;
        }
        if (pos + 1 < size) {
            buf[pos++] = (char)ch;
            buf[pos] = '\0';
            history_index = -1;
            g_redraw_cols++;
#if SHELL_REMOTE_ECHO
            putchar(ch);
            fflush(stdout);
#endif
        } else {
            overflow = true;
        }
    }

    buf[pos] = '\0';
    if (overflow) {
        printf("Input truncated.\n");
    }
    return true;
}

static bool shell_read_line(char *buf, size_t size) {
    return shell_read_line_ex(NULL, buf, size, false);
}

static bool prompt_line(const char *label, char *buf, size_t size) {
    return shell_read_line_ex(label, buf, size, false);
}

static bool parse_u32(const char *s, uint32_t *out) {
    char *end = NULL;
    unsigned long val;

    if (!s || !out) return false;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return false;

    val = strtoul(s, &end, 0);
    if (end == s) return false;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0') return false;
    if (val > 0xFFFFFFFFul) return false;
    *out = (uint32_t)val;
    return true;
}

static bool prompt_u32_default(const char *label, uint32_t def,
                               uint32_t min, uint32_t max, uint32_t *out) {
    char line[64];

    while (1) {
        printf("%s [default %lu]: ", label, (unsigned long)def);
        fflush(stdout);
        if (!shell_read_line(line, sizeof(line))) return false;
        shell_trim(line);
        if (line[0] == '\0') {
            *out = def;
            return true;
        }
        if (parse_u32(line, out) && *out >= min && *out <= max) {
            return true;
        }
        printf("Invalid value.\n");
    }
}

static bool prompt_u32_required(const char *label, uint32_t min, uint32_t max,
                                uint32_t *out) {
    char line[64];

    while (1) {
        printf("%s: ", label);
        fflush(stdout);
        if (!shell_read_line(line, sizeof(line))) return false;
        shell_trim(line);
        if (parse_u32(line, out) && *out >= min && *out <= max) {
            return true;
        }
        printf("Invalid value.\n");
    }
}

static bool parse_hex_bytes(const char *s, uint8_t *out, size_t expected) {
    size_t count = 0;
    bool has_sep = false;

    if (!s || !out) return false;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return false;

    for (const char *p = s; *p; ++p) {
        if (isspace((unsigned char)*p) || *p == ',' || *p == ':' || *p == '-') {
            has_sep = true;
            break;
        }
    }

    if (!has_sep) {
        size_t len = strlen(s);
        if (len != expected * 2u) return false;
        for (size_t i = 0; i < expected; i++) {
            char tmp[3];
            char *end = NULL;
            unsigned long val;

            tmp[0] = s[i * 2u];
            tmp[1] = s[i * 2u + 1u];
            tmp[2] = '\0';
            val = strtoul(tmp, &end, 16);
            if (!end || *end != '\0' || val > 0xFFul) return false;
            out[i] = (uint8_t)val;
        }
        return true;
    }

    while (*s) {
        char token[8];
        size_t ti = 0;
        char *end = NULL;
        unsigned long val;

        while (*s && (isspace((unsigned char)*s) || *s == ',' || *s == ':' || *s == '-')) {
            s++;
        }
        if (*s == '\0') break;
        while (*s && !(isspace((unsigned char)*s) || *s == ',' || *s == ':' || *s == '-')) {
            if (ti + 1u >= sizeof(token)) return false;
            token[ti++] = *s++;
        }
        token[ti] = '\0';
        val = strtoul(token, &end, 16);
        if (end == token || *end != '\0' || val > 0xFFul) return false;
        if (count >= expected) return false;
        out[count++] = (uint8_t)val;
    }

    return count == expected;
}

static bool prompt_hex_bytes(const char *label, size_t expected, uint8_t *out) {
    char line[128];

    while (1) {
        printf("%s (%u bytes, hex): ", label, (unsigned)expected);
        fflush(stdout);
        if (!shell_read_line(line, sizeof(line))) return false;
        shell_trim(line);
        if (parse_hex_bytes(line, out, expected)) {
            return true;
        }
        printf("Invalid hex input.\n");
    }
}

static uint16_t df_default_access_rights(uint8_t keyNo) {
    uint16_t k = (uint16_t)(keyNo & 0x0Fu);
    return (uint16_t)((k << 12) | (k << 8) | (k << 4) | 0x0000u);
}

static void print_hex_line(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if (i + 1u < len) {
            printf(" ");
        }
    }
    printf("\n");
}

static void show_df_config(const AppState *app) {
    printf("DF config:\n");
    printf("  AID: %02X %02X %02X\n",
           (unsigned)((app->df.appId >> 16) & 0xFFu),
           (unsigned)((app->df.appId >> 8) & 0xFFu),
           (unsigned)(app->df.appId & 0xFFu));
    printf("  keyNo: %u\n", (unsigned)app->df.userKeyNo);
    printf("  fileNo: %u\n", (unsigned)app->df.fileNo);
    printf("  fileSize: %lu\n", (unsigned long)app->df.fileSize);
    printf("  accessRights: 0x%04X\n", (unsigned)app->df.accessRights);
}

static void show_dna_config(const AppState *app) {
    printf("DNA config:\n");
    printf("  keyNo: %u\n", (unsigned)app->dna.userKeyNo);
    printf("  fileNo: %u\n", (unsigned)app->dna.fileNo);
    printf("  fileSize: %lu\n", (unsigned long)app->dna.fileSize);
    printf("  accessRights: 0x%04X\n", (unsigned)app->dna.accessRights);
}

static void prompt_place_card(void) {
    char line[8];

    printf("Place the card on the reader, then press Enter.\n");
    printf("Ready? ");
    fflush(stdout);
    (void)shell_read_line(line, sizeof(line));
}

static void prompt_place_card_auto(void) {
    printf("Auto: place card on reader (polling up to 10 s)...\n");
    fflush(stdout);
}

static void note_step(const char *text) {
    if (text && text[0]) {
        printf("%s\n", text);
    }
}

static bool rc522_diagnostics(void) {
    uint8_t ver = Read_MFRC522(VersionReg);
    uint8_t tx = Read_MFRC522(TxControlReg);
    uint8_t rf = Read_MFRC522(RFCfgReg);
    uint8_t cmd = Read_MFRC522(CommandReg);
    uint8_t irq = Read_MFRC522(CommIrqReg);
    uint8_t err = Read_MFRC522(ErrorReg);
    bool connected = (ver != 0x00u && ver != 0xFFu);

    printf("RC522 diagnostics:\n");
    printf("  connected: %s\n", connected ? "yes" : "no");
    printf("  VersionReg: 0x%02X\n", ver);
    printf("  CommandReg: 0x%02X\n", cmd);
    printf("  CommIrqReg: 0x%02X\n", irq);
    printf("  ErrorReg:   0x%02X\n", err);
    printf("  TxControl:  0x%02X\n", tx);
    printf("  RFCfgReg:   0x%02X\n", rf);
    if (!connected) {
        printf("RC522 not detected. Check SPI wiring, CS, RST, and power.\n");
    }
    g_rc522_ready = connected;
    return connected;
}

static bool require_rc522_ready(void) {
    if (!g_rc522_ready) {
        printf("RC522 not validated in this session. Run 'rc522 diag' first.\n");
        return false;
    }
    return true;
}

static void close_card_session(AppState *app) {
    if (app) {
        app->ctx.session.active = false;
    }
    MFRC522_FieldReset(CARD_SESSION_RESET_MS);
    printf("[NFC] card session closed; RF field reset.\n");
}

static DFStatus prepare_df_session(AppState *app) {
    DFStatus st;
    const uint8_t *key;
    uint8_t keyNo;

    if (!require_rc522_ready()) {
        return DF_ERR_PARAM;
    }
    prompt_place_card();
    st = wait_for_card(app);
    if (st != DF_OK) return st;

    app->ctx.isDNA = false;
    st = df_select_application(&app->ctx, app->df.appId);
    if (st != DF_OK) return st;

    keyNo = app->df.userKeyNo;
    key = (keyNo == 0) ? app->df.appMasterKey : app->df.appUserKey;
    st = df_authenticate_ev2_first(&app->ctx, keyNo, key);
    if (st != DF_OK) return st;

    return DF_OK;
}

static DFStatus prepare_dna_session(AppState *app) {
    DFStatus st;

    if (!require_rc522_ready()) {
        return DF_ERR_PARAM;
    }
    prompt_place_card();
    st = wait_for_card(app);
    if (st != DF_OK) return st;

    app->ctx.isDNA = true;
    st = df_select_application(&app->ctx, DNA_APP_ID);
    if (st != DF_OK) return st;

    st = df_authenticate_ev2_first(&app->ctx, app->dna.userKeyNo, app->dna.appUserKey);
    if (st != DF_OK) return st;

    return DF_OK;
}

static DFStatus run_df_setup(AppState *app, bool auto_mode) {
    DFStatus st;
    static const uint8_t piccMasterKey[16] = {0};

    if (!app->df.configured) {
        printf("Run 'df credentials' first.\n");
        return DF_ERR_PARAM;
    }
    if (!require_rc522_ready()) {
        return DF_ERR_PARAM;
    }

    note_step("DF setup flow: wait for card, format PICC, create app, change keys, create file.");
    if (auto_mode) {
        prompt_place_card_auto();
    } else {
        prompt_place_card();
    }
    st = wait_for_card(app);
    if (st != DF_OK) {
        printf("df setup aborted: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    note_step("Step 1: format PICC and authenticate with the PICC master key.");
    st = df_setup_desfire(&app->ctx,
                          app->df.appId,
                          piccMasterKey,
                          app->df.appMasterKey,
                          app->df.appUserKey,
                          app->df.userKeyNo,
                          app->df.fileNo,
                          app->df.fileSize,
                          app->df.accessRights);
    if (st != DF_OK) {
        printf("df setup failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("DF setup complete.\n");
    return DF_OK;
}

static DFStatus run_dna_setup(AppState *app) {
    DFStatus st;

    if (!app->dna.configured) {
        printf("Run 'dna credentials' first.\n");
        return DF_ERR_PARAM;
    }
    if (!require_rc522_ready()) {
        return DF_ERR_PARAM;
    }

    note_step("DNA setup flow: wait for card, select DNA app, change keys, update file settings.");
    prompt_place_card();
    st = wait_for_card(app);
    if (st != DF_OK) return st;

    st = df_select_application(&app->ctx, DNA_APP_ID);
    if (st != DF_OK) {
        printf("dna select failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    st = df_setup_dna(&app->ctx,
                      app->dna.appUserKey,
                      app->dna.userKeyNo,
                      app->dna.fileNo,
                      app->dna.accessRights);
    if (st != DF_OK) {
        printf("dna setup failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    st = df_select_application(&app->ctx, DNA_APP_ID);
    if (st != DF_OK) {
        printf("dna reselect failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }
    st = df_authenticate_ev2_first(&app->ctx, app->dna.userKeyNo, app->dna.appUserKey);
    if (st != DF_OK) {
        printf("dna auth failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("DNA setup complete.\n");
    return DF_OK;
}

static DFStatus run_df_write(AppState *app) {
    char line[SHELL_TEXT_MAX];
    size_t len;
    DFStatus st;
    uint8_t *payload;

    if (!prompt_line("Data to write: ", line, sizeof(line))) {
        return DF_ERR_PARAM;
    }
    len = strlen(line);
    if (len == 0) {
        printf("Empty input.\n");
        return DF_ERR_PARAM;
    }
    if (len > app->df.fileSize) {
        printf("Input is %u bytes, limit is %lu bytes.\n",
               (unsigned)len, (unsigned long)app->df.fileSize);
        return DF_ERR_LEN;
    }

    note_step("Write flow: payload is plaintext locally, then the library wraps it into encrypted APDUs.");
    payload = (uint8_t *)malloc(len);
    if (!payload) return DF_ERR_PARAM;
    memcpy(payload, line, len);

    st = prepare_df_session(app);
    if (st != DF_OK) {
        free(payload);
        return st;
    }

    st = df_write_data(&app->ctx, app->df.fileNo, 0, payload, (uint32_t)len);
    free(payload);
    if (st != DF_OK) {
        printf("df write failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("Wrote %u bytes.\n", (unsigned)len);
    return DF_OK;
}

static DFStatus run_dna_write(AppState *app) {
    char line[SHELL_TEXT_MAX];
    size_t len;
    DFStatus st;
    uint8_t *payload;

    if (!prompt_line("Data to write: ", line, sizeof(line))) {
        return DF_ERR_PARAM;
    }
    len = strlen(line);
    if (len == 0) {
        printf("Empty input.\n");
        return DF_ERR_PARAM;
    }
    if (len > app->dna.fileSize) {
        printf("Input is %u bytes, limit is %lu bytes.\n",
               (unsigned)len, (unsigned long)app->dna.fileSize);
        return DF_ERR_LEN;
    }

    note_step("Write flow: payload is plaintext locally, then the library wraps it into encrypted APDUs.");
    payload = (uint8_t *)malloc(len);
    if (!payload) return DF_ERR_PARAM;
    memcpy(payload, line, len);

    st = prepare_dna_session(app);
    if (st != DF_OK) {
        free(payload);
        return st;
    }

    st = df_write_data(&app->ctx, app->dna.fileNo, 0, payload, (uint32_t)len);
    free(payload);
    if (st != DF_OK) {
        printf("dna write failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("Wrote %u bytes.\n", (unsigned)len);
    return DF_OK;
}

static DFStatus run_df_read(AppState *app) {
    uint32_t len = 0;
    DFStatus st;
    uint8_t *buf;

    if (!prompt_u32_default("Bytes to read", app->df.fileSize, 1, app->df.fileSize, &len)) {
        return DF_ERR_PARAM;
    }

    note_step("Read flow: the card returns encrypted data plus MAC, and the library verifies it before printing plaintext.");
    buf = (uint8_t *)malloc(len);
    if (!buf) return DF_ERR_PARAM;

    st = prepare_df_session(app);
    if (st != DF_OK) {
        free(buf);
        return st;
    }

    st = df_read_data(&app->ctx, app->df.fileNo, 0, len, buf);
    if (st != DF_OK) {
        free(buf);
        printf("df read failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("Read %lu bytes:\n", (unsigned long)len);
    print_hex_line(buf, len);
    free(buf);
    return DF_OK;
}

static DFStatus run_dna_read(AppState *app) {
    uint32_t len = 0;
    DFStatus st;
    uint8_t *buf;

    if (!prompt_u32_default("Bytes to read", app->dna.fileSize, 1, app->dna.fileSize, &len)) {
        return DF_ERR_PARAM;
    }

    note_step("Read flow: the card returns encrypted data plus MAC, and the library verifies it before printing plaintext.");
    buf = (uint8_t *)malloc(len);
    if (!buf) return DF_ERR_PARAM;

    st = prepare_dna_session(app);
    if (st != DF_OK) {
        free(buf);
        return st;
    }

    st = df_read_data(&app->ctx, app->dna.fileNo, 0, len, buf);
    if (st != DF_OK) {
        free(buf);
        printf("dna read failed: %s (err %d)\n", df_status_describe(st), (int)st);
        return st;
    }

    printf("Read %lu bytes:\n", (unsigned long)len);
    print_hex_line(buf, len);
    free(buf);
    return DF_OK;
}

static DFStatus run_df_credentials(AppState *app) {
    uint32_t userKeyNo = 0;
    uint8_t masterKey[16];
    uint8_t userKey[16];
    uint8_t aid[3];
    uint32_t fileNo = 0;
    uint32_t fileSize = 0;

    if (!prompt_hex_bytes("DF app AID", 3, aid)) return DF_ERR_PARAM;
    if (!prompt_u32_required("DF keyNo [0-13]", 0, DF_MAX_KEY_NO, &userKeyNo)) return DF_ERR_PARAM;
    if (!prompt_hex_bytes("DFAppMasterKey", 16, masterKey)) return DF_ERR_PARAM;

    memset(userKey, 0, sizeof(userKey));
    if (userKeyNo > 0) {
        if (!prompt_hex_bytes("DFAppUserKey", 16, userKey)) return DF_ERR_PARAM;
    }

    if (!prompt_u32_default("DF fileNo", DF_DEFAULT_FILE_NO, 0, 255, &fileNo)) return DF_ERR_PARAM;
    if (!prompt_u32_default("DF fileSize", DF_DEFAULT_FILE_SIZE, 1, 0xFFFFFFFFu, &fileSize)) return DF_ERR_PARAM;

    printf("Access rights are 4 nibbles: 0xRWrwC\n");
    printf("  R=read  W=write  rw=read+write  C=change\n");
    printf("  0-D=key number  E=free/plain  F=deny\n");
    printf("  Default uses keyNo for read/write/read+write and key 0 for change.\n");
    uint32_t rights = 0;
    uint16_t defaultRights = df_default_access_rights((uint8_t)userKeyNo);
    while (1) {
        if (!prompt_u32_default("DF accessRights", defaultRights, 0, 0xFFFF, &rights)) return DF_ERR_PARAM;
        if ((rights & 0xFFFFu) != 0xEEEEu) {
            break;
        }
        printf("0xEEEE is free/plain access. This DF write/read path uses encrypted APDUs; choose key-based rights like 0x%04X.\n",
               (unsigned)defaultRights);
    }

    app->df.configured = true;
    app->df.appId = ((uint32_t)aid[0] << 16) | ((uint32_t)aid[1] << 8) | (uint32_t)aid[2];
    app->df.userKeyNo = (uint8_t)userKeyNo;
    memcpy(app->df.appMasterKey, masterKey, sizeof(masterKey));
    memcpy(app->df.appUserKey, userKey, sizeof(userKey));
    app->df.fileNo = (uint8_t)fileNo;
    app->df.fileSize = fileSize;
    app->df.accessRights = (uint16_t)rights;

    printf("DF credentials updated.\n");
    show_df_config(app);
    return DF_OK;
}

static DFStatus run_dna_credentials(AppState *app) {
    uint32_t userKeyNo = 0;
    uint8_t key[16];
    uint32_t fileNo = 0;
    uint32_t fileSize = 0;

    if (!prompt_u32_required("DNA keyNo [0-5]", 0, 5, &userKeyNo)) return DF_ERR_PARAM;
    if (!prompt_hex_bytes("DNA key", 16, key)) return DF_ERR_PARAM;
    if (!prompt_u32_default("DNA fileNo", DNA_DEFAULT_FILE_NO, 0, 255, &fileNo)) return DF_ERR_PARAM;
    if (!prompt_u32_default("DNA fileSize", DNA_DEFAULT_FILE_SIZE, 1, 0xFFFFFFFFu, &fileSize)) return DF_ERR_PARAM;

    app->dna.configured = true;
    app->dna.userKeyNo = (uint8_t)userKeyNo;
    memcpy(app->dna.appUserKey, key, sizeof(key));
    app->dna.fileNo = (uint8_t)fileNo;
    app->dna.fileSize = fileSize;
    app->dna.accessRights = DNA_DEFAULT_RIGHTS;

    printf("DNA credentials updated.\n");
    show_dna_config(app);
    return DF_OK;
}

static void print_help(void) {
    printf("Commands:\n");
    printf("  help\n");
    printf("  exit\n");
    printf("  quit\n");
    printf("  show\n");
    printf("  df credentials\n");
    printf("  df setup\n");
    printf("  df setup -y   (auto — no Enter prompt; for scripts)\n");
    printf("  df write\n");
    printf("  df read\n");
    printf("  dna credentials\n");
    printf("  dna setup\n");
    printf("  dna write\n");
    printf("  dna read\n");
    printf("  rc522 diag\n");
}

void run_interactive_shell(AppState *app) {
    char line[SHELL_LINE_MAX];

    if (!app) return;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("\nInteractive NFC shell ready. Type help for commands.\n");
    if (!rc522_diagnostics()) {
        return;
    }

    while (1) {
        if (!shell_read_line_ex("\nnfc> ", line, sizeof(line), true)) {
            continue;
        }
        shell_trim(line);
        if (line[0] == '\0') {
            continue;
        }
        shell_history_add(line);

        if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
            print_help();
        } else if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            printf("Leaving interactive shell.\n");
            return;
        } else if (strcmp(line, "show") == 0) {
            show_df_config(app);
            show_dna_config(app);
        } else if (strcmp(line, "df credentials") == 0) {
            run_df_credentials(app);
        } else if (strcmp(line, "df setup") == 0 || strcmp(line, "df setup -y") == 0) {
            run_df_setup(app, strcmp(line, "df setup -y") == 0);
            close_card_session(app);
        } else if (strcmp(line, "df write") == 0) {
            run_df_write(app);
            close_card_session(app);
        } else if (strcmp(line, "df read") == 0) {
            run_df_read(app);
            close_card_session(app);
        } else if (strcmp(line, "dna credentials") == 0) {
            run_dna_credentials(app);
        } else if (strcmp(line, "dna setup") == 0) {
            run_dna_setup(app);
            close_card_session(app);
        } else if (strcmp(line, "dna write") == 0) {
            run_dna_write(app);
            close_card_session(app);
        } else if (strcmp(line, "dna read") == 0) {
            run_dna_read(app);
            close_card_session(app);
        } else if (strcmp(line, "rc522 diag") == 0 || strcmp(line, "diag") == 0) {
            rc522_diagnostics();
        } else {
            printf("Unknown command. Type 'help'.\n");
        }
    }
}
