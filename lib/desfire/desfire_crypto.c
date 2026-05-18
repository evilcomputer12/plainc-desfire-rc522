#include "desfire_crypto.h"
#include <string.h>
#include <stdbool.h>

/* ── AES-128 implementation ─────────────────────────────────────────── */

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t AES_RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

static void _des_cbc_crypt(const uint8_t *key8, const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len,
                           bool encrypt);
static void _des3_ecb_crypt(const uint8_t *key24, const uint8_t *in,
                            uint8_t *out, size_t len, bool encrypt);
static void _des3_cbc_crypt(const uint8_t *key24, const uint8_t iv8[8],
                            const uint8_t *in, uint8_t *out, size_t len,
                            bool encrypt);

static uint8_t _xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1B));
}

static uint8_t _mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = _xtime(a);
        b >>= 1;
    }
    return r;
}

static void _aes_key_expand(const uint8_t key[16], uint8_t roundKeys[176]) {
    memcpy(roundKeys, key, 16);
    uint8_t t[4];
    int bytes = 16;
    int rcon = 1;
    while (bytes < 176) {
        for (int i = 0; i < 4; i++) t[i] = roundKeys[bytes - 4 + i];
        if ((bytes % 16) == 0) {
            uint8_t tmp = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int i = 0; i < 4; i++) t[i] = AES_SBOX[t[i]];
            t[0] ^= AES_RCON[rcon++];
        }
        for (int i = 0; i < 4; i++) {
            roundKeys[bytes] = roundKeys[bytes - 16] ^ t[i];
            bytes++;
        }
    }
}

static void _aes_add_round_key(uint8_t state[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void _aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]];
}

static void _aes_inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]];
}

static void _aes_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3];  s[3]  = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = t;
}

static void _aes_inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void _aes_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &s[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(_mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3);
        col[1] = (uint8_t)(a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3);
        col[2] = (uint8_t)(a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3));
        col[3] = (uint8_t)(_mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2));
    }
}

static void _aes_inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &s[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(_mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9));
        col[1] = (uint8_t)(_mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13));
        col[2] = (uint8_t)(_mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11));
        col[3] = (uint8_t)(_mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14));
    }
}

static void _aes_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t rk[176];
    memcpy(state, in, 16);
    _aes_key_expand(key, rk);
    _aes_add_round_key(state, rk);
    for (int round = 1; round <= 9; round++) {
        _aes_sub_bytes(state);
        _aes_shift_rows(state);
        _aes_mix_columns(state);
        _aes_add_round_key(state, rk + round * 16);
    }
    _aes_sub_bytes(state);
    _aes_shift_rows(state);
    _aes_add_round_key(state, rk + 160);
    memcpy(out, state, 16);
}

static void _aes_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t rk[176];
    memcpy(state, in, 16);
    _aes_key_expand(key, rk);
    _aes_add_round_key(state, rk + 160);
    for (int round = 9; round >= 1; round--) {
        _aes_inv_shift_rows(state);
        _aes_inv_sub_bytes(state);
        _aes_add_round_key(state, rk + round * 16);
        _aes_inv_mix_columns(state);
    }
    _aes_inv_shift_rows(state);
    _aes_inv_sub_bytes(state);
    _aes_add_round_key(state, rk);
    memcpy(out, state, 16);
}

/* ── ECB ─────────────────────────────────────────────────────────────── */

void df_aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    _aes_encrypt_block(key, in, out);
}

void df_aes_ecb_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    _aes_decrypt_block(key, in, out);
}

/* ── CBC ─────────────────────────────────────────────────────────────── */

void df_aes_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        for (int i = 0; i < 16; i++) block[i] = in[off + i] ^ prev[i];
        _aes_encrypt_block(key, block, out + off);
        memcpy(prev, out + off, 16);
    }
}

void df_aes_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        _aes_decrypt_block(key, in + off, block);
        for (int i = 0; i < 16; i++) out[off + i] = block[i] ^ prev[i];
        memcpy(prev, in + off, 16);
    }
}

/* ── CMAC ────────────────────────────────────────────────────────────── */

static void _left_shift_1(const uint8_t *in, uint8_t *out) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        out[i] = (in[i] << 1) | carry;
        carry = (in[i] >> 7) & 1;
    }
}

static void _gen_subkey(const uint8_t *l, uint8_t *k) {
    _left_shift_1(l, k);
    if (l[0] & 0x80) k[15] ^= 0x87;
}

void df_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[16]) {
    uint8_t l[16] = {0};
    df_aes_ecb_encrypt(key, l, l);

    uint8_t k1[16], k2[16];
    _gen_subkey(l, k1);
    _gen_subkey(k1, k2);

    size_t n = (len + 15) / 16;
    int last_complete = (len > 0) && (len % 16 == 0);
    if (n == 0) n = 1;

    /* build padded last block XOR'd with subkey */
    uint8_t last[16] = {0};
    if (last_complete) {
        memcpy(last, msg + (n - 1) * 16, 16);
        for (int i = 0; i < 16; i++) last[i] ^= k1[i];
    } else {
        size_t rem = len % 16;
        if (rem) memcpy(last, msg + (n - 1) * 16, rem);
        last[rem] = 0x80;
        for (int i = 0; i < 16; i++) last[i] ^= k2[i];
    }

    /* CBC over first (n-1) full blocks with zero IV, then absorb last */
    uint8_t x[16] = {0};
    uint8_t scratch[16];
    for (size_t b = 0; b < n - 1; b++) {
        for (int i = 0; i < 16; i++) scratch[i] = msg[b * 16 + i] ^ x[i];
        df_aes_ecb_encrypt(key, scratch, x);
    }
    for (int i = 0; i < 16; i++) x[i] ^= last[i];
    df_aes_ecb_encrypt(key, x, out);
}

/* ── Truncated MAC ───────────────────────────────────────────────────── */

void df_truncate_mac(const uint8_t mac[16], uint8_t out[8]) {
    out[0] = mac[1];
    out[1] = mac[3];
    out[2] = mac[5];
    out[3] = mac[7];
    out[4] = mac[9];
    out[5] = mac[11];
    out[6] = mac[13];
    out[7] = mac[15];
}

/* ── CRC32 ───────────────────────────────────────────────────────────── */

uint32_t df_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320) : (crc >> 1);
    }
    return crc;
}

/* ── Session key derivation ──────────────────────────────────────────── */

void df_derive_session_key(const uint8_t key[16], const uint8_t rndA[16],
                           const uint8_t rndB[16], uint8_t label,
                           uint8_t out[16]) {
    uint8_t sv[32];
    sv[0] = label;
    sv[1] = (label == 0xA5) ? 0x5A : 0xA5;
    sv[2] = 0x00;
    sv[3] = 0x01;
    sv[4] = 0x00;
    sv[5] = 0x80;
    sv[6] = rndA[0];
    sv[7] = rndA[1];
    for (int i = 0; i < 6; i++) sv[8 + i]  = rndA[2 + i] ^ rndB[i];
    for (int i = 0; i < 10; i++) sv[14 + i] = rndB[6 + i];
    for (int i = 0; i < 8; i++)  sv[24 + i] = rndA[8 + i];
    df_cmac(key, sv, 32, out);
}

/* ── DES / 3DES implementation ──────────────────────────────────────── */

static const uint8_t DES_IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

static const uint8_t DES_FP[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

static const uint8_t DES_E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const uint8_t DES_P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

static const uint8_t DES_PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const uint8_t DES_PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const uint8_t DES_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t DES_SBOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

static uint64_t _permute(uint64_t in, const uint8_t *table, size_t n, int inbits) {
    uint64_t out = 0;
    for (size_t i = 0; i < n; i++) {
        out <<= 1;
        out |= (in >> (inbits - table[i])) & 1ULL;
    }
    return out;
}

static void _des_key_schedule(const uint8_t key[8], uint64_t subkeys[16]) {
    uint64_t k = 0;
    for (int i = 0; i < 8; i++) {
        k = (k << 8) | key[i];
    }
    uint64_t pc1 = _permute(k, DES_PC1, 56, 64);
    uint32_t c = (uint32_t)((pc1 >> 28) & 0x0FFFFFFFUL);
    uint32_t d = (uint32_t)(pc1 & 0x0FFFFFFFUL);
    for (int r = 0; r < 16; r++) {
        uint8_t s = DES_SHIFTS[r];
        c = ((c << s) | (c >> (28 - s))) & 0x0FFFFFFFUL;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFFFFFFUL;
        uint64_t cd = (((uint64_t)c) << 28) | d;
        subkeys[r] = _permute(cd, DES_PC2, 48, 56);
    }
}

static uint32_t _des_f(uint32_t r, uint64_t subkey48) {
    uint64_t expanded = _permute((uint64_t)r, DES_E, 48, 32);
    expanded ^= subkey48;
    uint32_t sbox_out = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t chunk = (uint8_t)((expanded >> (42 - 6 * i)) & 0x3F);
        uint8_t row = (uint8_t)(((chunk & 0x20) >> 4) | (chunk & 0x01));
        uint8_t col = (uint8_t)((chunk >> 1) & 0x0F);
        sbox_out = (sbox_out << 4) | DES_SBOX[i][row][col];
    }
    return (uint32_t)_permute((uint64_t)sbox_out, DES_P, 32, 32);
}

static uint64_t _des_crypt_block(uint64_t block, const uint8_t key[8], bool encrypt) {
    uint64_t subkeys[16];
    _des_key_schedule(key, subkeys);

    uint64_t ip = _permute(block, DES_IP, 64, 64);
    uint32_t l = (uint32_t)(ip >> 32);
    uint32_t r = (uint32_t)(ip & 0xFFFFFFFFUL);

    for (int i = 0; i < 16; i++) {
        uint32_t prev_r = r;
        uint64_t sk = encrypt ? subkeys[i] : subkeys[15 - i];
        r = l ^ _des_f(r, sk);
        l = prev_r;
    }

    uint64_t preout = (((uint64_t)r) << 32) | l;
    return _permute(preout, DES_FP, 64, 64);
}

static void _des_cbc_crypt(const uint8_t *key8, const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len,
                           bool encrypt) {
    uint64_t iv = 0;
    for (int i = 0; i < 8; i++) {
        iv = (iv << 8) | iv8[i];
    }

    for (size_t off = 0; off < len; off += 8) {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++) {
            block = (block << 8) | in[off + i];
        }

        if (encrypt) {
            block ^= iv;
            block = _des_crypt_block(block, key8, true);
            iv = block;
        } else {
            uint64_t cur = block;
            block = _des_crypt_block(block, key8, false);
            block ^= iv;
            iv = cur;
        }

        for (int i = 7; i >= 0; i--) {
            out[off + i] = (uint8_t)(block & 0xFF);
            block >>= 8;
        }
    }
}

static void _des3_crypt_block(uint64_t block, const uint8_t key[24], bool encrypt,
                              uint64_t *out_block) {
    uint8_t k1[8], k2[8], k3[8];
    memcpy(k1, key, 8);
    memcpy(k2, key + 8, 8);
    memcpy(k3, key + 16, 8);

    uint64_t a;
    if (encrypt) {
        a = _des_crypt_block(block, k1, true);
        a = _des_crypt_block(a, k2, false);
        a = _des_crypt_block(a, k3, true);
    } else {
        a = _des_crypt_block(block, k3, false);
        a = _des_crypt_block(a, k2, true);
        a = _des_crypt_block(a, k1, false);
    }
    *out_block = a;
}

static void _des3_ecb_crypt(const uint8_t *key24, const uint8_t *in,
                            uint8_t *out, size_t len, bool encrypt) {
    for (size_t off = 0; off < len; off += 8) {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++) {
            block = (block << 8) | in[off + i];
        }
        uint64_t outBlock;
        _des3_crypt_block(block, key24, encrypt, &outBlock);
        for (int i = 7; i >= 0; i--) {
            out[off + i] = (uint8_t)(outBlock & 0xFF);
            outBlock >>= 8;
        }
    }
}

static void _des3_cbc_crypt(const uint8_t *key24, const uint8_t iv8[8],
                            const uint8_t *in, uint8_t *out, size_t len,
                            bool encrypt) {
    uint64_t iv = 0;
    for (int i = 0; i < 8; i++) {
        iv = (iv << 8) | iv8[i];
    }
    for (size_t off = 0; off < len; off += 8) {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++) {
            block = (block << 8) | in[off + i];
        }

        if (encrypt) {
            block ^= iv;
            uint64_t enc;
            _des3_crypt_block(block, key24, true, &enc);
            block = enc;
            iv = block;
        } else {
            uint64_t cur = block;
            uint64_t dec;
            _des3_crypt_block(block, key24, false, &dec);
            block = dec ^ iv;
            iv = cur;
        }

        for (int i = 7; i >= 0; i--) {
            out[off + i] = (uint8_t)(block & 0xFF);
            block >>= 8;
        }
    }
}

void df_3des_cbc_encrypt(const uint8_t key16[16], const uint8_t iv8[8],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t key24[24];
    memcpy(key24, key16, 16);
    memcpy(key24 + 16, key16, 8);
    _des3_cbc_crypt(key24, iv8, in, out, len, true);
}

void df_3des_cbc_decrypt(const uint8_t key16[16], const uint8_t iv8[8],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t key24[24];
    memcpy(key24, key16, 16);
    memcpy(key24 + 16, key16, 8);
    _des3_cbc_crypt(key24, iv8, in, out, len, false);
}

void df_3des_ecb_decrypt(const uint8_t key16[16],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t key24[24];
    memcpy(key24, key16, 16);
    memcpy(key24 + 16, key16, 8);
    _des3_ecb_crypt(key24, in, out, len, false);
}

void df_3k3des_cbc_encrypt(const uint8_t key24[24], const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len) {
    _des3_cbc_crypt(key24, iv8, in, out, len, true);
}

void df_3k3des_cbc_decrypt(const uint8_t key24[24], const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len) {
    _des3_cbc_crypt(key24, iv8, in, out, len, false);
}

/* ── Single-DES CBC fallback ─────────────────────────────────────────── */

void df_des_cbc_encrypt(const uint8_t key8[8], const uint8_t iv8[8],
                        const uint8_t *in, uint8_t *out, size_t len) {
    _des_cbc_crypt(key8, iv8, in, out, len, true);
}

void df_des_cbc_decrypt(const uint8_t key8[8], const uint8_t iv8[8],
                        const uint8_t *in, uint8_t *out, size_t len) {
    _des_cbc_crypt(key8, iv8, in, out, len, false);
}
