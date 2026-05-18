#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── AES-128 ─────────────────────────────────────────────────────────── */
void df_aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void df_aes_ecb_decrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void df_aes_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);
void df_aes_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);
void df_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[16]);
void df_truncate_mac(const uint8_t mac[16], uint8_t out[8]);
void df_derive_session_key(const uint8_t key[16], const uint8_t rndA[16],
                           const uint8_t rndB[16], uint8_t label,
                           uint8_t out[16]);

/* ── 3DES (2K3DES, 16-byte key) — for DESFire legacy PICC auth ───────── */
/* Uses mbedTLS which is part of ESP32 SDK — no extra library needed.     */
void df_3des_cbc_encrypt(const uint8_t key16[16], const uint8_t iv8[8],
                          const uint8_t *in, uint8_t *out, size_t len);
void df_3des_cbc_decrypt(const uint8_t key16[16], const uint8_t iv8[8],
                          const uint8_t *in, uint8_t *out, size_t len);
void df_3des_ecb_decrypt(const uint8_t key16[16],
                         const uint8_t *in, uint8_t *out, size_t len);

/* ── 3K3DES (24-byte key) — for ISO legacy PICC auth ─────────────────── */
void df_3k3des_cbc_encrypt(const uint8_t key24[24], const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len);
void df_3k3des_cbc_decrypt(const uint8_t key24[24], const uint8_t iv8[8],
                           const uint8_t *in, uint8_t *out, size_t len);

/* Single-DES CBC fallback (factory cards where K1==K2, e.g. all zeros) */
void df_des_cbc_encrypt(const uint8_t key8[8], const uint8_t iv8[8],
                         const uint8_t *in, uint8_t *out, size_t len);
void df_des_cbc_decrypt(const uint8_t key8[8], const uint8_t iv8[8],
                         const uint8_t *in, uint8_t *out, size_t len);

/* ── Misc ─────────────────────────────────────────────────────────────── */
uint32_t df_crc32(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
