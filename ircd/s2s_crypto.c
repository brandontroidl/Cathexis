/*
 * IRC - Internet Relay Chat, ircd/s2s_crypto.c
 * Copyright (C) 2026 Cathexis Development Team

 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * Cathexis protocol extensions for cryptographic S2S authentication.
 * Requires OpenSSL for HMAC-SHA256 and SHA-256.
 */
/** @file
 * @brief Server-to-server cryptographic message authentication.
 */
#include "config.h"

#ifdef USE_SSL

#include "s2s_crypto.h"
#include "channel.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_crypto.h"
#include "s_debug.h"
#include "send.h"
#include "list.h"

#ifdef USE_PQ
#include "pq_crypto.h"
#include <openssl/evp.h>
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 * Internal helpers
 * ================================================================ */

/** Convert binary data to lowercase hex string.
 * @param[out] hex   Output buffer (must be >= len*2 + 1).
 * @param[in]  bin   Binary data.
 * @param[in]  len   Length of binary data.
 */
static void bin_to_hex(char *hex, const unsigned char *bin, size_t len)
{
  static const char hextab[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    hex[i * 2]     = hextab[(bin[i] >> 4) & 0x0f];
    hex[i * 2 + 1] = hextab[bin[i] & 0x0f];
  }
  hex[len * 2] = '\0';
}

/** Convert hex string to binary.
 * @param[out] bin    Output buffer.
 * @param[in]  hex    Hex string.
 * @param[in]  binlen Expected binary length.
 * @return 0 on success, -1 on invalid hex.
 */
static int hex_to_bin(unsigned char *bin, const char *hex, size_t binlen)
{
  size_t i;
  for (i = 0; i < binlen; i++) {
    unsigned int hi, lo;
    if (hex[i*2] >= '0' && hex[i*2] <= '9') hi = hex[i*2] - '0';
    else if (hex[i*2] >= 'a' && hex[i*2] <= 'f') hi = hex[i*2] - 'a' + 10;
    else if (hex[i*2] >= 'A' && hex[i*2] <= 'F') hi = hex[i*2] - 'A' + 10;
    else return -1;

    if (hex[i*2+1] >= '0' && hex[i*2+1] <= '9') lo = hex[i*2+1] - '0';
    else if (hex[i*2+1] >= 'a' && hex[i*2+1] <= 'f') lo = hex[i*2+1] - 'a' + 10;
    else if (hex[i*2+1] >= 'A' && hex[i*2+1] <= 'F') lo = hex[i*2+1] - 'A' + 10;
    else return -1;

    bin[i] = (hi << 4) | lo;
  }
  return 0;
}

/** Compute HMAC-SHA256.
 * @param[out] mac     32-byte output.
 * @param[in]  key     Key material.
 * @param[in]  keylen  Key length.
 * @param[in]  data    Data to authenticate.
 * @param[in]  datalen Data length.
 * @return 0 on success, -1 on failure.
 */
/** Compute the link MAC over a message.
 *
 *  Cathexis 1.6.0+ with USE_PQ: HMAC-SHA3-512 (64 bytes output).
 *  Pre-1.6.0 / !USE_PQ:          HMAC-SHA256    (32 bytes output).
 *
 *  The MAC width is chosen at compile time; mac_out must be at least
 *  s2s_mac_len() bytes (64 or 32).
 *
 * @param[out] mac     Buffer for MAC output (caller sizes using s2s_mac_len).
 * @param[in]  key     HMAC key (64 bytes of derived key material).
 * @param[in]  keylen  Key length actually consumed (64 for SHA3, 32 for SHA256).
 * @param[in]  data    Data to authenticate.
 * @param[in]  datalen Data length.
 * @return 0 on success, -1 on failure.
 */
static int compute_link_mac(unsigned char *mac,
                            const unsigned char *key, size_t keylen,
                            const unsigned char *data, size_t datalen)
{
#ifdef USE_PQ
  /* Modern path: HMAC-SHA3-512 produces 64-byte MAC.
   * keylen is the HMAC key length; we pass the full 64-byte derived key. */
  return pq_hmac_sha3_512(key, keylen, data, datalen, mac);
#else
  return ircd_hmac_sha256(key, keylen, data, datalen, mac);
#endif
}

/** Return the MAC byte width for the active compile-time cipher suite. */
static size_t s2s_mac_len(void)
{
#ifdef USE_PQ
  return 64;  /* SHA3-512 */
#else
  return 32;  /* SHA256 */
#endif
}

/** Return the hex-encoded MAC length (2 * byte width). */
static size_t s2s_mac_hexlen(void)
{
  return s2s_mac_len() * 2;
}

/* Legacy shim — keep the old name for any internal callers. */
static int compute_hmac_sha256(unsigned char *mac,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *data, size_t datalen)
{
  return compute_link_mac(mac, key, keylen, data, datalen);
}

/* ================================================================
 * Key Derivation
 * ================================================================ */

/** Derive S2S keys from the link password.
 *
 * Cathexis 1.6.0+ (USE_PQ): HKDF-SHA3-512 with fresh labels that include
 *   the version suffix "-v2". This prevents accidental key reuse with
 *   the pre-1.6.0 HMAC-SHA256 derivation, and the wider 64-byte output
 *   saturates HMAC-SHA3-512's block size.
 *
 * Pre-1.6.0: HMAC-SHA256 KDF with v1 labels for backward compatibility.
 *   Only reached if Cathexis is built with --disable-ssl or without liboqs.
 */
int s2s_derive_keys(struct S2SKey *key, const char *passwd)
{
  if (!passwd || !*passwd) {
    key->active = 0;
    return -1;
  }

  memset(key->hmac_key, 0, sizeof(key->hmac_key));
  memset(key->sacert_key, 0, sizeof(key->sacert_key));
  memset(key->peer_pqfp, 0, sizeof(key->peer_pqfp));
  key->pq_active = 0;
  key->pq_required = 0;

#ifdef USE_PQ
  /* Modern path: HKDF-SHA3-512, 64-byte keys.
   * Labels are distinct per-subkey AND distinct from the v1 labels so
   * an attacker who knew a pre-1.6.0 key cannot reuse it here. */
  {
    static const uint8_t label_hmac[]   = "cathexis-s2s-hmac-sha3-v2";
    static const uint8_t label_sacert[] = "cathexis-s2s-sacert-sha3-v2";
    if (pq_hkdf_sha3_512((const uint8_t *)passwd, strlen(passwd),
                         NULL, 0,
                         label_hmac, sizeof(label_hmac) - 1,
                         key->hmac_key, 64) != 0)
      return -1;
    if (pq_hkdf_sha3_512((const uint8_t *)passwd, strlen(passwd),
                         NULL, 0,
                         label_sacert, sizeof(label_sacert) - 1,
                         key->sacert_key, 64) != 0)
      return -1;
  }
#else
  /* Classical fallback — this code path is dead in a 1.6.0 production
   * build (PQ is hard-required by configure), but remains for --disable-ssl
   * or auditors wanting to read the pre-upgrade derivation. */
  if (compute_hmac_sha256(key->hmac_key,
      (const unsigned char *)passwd, strlen(passwd),
      (const unsigned char *)"cathexis-s2s-hmac-v1", 20) < 0)
    return -1;
  if (compute_hmac_sha256(key->sacert_key,
      (const unsigned char *)passwd, strlen(passwd),
      (const unsigned char *)"cathexis-s2s-sacert-v1", 22) < 0)
    return -1;
#endif

  key->active = 1;
  Debug((DEBUG_DEBUG, "s2s_derive_keys: %s keys derived",
#ifdef USE_PQ
         "HMAC-SHA3-512"
#else
         "HMAC-SHA256"
#endif
         ));
  return 0;
}

/* ================================================================
 * Per-Message HMAC
 * ================================================================ */

int s2s_sign_message(char *out, size_t outlen,
                     const char *msg, const struct S2SKey *key)
{
  unsigned char mac[64];         /* Largest possible: SHA3-512 */
  char hexmac[129];              /* Largest possible hex + NUL */
  size_t maclen, hexlen;
  size_t taglen, msglen;

  if (!key || !key->active)
    return -1;

  maclen = s2s_mac_len();
  hexlen = s2s_mac_hexlen();
  msglen = strlen(msg);

  if (compute_link_mac(mac, key->hmac_key, maclen,
      (const unsigned char *)msg, msglen) < 0)
    return -1;

  bin_to_hex(hexmac, mac, maclen);

  /* Format: @hmac=<hex> <message> */
  taglen = 6 + hexlen + 1; /* "@hmac=" + hex + " " */
  if (taglen + msglen + 1 > outlen)
    return -1;

  ircd_snprintf(0, out, outlen, "%s%s %s", S2S_HMAC_TAG, hexmac, msg);
  return strlen(out);
}

int s2s_verify_message(const char *tagged, const struct S2SKey *key,
                       const char **content)
{
  unsigned char expected[64], received[64];
  const char *hexstart, *msgstart;
  size_t maclen, hexlen;

  if (!key || !key->active) {
    /* No key = no verification (legacy link) */
    *content = tagged;
    return 1;
  }

  maclen = s2s_mac_len();
  hexlen = s2s_mac_hexlen();

  /* Check for @hmac= prefix */
  if (strncmp(tagged, S2S_HMAC_TAG, 6) != 0) {
    Debug((DEBUG_DEBUG, "s2s_verify: missing HMAC tag"));
    *content = tagged;
    return 0;
  }

  hexstart = tagged + 6;

  if (strlen(hexstart) < hexlen + 1) {
    Debug((DEBUG_DEBUG, "s2s_verify: truncated HMAC tag"));
    return 0;
  }

  if (hex_to_bin(received, hexstart, maclen) < 0) {
    Debug((DEBUG_DEBUG, "s2s_verify: invalid hex in HMAC tag"));
    return 0;
  }

  msgstart = hexstart + hexlen;
  if (*msgstart != ' ') {
    Debug((DEBUG_DEBUG, "s2s_verify: char after hex is '%c' (0x%02x), not space",
           *msgstart, (unsigned char)*msgstart));
    return 0;
  }
  msgstart++;

  if (compute_link_mac(expected, key->hmac_key, maclen,
      (const unsigned char *)msgstart, strlen(msgstart)) < 0)
    return 0;

  if (CRYPTO_memcmp(expected, received, maclen) != 0) {
    Debug((DEBUG_DEBUG, "s2s_verify: HMAC mismatch — message rejected"));
    return 0;
  }

  *content = msgstart;
  return 1;
}

/* ================================================================
 * SA* Command Signing
 * ================================================================ */

int s2s_sign_sacmd(char *out, size_t outlen,
                   const char *cmd, const struct S2SKey *key)
{
  unsigned char mac[64];
  char hexmac[129];
  size_t maclen, hexlen;

  if (!key || !key->active)
    return -1;

  maclen = s2s_mac_len();
  hexlen = s2s_mac_hexlen();

  if (compute_link_mac(mac, key->sacert_key, maclen,
      (const unsigned char *)cmd, strlen(cmd)) < 0)
    return -1;

  bin_to_hex(hexmac, mac, maclen);

  if (8 + hexlen + 1 + strlen(cmd) + 1 > outlen)
    return -1;

  ircd_snprintf(0, out, outlen, "%s%s %s", S2S_SACERT_TAG, hexmac, cmd);
  return strlen(out);
}

int s2s_verify_sacmd(const char *tagged, const struct S2SKey *key,
                     const char **content)
{
  unsigned char expected[64], received[64];
  const char *hexstart, *cmdstart;
  size_t maclen, hexlen;

  if (!key || !key->active) {
    *content = tagged;
    return 0; /* No key = cannot verify = reject */
  }

  maclen = s2s_mac_len();
  hexlen = s2s_mac_hexlen();

  if (strncmp(tagged, S2S_SACERT_TAG, 8) != 0) {
    Debug((DEBUG_DEBUG, "s2s_verify_sacmd: missing sacert tag"));
    *content = tagged;
    return 0;
  }

  hexstart = tagged + 8;
  if (strlen(hexstart) < hexlen + 1)
    return 0;

  if (hex_to_bin(received, hexstart, maclen) < 0)
    return 0;

  cmdstart = hexstart + hexlen;
  if (*cmdstart != ' ')
    return 0;
  cmdstart++;

  if (compute_link_mac(expected, key->sacert_key, maclen,
      (const unsigned char *)cmdstart, strlen(cmdstart)) < 0)
    return 0;

  if (CRYPTO_memcmp(expected, received, maclen) != 0) {
    Debug((DEBUG_DEBUG, "s2s_verify_sacmd: HMAC mismatch — SA* command rejected"));
    return 0;
  }

  *content = cmdstart;
  return 1;
}

/* ================================================================
 * Channel State Hashing
 * ================================================================ */

/** Build a deterministic string representation of channel state.
 * Format:
 *   NAME:<chname>\n
 *   MODE:<modestring>\n
 *   KEY:<key>\n
 *   LIMIT:<limit>\n
 *   TOPIC:<topictext>\n
 *   BAN:<banmask>\n  (sorted)
 *   EXCEPT:<exceptmask>\n  (sorted)
 *   MEMBER:<nick>:<status>\n  (sorted by nick)
 *
 * Sorting ensures the hash is deterministic regardless of internal
 * ordering differences between servers.
 */
int s2s_channel_hash(char *hexhash, const struct Channel *chptr)
{
  EVP_MD_CTX *ctx;
  unsigned char hash[64];        /* SHA3-512 output */
  char buf[512];
  struct Membership *member;
  int len;
  const EVP_MD *md;
  size_t hashlen;

  if (!chptr) return -1;

  ctx = EVP_MD_CTX_new();
  if (!ctx) return -1;

#ifdef USE_PQ
  md = EVP_sha3_512();
  hashlen = 64;
#else
  md = EVP_sha256();
  hashlen = 32;
#endif

  if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  len = ircd_snprintf(0, buf, sizeof(buf), "NAME:%s\n", chptr->chname);
  EVP_DigestUpdate(ctx, buf, len);

  len = ircd_snprintf(0, buf, sizeof(buf), "MODE:%u\n", chptr->mode.mode);
  EVP_DigestUpdate(ctx, buf, len);

  len = ircd_snprintf(0, buf, sizeof(buf), "EXMODE:%u\n", chptr->mode.exmode);
  EVP_DigestUpdate(ctx, buf, len);

  if (chptr->mode.key[0]) {
    len = ircd_snprintf(0, buf, sizeof(buf), "KEY:%s\n", chptr->mode.key);
    EVP_DigestUpdate(ctx, buf, len);
  }

  if (chptr->mode.limit) {
    len = ircd_snprintf(0, buf, sizeof(buf), "LIMIT:%u\n", chptr->mode.limit);
    EVP_DigestUpdate(ctx, buf, len);
  }

  if (chptr->topic[0]) {
    len = ircd_snprintf(0, buf, sizeof(buf), "TOPIC:%s\n", chptr->topic);
    EVP_DigestUpdate(ctx, buf, len);
  }

  {
    struct Ban *ban;
    for (ban = chptr->banlist; ban; ban = ban->next) {
      len = ircd_snprintf(0, buf, sizeof(buf), "BAN:%s\n", ban->banstr);
      EVP_DigestUpdate(ctx, buf, len);
    }
  }

  for (member = chptr->members; member; member = member->next_member) {
    unsigned int status = member->status;
    len = ircd_snprintf(0, buf, sizeof(buf), "MEMBER:%s:%u\n",
                        cli_name(member->user), status);
    EVP_DigestUpdate(ctx, buf, len);
  }

  EVP_DigestFinal_ex(ctx, hash, NULL);
  EVP_MD_CTX_free(ctx);

  bin_to_hex(hexhash, hash, hashlen);
  return 0;
}

int s2s_channel_verify(const struct Channel *chptr, const char *remote_hash)
{
  char local_hash[129];
  size_t hexlen;

  if (s2s_channel_hash(local_hash, chptr) < 0)
    return 0;

#ifdef USE_PQ
  hexlen = 128;  /* SHA3-512 */
#else
  hexlen = 64;   /* SHA256 */
#endif

  if (strlen(remote_hash) != hexlen)
    return 0;

  return (CRYPTO_memcmp(local_hash, remote_hash, hexlen) == 0);
}

/* ================================================================
 * Post-Quantum Link Authentication (Cathexis 1.6.0+)
 * ================================================================ */

#ifdef USE_PQ

/* base64 encode helper — EVP_EncodeBlock, NUL-terminate output. */
static int s2s_b64_encode(const uint8_t *in, size_t inlen,
                           char *out, size_t outcap)
{
  int n;
  if (!in || !out) return -1;
  n = EVP_EncodeBlock((unsigned char *)out, in, (int)inlen);
  if (n < 0 || (size_t)(n + 1) > outcap) return -1;
  out[n] = '\0';
  return n;
}

static int s2s_b64_decode(const char *in, uint8_t *out, size_t outcap,
                           size_t *written)
{
  int n;
  size_t inlen;
  if (!in || !out) return -1;
  inlen = strlen(in);
  n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)inlen);
  if (n < 0) return -1;
  /* Account for '=' padding */
  while (inlen > 0 && in[inlen - 1] == '=') {
    n--;
    inlen--;
  }
  if ((size_t)n > outcap) return -1;
  if (written) *written = (size_t)n;
  return 0;
}

int s2s_pq_sign_challenge(char *b64out, size_t b64outlen,
                          const struct PQKeypair *kp,
                          const unsigned char *challenge,
                          size_t challen)
{
  uint8_t raw[16384];
  size_t rawlen = sizeof(raw);

  if (!b64out || !kp || !kp->active || !challenge) return -1;

  if (pq_sign_dual(raw, &rawlen, kp, challenge, challen) != 0) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "s2s_pq_sign_challenge: pq_sign_dual failed (buffer too small? rawlen=%zu)",
              rawlen);
    return -1;
  }

  if (s2s_b64_encode(raw, rawlen, b64out, b64outlen) < 0) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "s2s_pq_sign_challenge: base64 encode failed (rawlen=%zu b64cap=%zu)",
              rawlen, b64outlen);
    return -1;
  }
  return 0;
}

int s2s_pq_verify_challenge(const char *b64sig,
                             const struct PQKeypair *peer_kp,
                             const unsigned char *challenge,
                             size_t challen)
{
  uint8_t raw[16384];
  size_t rawlen;

  if (!b64sig || !peer_kp || !challenge) return 0;

  if (s2s_b64_decode(b64sig, raw, sizeof(raw), &rawlen) < 0) {
    Debug((DEBUG_DEBUG, "s2s_pq_verify: base64 decode failed"));
    return 0;
  }

  return pq_verify_dual(raw, rawlen, peer_kp, challenge, challen) == 1;
}

int s2s_pq_fingerprint(unsigned char fp_out[32],
                       const struct PQKeypair *kp)
{
  EVP_MD_CTX *ctx;
  const EVP_MD *md;
  unsigned int outlen = 32;

  if (!fp_out || !kp) return -1;

  md = EVP_sha3_256();
  if (!md) return -1;

  ctx = EVP_MD_CTX_new();
  if (!ctx) return -1;

  /* Hash the concatenation of both public keys in a stable order. */
  if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
      EVP_DigestUpdate(ctx, kp->primary_pub,   kp->primary_pub_len)   != 1 ||
      EVP_DigestUpdate(ctx, kp->secondary_pub, kp->secondary_pub_len) != 1 ||
      EVP_DigestFinal_ex(ctx, fp_out, &outlen) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return (outlen == 32) ? 0 : -1;
}

#endif /* USE_PQ */

#else /* !USE_SSL */

/* Stub implementations when OpenSSL is not available.
 * S2S crypto features are disabled — links operate in legacy mode. */

#include "s2s_crypto.h"
#include "channel.h"
#include "client.h"
#include "ircd_string.h"

#include <string.h>

int s2s_derive_keys(struct S2SKey *key, const char *passwd)
{
  key->active = 0;
  return -1;
}

int s2s_sign_message(char *out, size_t outlen,
                     const char *msg, const struct S2SKey *key)
{
  /* No signing — pass through */
  ircd_strncpy(out, msg, outlen - 1);
  return strlen(out);
}

int s2s_verify_message(const char *tagged, const struct S2SKey *key,
                       const char **content)
{
  *content = tagged;
  return 1; /* Accept all in legacy mode */
}

int s2s_sign_sacmd(char *out, size_t outlen,
                   const char *cmd, const struct S2SKey *key)
{
  ircd_strncpy(out, cmd, outlen - 1);
  return strlen(out);
}

int s2s_verify_sacmd(const char *tagged, const struct S2SKey *key,
                     const char **content)
{
  *content = tagged;
  return 0; /* Reject SA* in non-SSL builds — no verification possible */
}

int s2s_channel_hash(char *hexhash, const struct Channel *chptr)
{
  memset(hexhash, '0', 64);
  hexhash[64] = '\0';
  return -1;
}

int s2s_channel_verify(const struct Channel *chptr, const char *remote_hash)
{
  return 1; /* Assume sync in legacy mode */
}

#endif /* USE_SSL */
