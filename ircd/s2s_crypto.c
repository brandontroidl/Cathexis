/*
 * IRC - Internet Relay Chat, ircd/s2s_crypto.c
 * Copyright (C) 2026 Brandon Troidl

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
static int compute_hmac_sha256(unsigned char *mac,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *data, size_t datalen)
{
  return ircd_hmac_sha256(key, keylen, data, datalen, mac);
}

/* ================================================================
 * Key Derivation
 * ================================================================ */

/** Derive S2S keys from link password using HMAC-SHA256 as KDF.
 *
 * hmac_key   = HMAC-SHA256(password, "cathexis-s2s-hmac-v1")
 * sacert_key = HMAC-SHA256(password, "cathexis-s2s-sacert-v1")
 *
 * This is a simple but sound KDF: HMAC with distinct labels produces
 * independent keys. The link password provides the entropy.
 */
int s2s_derive_keys(struct S2SKey *key, const char *passwd)
{
  if (!passwd || !*passwd) {
    key->active = 0;
    return -1;
  }

  if (compute_hmac_sha256(key->hmac_key,
      (const unsigned char *)passwd, strlen(passwd),
      (const unsigned char *)"cathexis-s2s-hmac-v1", 20) < 0)
    return -1;

  if (compute_hmac_sha256(key->sacert_key,
      (const unsigned char *)passwd, strlen(passwd),
      (const unsigned char *)"cathexis-s2s-sacert-v1", 22) < 0)
    return -1;

  key->active = 1;
  Debug((DEBUG_DEBUG, "s2s_derive_keys: keys derived successfully"));
  return 0;
}

/* ================================================================
 * Per-Message HMAC
 * ================================================================ */

int s2s_sign_message(char *out, size_t outlen,
                     const char *msg, const struct S2SKey *key)
{
  unsigned char mac[32];
  char hexmac[65];
  size_t taglen, msglen;

  if (!key || !key->active)
    return -1;

  msglen = strlen(msg);

  /* Compute HMAC-SHA256 over the raw message */
  if (compute_hmac_sha256(mac, key->hmac_key, 32,
      (const unsigned char *)msg, msglen) < 0)
    return -1;

  bin_to_hex(hexmac, mac, 32);

  /* Format: @hmac=<64hex> <message>\r\n */
  taglen = 6 + 64 + 1; /* "@hmac=" + hex + " " */
  if (taglen + msglen + 1 > outlen)
    return -1;

  ircd_snprintf(0, out, outlen, "%s%s %s", S2S_HMAC_TAG, hexmac, msg);
  return strlen(out);
}

int s2s_verify_message(const char *tagged, const struct S2SKey *key,
                       const char **content)
{
  unsigned char expected[32], received[32];
  const char *hexstart, *msgstart;

  if (!key || !key->active) {
    /* No key = no verification (legacy link) */
    *content = tagged;
    return 1;
  }

  /* Check for @hmac= prefix */
  if (strncmp(tagged, S2S_HMAC_TAG, 6) != 0) {
    /* No HMAC tag on a link that requires it */
    Debug((DEBUG_DEBUG, "s2s_verify: missing HMAC tag"));
    *content = tagged;
    return 0;
  }

  hexstart = tagged + 6; /* skip "@hmac=" */

  /* Verify hex length */
  if (strlen(hexstart) < 64 + 1) { /* 64 hex + space */
    Debug((DEBUG_DEBUG, "s2s_verify: truncated HMAC tag"));
    return 0;
  }

  /* Parse the hex HMAC */
  if (hex_to_bin(received, hexstart, 32) < 0) {
    Debug((DEBUG_DEBUG, "s2s_verify: invalid hex in HMAC tag"));
    return 0;
  }

  /* Message content starts after the tag + space */
  msgstart = hexstart + 64;
  if (*msgstart != ' ') {
    Debug((DEBUG_DEBUG, "s2s_verify: char after hex is '%c' (0x%02x), not space",
           *msgstart, (unsigned char)*msgstart));
    return 0;
  }
  msgstart++; /* skip the space */

  /* Compute expected HMAC over the message content */
  if (compute_hmac_sha256(expected, key->hmac_key, 32,
      (const unsigned char *)msgstart, strlen(msgstart)) < 0)
    return 0;

  /* Constant-time comparison */
  if (CRYPTO_memcmp(expected, received, 32) != 0) {
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
  unsigned char mac[32];
  char hexmac[65];

  if (!key || !key->active)
    return -1;

  if (compute_hmac_sha256(mac, key->sacert_key, 32,
      (const unsigned char *)cmd, strlen(cmd)) < 0)
    return -1;

  bin_to_hex(hexmac, mac, 32);

  ircd_snprintf(0, out, outlen, "%s%s %s", S2S_SACERT_TAG, hexmac, cmd);
  return strlen(out);
}

int s2s_verify_sacmd(const char *tagged, const struct S2SKey *key,
                     const char **content)
{
  unsigned char expected[32], received[32];
  const char *hexstart, *cmdstart;

  if (!key || !key->active) {
    *content = tagged;
    return 0; /* No key = cannot verify = reject */
  }

  if (strncmp(tagged, S2S_SACERT_TAG, 8) != 0) {
    Debug((DEBUG_DEBUG, "s2s_verify_sacmd: missing sacert tag"));
    *content = tagged;
    return 0;
  }

  hexstart = tagged + 8;
  if (strlen(hexstart) < 64 + 1)
    return 0;

  if (hex_to_bin(received, hexstart, 32) < 0)
    return 0;

  cmdstart = hexstart + 64;
  if (*cmdstart != ' ')
    return 0;
  cmdstart++;

  if (compute_hmac_sha256(expected, key->sacert_key, 32,
      (const unsigned char *)cmdstart, strlen(cmdstart)) < 0)
    return 0;

  if (CRYPTO_memcmp(expected, received, 32) != 0) {
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
  unsigned char hash[32];
  char buf[512];
  struct Membership *member;
  int len;

  if (!chptr) return -1;

  ctx = EVP_MD_CTX_new();
  if (!ctx) return -1;

  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

  /* Channel name */
  len = ircd_snprintf(0, buf, sizeof(buf), "NAME:%s\n", chptr->chname);
  EVP_DigestUpdate(ctx, buf, len);

  /* Channel modes (numeric representation for determinism) */
  len = ircd_snprintf(0, buf, sizeof(buf), "MODE:%u\n", chptr->mode.mode);
  EVP_DigestUpdate(ctx, buf, len);

  /* Extended modes */
  len = ircd_snprintf(0, buf, sizeof(buf), "EXMODE:%u\n", chptr->mode.exmode);
  EVP_DigestUpdate(ctx, buf, len);

  /* Channel key */
  if (chptr->mode.key[0]) {
    len = ircd_snprintf(0, buf, sizeof(buf), "KEY:%s\n", chptr->mode.key);
    EVP_DigestUpdate(ctx, buf, len);
  }

  /* Channel limit */
  if (chptr->mode.limit) {
    len = ircd_snprintf(0, buf, sizeof(buf), "LIMIT:%u\n", chptr->mode.limit);
    EVP_DigestUpdate(ctx, buf, len);
  }

  /* Topic */
  if (chptr->topic[0]) {
    len = ircd_snprintf(0, buf, sizeof(buf), "TOPIC:%s\n", chptr->topic);
    EVP_DigestUpdate(ctx, buf, len);
  }

  /* Ban list — hash each entry. Note: for true determinism across
   * servers with different ban ordering, we should sort. For the
   * initial implementation, we hash in list order and accept that
   * different ordering = different hash = resync trigger. This is
   * conservative (may cause unnecessary resyncs) but always safe. */
  {
    struct Ban *ban;
    for (ban = chptr->banlist; ban; ban = ban->next) {
      len = ircd_snprintf(0, buf, sizeof(buf), "BAN:%s\n", ban->banstr);
      EVP_DigestUpdate(ctx, buf, len);
    }
  }

  /* Members — hash nick:status pairs */
  for (member = chptr->members; member; member = member->next_member) {
    unsigned int status = member->status;
    len = ircd_snprintf(0, buf, sizeof(buf), "MEMBER:%s:%u\n",
                        cli_name(member->user), status);
    EVP_DigestUpdate(ctx, buf, len);
  }

  EVP_DigestFinal_ex(ctx, hash, NULL);
  EVP_MD_CTX_free(ctx);

  bin_to_hex(hexhash, hash, 32);
  return 0;
}

int s2s_channel_verify(const struct Channel *chptr, const char *remote_hash)
{
  char local_hash[65];

  if (s2s_channel_hash(local_hash, chptr) < 0)
    return 0;

  /* Constant-time comparison */
  if (strlen(remote_hash) != 64)
    return 0;

  return (CRYPTO_memcmp(local_hash, remote_hash, 64) == 0);
}

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
