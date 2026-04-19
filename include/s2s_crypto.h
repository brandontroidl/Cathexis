/** @file s2s_crypto.h
 * @brief Server-to-server cryptographic message authentication.
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
 * Cathexis 1.2.0 protocol extensions:
 *
 *   1. Per-message HMAC-SHA256 — every S2S message is signed with a key
 *      derived from the link password. Prevents injection and tampering.
 *
 *   2. Channel state hashing — after BURST, servers exchange SHA-256
 *      hashes of channel state. Mismatches trigger re-synchronization.
 *
 *   3. SA* command signing — privileged commands (SAJOIN, SAMODE, etc.)
 *      carry an HMAC proving they originated from an authorized source.
 *
 * Wire format extensions (breaks legacy P10 compatibility):
 *
 *   @hmac=<64-hex>         Per-message authentication tag
 *   @sacert=<64-hex>       SA* command authorization tag
 *   CSYNC #channel <hash>  Channel state verification
 *   CRESYNC #channel       Request full channel re-burst
 */
#ifndef INCLUDED_s2s_crypto_h
#define INCLUDED_s2s_crypto_h

#include "config.h"
#include <stddef.h>

struct Client;
struct Channel;

/** Maximum hex-encoded HMAC length (SHA-256 = 32 bytes = 64 hex chars). */
#define S2S_HMAC_HEXLEN  64
/** S2S HMAC tag prefix in IRCv3 format. */
#define S2S_HMAC_TAG     "@hmac="
/** SA* authorization tag prefix. */
#define S2S_SACERT_TAG   "@sacert="
/** Channel state hash length (SHA-256 = 64 hex chars). */
#define S2S_HASH_HEXLEN  64

/** Derived key for a server-to-server link.
 * Stored in the server's Client structure after link establishment.
 */
struct S2SKey {
  unsigned char hmac_key[32];    /**< HMAC-SHA256 key for message auth */
  unsigned char sacert_key[32];  /**< HMAC-SHA256 key for SA* signing */
  int           active;          /**< 1 if keys are derived and active */
};

/* ================================================================
 * Key Derivation
 * ================================================================ */

/** Derive S2S cryptographic keys from a link password.
 * Uses HMAC-SHA256 as a KDF with fixed labels to produce two
 * independent keys: one for per-message HMAC, one for SA* signing.
 *
 * @param[out] key     S2SKey structure to populate.
 * @param[in]  passwd  Link password from the Connect block.
 * @return 0 on success, -1 on failure.
 */
extern int s2s_derive_keys(struct S2SKey *key, const char *passwd);

/* ================================================================
 * Per-Message HMAC
 * ================================================================ */

/** Sign an outgoing S2S message.
 * Computes HMAC-SHA256 over the message content and prepends the
 * tag. The output buffer must be at least strlen(msg) + 72 bytes.
 *
 * @param[out] out     Output buffer (tagged message).
 * @param[in]  outlen  Size of output buffer.
 * @param[in]  msg     Original message to sign.
 * @param[in]  key     S2S key for the destination server.
 * @return Length of tagged message, or -1 on failure.
 */
extern int s2s_sign_message(char *out, size_t outlen,
                            const char *msg, const struct S2SKey *key);

/** Verify an incoming S2S message.
 * Extracts the @hmac= tag, verifies the HMAC, and returns a pointer
 * to the message content (past the tag).
 *
 * @param[in]  tagged   Full tagged message.
 * @param[in]  key      S2S key for the source server.
 * @param[out] content  Pointer to message content (past tag).
 * @return 1 if valid, 0 if invalid or missing tag.
 */
extern int s2s_verify_message(const char *tagged, const struct S2SKey *key,
                              const char **content);

/* ================================================================
 * SA* Command Signing
 * ================================================================ */

/** Sign an SA* command with the services authorization key.
 * Computes HMAC-SHA256 over the command and prepends @sacert= tag.
 *
 * @param[out] out     Output buffer.
 * @param[in]  outlen  Size of output buffer.
 * @param[in]  cmd     SA* command to sign.
 * @param[in]  key     S2S key (uses sacert_key).
 * @return Length of tagged command, or -1 on failure.
 */
extern int s2s_sign_sacmd(char *out, size_t outlen,
                          const char *cmd, const struct S2SKey *key);

/** Verify an SA* command's authorization tag.
 * @param[in]  tagged  Full tagged SA* command.
 * @param[in]  key     S2S key (uses sacert_key).
 * @param[out] content Pointer to command content (past tag).
 * @return 1 if valid, 0 if invalid or missing tag.
 */
extern int s2s_verify_sacmd(const char *tagged, const struct S2SKey *key,
                            const char **content);

/* ================================================================
 * Channel State Hashing
 * ================================================================ */

/** Compute a SHA-256 hash of a channel's complete state.
 * Includes: channel name, modes, key, limit, topic,
 * ban list, exception list, and sorted member list with status bits.
 * The hash is deterministic given the same channel state.
 *
 * @param[out] hexhash Output buffer (must be >= 65 bytes).
 * @param[in]  chptr   Channel to hash.
 * @return 0 on success, -1 on failure.
 */
extern int s2s_channel_hash(char *hexhash, const struct Channel *chptr);

/** Compare local channel state hash against a remote hash.
 * @param[in] chptr     Channel to verify.
 * @param[in] remote_hash Hex-encoded hash from the remote server.
 * @return 1 if hashes match, 0 if desync detected.
 */
extern int s2s_channel_verify(const struct Channel *chptr,
                              const char *remote_hash);

#endif /* INCLUDED_s2s_crypto_h */
