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

/** Maximum hex-encoded HMAC length.
 *  Pre-1.6.0: HMAC-SHA256 = 32 bytes = 64 hex chars
 *  1.6.0+:    HMAC-SHA3-512 = 64 bytes = 128 hex chars
 *  We use the larger size for both paths so buffers never truncate. */
#define S2S_HMAC_HEXLEN  128
/** S2S HMAC tag prefix in IRCv3 format. */
#define S2S_HMAC_TAG     "@hmac="
/** SA* authorization tag prefix. */
#define S2S_SACERT_TAG   "@sacert="
/** Channel state hash length (SHA3-512 = 128 hex chars post-1.6.0). */
#define S2S_HASH_HEXLEN  128

/** PQ dual-signature tag prefix. Present when both peers are PQ-capable
 *  and posture >= PREFERRED. The value is base64-encoded binary containing
 *  the concatenated ML-DSA-87 + SLH-DSA-SHAKE-256f signatures as produced
 *  by pq_sign_dual(). Because the dual signature is ~8KB, it is only used
 *  on link authentication, oper commands, and SA* commands — not on every
 *  message. Per-message HMAC-SHA3-512 still protects normal traffic. */
#define S2S_PQSIG_TAG    "@pqsig="

/** Derived key material for a server-to-server link.
 * Stored in the server's Client structure after link establishment.
 * Grown in Cathexis 1.6.0 to hold SHA3-512 keys and the peer's PQ
 * public-key fingerprint.
 */
struct S2SKey {
  unsigned char hmac_key[64];        /**< HMAC-SHA3-512 key (64B in 1.6.0+, 32B effective pre-1.6.0) */
  unsigned char sacert_key[64];      /**< HMAC-SHA3-512 key for SA* and link-auth signing */
  unsigned char peer_pqfp[32];       /**< SHA3-256 fingerprint of peer's dual-sig public keys (0 if not PQ) */
  int           active;              /**< 1 if keys are derived and active */
  int           pq_active;           /**< 1 if peer negotiated PQ, 0 if classical-only */
  int           pq_required;         /**< 1 if this link requires PQ (posture REQUIRED or peer demanded) */
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

/* ================================================================
 * Post-Quantum Link Authentication (Cathexis 1.6.0+)
 * ================================================================
 *
 * The PQ layer provides two things on top of the classical HMAC:
 *
 *   1. Dual signature (ML-DSA-87 + SLH-DSA-SHAKE-256f) on link
 *      authentication and privileged (SA*) commands. Both signatures
 *      MUST verify.
 *
 *   2. HMAC-SHA3-512 replaces HMAC-SHA256 for per-message authentication
 *      and channel state hashing.
 *
 * Posture (runtime feature FEAT_PQ_POSTURE):
 *   PQ_POSTURE_DISABLED  — no PQ negotiated or enforced (emergency only)
 *   PQ_POSTURE_PREFERRED — negotiate PQ; fall back to HMAC-SHA3-512-only
 *                          with a warning if peer doesn't support PQ (default)
 *   PQ_POSTURE_REQUIRED  — reject peers that don't negotiate PQ
 *
 * During link registration, each side announces its PQ capability via a
 * PASS-line extension "+pq87shk" (ML-DSA-87 + SLH-DSA-SHAKE-256f). If
 * both announce it, the link is PQ-enabled; both sides sign a challenge
 * with their private PQ keys, and s2s_link_verify_pq() validates the
 * peer's response using the peer's public keys loaded from the Connect
 * block's PQ key-file path.
 */

#ifdef USE_PQ
struct PQKeypair; /* from pq_crypto.h */

/** Sign a server-link challenge with our PQ dual keypair.
 *  @param[out] b64out     Base64-encoded dual signature (NUL-terminated).
 *  @param[in]  b64outlen  Capacity of b64out (recommend 16384 bytes).
 *  @param[in]  kp         Our PQ keypair.
 *  @param[in]  challenge  The peer's challenge nonce.
 *  @param[in]  challen    Length of challenge.
 *  @return 0 on success, -1 on failure. */
extern int s2s_pq_sign_challenge(char *b64out, size_t b64outlen,
                                  const struct PQKeypair *kp,
                                  const unsigned char *challenge,
                                  size_t challen);

/** Verify a peer's PQ-signed challenge response.
 *  @param[in] b64sig    Base64-encoded dual signature from peer.
 *  @param[in] peer_kp   Peer's public keypair (primary_pub/secondary_pub set).
 *  @param[in] challenge The challenge we sent.
 *  @param[in] challen   Length of challenge.
 *  @return 1 if verified, 0 otherwise. */
extern int s2s_pq_verify_challenge(const char *b64sig,
                                    const struct PQKeypair *peer_kp,
                                    const unsigned char *challenge,
                                    size_t challen);

/** Compute a stable 32-byte fingerprint of a peer's PQ public keys.
 *  Used in logging and optional pinning.
 *  @param[out] fp_out   32 bytes of SHA3-256 output.
 *  @param[in]  kp       Keypair with public keys populated.
 *  @return 0 on success, -1 on failure. */
extern int s2s_pq_fingerprint(unsigned char fp_out[32],
                               const struct PQKeypair *kp);
#endif /* USE_PQ */

#endif /* INCLUDED_s2s_crypto_h */
