/** @file pq_crypto.h
 * @brief Post-quantum cryptographic primitives for Cathexis.
 * Copyright (C) 2026 Cathexis Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Provides dual-signature authentication for server-to-server links using
 * two NIST-standardized post-quantum signature schemes from disjoint
 * cryptographic assumption families:
 *
 *   - ML-DSA-87 (FIPS 204 / Dilithium-5, Category 5): lattice-based
 *   - SLH-DSA-SHAKE-256f (FIPS 205 / SPHINCS+, Category 5): hash-based
 *
 * Both signatures MUST verify for an s2s message to be accepted when
 * PQ_REQUIRED mode is active. PQ_PREFERRED mode accepts classical-only
 * peers but logs a warning and downgrades the channel.
 *
 * Rationale for dual-signature: if a future cryptanalytic break is
 * discovered in either lattice or hash-based schemes (e.g., a Shor-like
 * quantum algorithm against structured lattices, or a generic collision
 * attack on SHAKE-256), the other family still protects the channel.
 * This matches NSA CNSA 2.0 and BSI TR-02102 defense-in-depth guidance.
 *
 * Quantum-safe symmetric primitives:
 *   - HMAC-SHA3-512 for message authentication (256-bit PQ security via
 *     Grover, 512-bit classical security)
 *   - AES-256-GCM for channel confidentiality (128-bit PQ via Grover)
 *   - HKDF-SHA3-512 for key derivation
 *
 * At-rest encryption uses AES-256-GCM with keys derived from Argon2id
 * (memory-hard, resistant to both classical and quantum brute force).
 */
#ifndef INCLUDED_pq_crypto_h
#define INCLUDED_pq_crypto_h

#include "config.h"
#include "ircd_crypto.h"

#ifdef USE_PQ

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

/* Algorithm identifiers (wire-format, little-endian ints) */
#define PQ_ALG_NONE          0x0000
#define PQ_ALG_ML_DSA_65     0x0001  /**< FIPS 204 Category 3 */
#define PQ_ALG_ML_DSA_87     0x0002  /**< FIPS 204 Category 5 (default) */
#define PQ_ALG_SLH_DSA_256F  0x0003  /**< FIPS 205 SHAKE-256f Category 5 (default) */
#define PQ_ALG_FALCON_1024   0x0004  /**< Round 3 Category 5 (optional) */

/* PQ posture — FEAT_PQ_POSTURE in ircd_features.c */
#define PQ_POSTURE_DISABLED   0  /**< No PQ (NOT recommended, interop only) */
#define PQ_POSTURE_PREFERRED  1  /**< Use PQ if peer supports, else classical (default) */
#define PQ_POSTURE_REQUIRED   2  /**< Reject non-PQ peers (strongest) */

/** PQ keypair — holds both primary and secondary signature keys.
 *  Primary: ML-DSA-87 (lattice-based)
 *  Secondary: SLH-DSA-SHAKE-256f (hash-based)
 *  Both must be generated and signed-with; both must verify on the peer. */
struct PQKeypair {
  int           active;               /**< 1 if keys are loaded */
  uint16_t      primary_alg;          /**< Primary algorithm (PQ_ALG_ML_DSA_87) */
  uint16_t      secondary_alg;        /**< Secondary algorithm (PQ_ALG_SLH_DSA_256F) */
  OQS_SIG      *primary_sig;          /**< OQS primary signature context */
  OQS_SIG      *secondary_sig;        /**< OQS secondary signature context */
  uint8_t      *primary_priv;         /**< Primary private key bytes */
  uint8_t      *primary_pub;          /**< Primary public key bytes */
  uint8_t      *secondary_priv;       /**< Secondary private key bytes */
  uint8_t      *secondary_pub;        /**< Secondary public key bytes */
  size_t        primary_priv_len;
  size_t        primary_pub_len;
  size_t        secondary_priv_len;
  size_t        secondary_pub_len;
};

/** Initialize the PQ subsystem.
 *  Calls OQS_init() (liboqs global init) and validates that the configured
 *  algorithms are available in the liboqs build.
 *  @return 0 on success, -1 on failure (liboqs missing required algorithms). */
extern int pq_init(void);

/** Clean up the PQ subsystem. Call at daemon shutdown. */
extern void pq_cleanup(void);

/** Generate a fresh dual-signature keypair.
 *  Uses the system CSPRNG (via OQS — which itself uses getrandom(2)/
 *  RAND_bytes).
 *  @param[out] kp Keypair to populate. Caller must call pq_keypair_free().
 *  @return 0 on success, -1 on failure. */
extern int pq_keypair_generate(struct PQKeypair *kp);

/** Load a keypair from a PEM-like on-disk format.
 *  File format is a simple concatenation of base64-encoded key blobs with
 *  labeled headers. See doc/pq-keys.txt for spec.
 *  @param[out] kp Keypair to populate.
 *  @param[in]  path Filesystem path to key file.
 *  @return 0 on success, -1 on failure. */
extern int pq_keypair_load(struct PQKeypair *kp, const char *path);

/** Save a keypair to disk in the format read by pq_keypair_load().
 *  File is created with mode 0600 (owner read/write only).
 *  @param[in] kp Keypair to serialize.
 *  @param[in] path Filesystem path.
 *  @return 0 on success, -1 on failure. */
extern int pq_keypair_save(const struct PQKeypair *kp, const char *path);

/** Free all dynamically-allocated memory in a keypair and securely clear
 *  private-key bytes. Safe to call on a zero-initialized struct. */
extern void pq_keypair_free(struct PQKeypair *kp);

/** Produce a dual signature over a message.
 *  The wire format of the output is:
 *    [2 bytes: primary_alg LE]
 *    [4 bytes: primary_sig_len LE]
 *    [primary_sig_len bytes: primary signature]
 *    [2 bytes: secondary_alg LE]
 *    [4 bytes: secondary_sig_len LE]
 *    [secondary_sig_len bytes: secondary signature]
 *
 *  Total on-wire size is ~8 KB for ML-DSA-87 + SLH-DSA-256f. This is why
 *  PQ sigs are used only on link authentication and oper commands, not
 *  per-message.
 *
 *  @param[out] out     Output buffer for the combined dual signature.
 *  @param[in,out] outlen Input: capacity of out. Output: actual bytes written.
 *  @param[in]  kp      Signing keypair (must have private keys).
 *  @param[in]  msg     Message to sign.
 *  @param[in]  msglen  Length of message.
 *  @return 0 on success, -1 on failure (usually buffer too small). */
extern int pq_sign_dual(uint8_t *out, size_t *outlen,
                         const struct PQKeypair *kp,
                         const uint8_t *msg, size_t msglen);

/** Verify a dual signature. Both primary and secondary must verify.
 *  @param[in] sig      Dual signature in the format produced by pq_sign_dual().
 *  @param[in] siglen   Length of sig buffer.
 *  @param[in] kp       Peer's public keypair (primary_pub / secondary_pub set).
 *  @param[in] msg      Message the signature covers.
 *  @param[in] msglen   Length of message.
 *  @return 1 if both signatures verify, 0 if either fails, -1 on malformed input. */
extern int pq_verify_dual(const uint8_t *sig, size_t siglen,
                           const struct PQKeypair *kp,
                           const uint8_t *msg, size_t msglen);

/** Compute HMAC-SHA3-512 over data.
 *  Used for s2s link message authentication when USE_PQ is defined.
 *  Produces a 64-byte MAC.
 *  @param[in]  key     HMAC key.
 *  @param[in]  keylen  Key length in bytes.
 *  @param[in]  data    Input data.
 *  @param[in]  datalen Data length.
 *  @param[out] mac     Output buffer (must be at least 64 bytes).
 *  @return 0 on success, -1 on failure. */
extern int pq_hmac_sha3_512(const void *key, size_t keylen,
                             const void *data, size_t datalen,
                             unsigned char *mac);

/** HKDF-SHA3-512 key derivation.
 *  @param[in]  ikm      Input keying material.
 *  @param[in]  ikm_len  Length of ikm.
 *  @param[in]  salt     Optional salt (may be NULL).
 *  @param[in]  salt_len Length of salt.
 *  @param[in]  info     Application-specific info string.
 *  @param[in]  info_len Length of info.
 *  @param[out] okm      Output keying material buffer.
 *  @param[in]  okm_len  Desired OKM length (at most 255 * 64 bytes).
 *  @return 0 on success, -1 on failure. */
extern int pq_hkdf_sha3_512(const uint8_t *ikm, size_t ikm_len,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *info, size_t info_len,
                             uint8_t *okm, size_t okm_len);

/** Derive the s2s MAC key from a link password using HKDF-SHA3-512.
 *  Replaces the SHA-256 HKDF used prior to Cathexis 1.6.0.
 *  The derivation label is "cathexis-s2s-hmac-sha3-v2" — different from
 *  the pre-1.6.0 label to prevent cross-version key reuse.
 *  @param[out] key     64-byte output buffer.
 *  @param[in]  passwd  Link password (NUL-terminated).
 *  @return 0 on success, -1 on failure. */
extern int pq_derive_s2s_mac_key(uint8_t key[64], const char *passwd);

#endif /* USE_PQ */

#endif /* INCLUDED_pq_crypto_h */
