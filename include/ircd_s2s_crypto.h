/** @file ircd_s2s_crypto.h
 * @brief Server-to-server cryptographic message authentication.
 *
 * Cathexis 1.2.0 protocol extension — breaks P10 backward compatibility.
 *
 * Three subsystems:
 *   1. Per-message HMAC-SHA256 authentication on every S2S message
 *   2. Post-burst state reconciliation via channel state hashes
 *   3. Cryptographic SA* command authorization (services hub signing)
 *
 * Enable with: FEAT_S2S_HMAC = TRUE (default FALSE for migration)
 */
#ifndef INCLUDED_ircd_s2s_crypto_h
#define INCLUDED_ircd_s2s_crypto_h

#include "config.h"

#ifdef USE_SSL

#include "client.h"
#include "channel.h"
#include "res.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* ================================================================
 * SYSTEM 1: Per-Message HMAC-SHA256 Authentication
 *
 * Every S2S message carries an HMAC tag computed over the full
 * message content. The HMAC key is derived from the link password
 * using HKDF-SHA256 at connection time.
 *
 * Wire format change (P10 extension):
 *   Old: AB B #channel :Hello
 *   New: AB B #channel :Hello @hmac=<base64-hmac-tag>
 *
 * The @hmac= tag is appended as the last token. Receiving servers
 * strip and verify the tag before processing.
 *
 * Key derivation:
 *   link_key = HKDF-SHA256(
 *     ikm = link_password,
 *     salt = server_nonce || peer_nonce,
 *     info = "cathexis-s2s-hmac-v1"
 *   )
 *
 * Nonces are exchanged during the SERVER handshake.
 * ================================================================ */

/** Size of HMAC-SHA256 output in bytes. */
#define S2S_HMAC_LEN 32

/** Size of nonce for key derivation. */
#define S2S_NONCE_LEN 32

/** Base64-encoded HMAC tag length (ceil(32/3)*4 + 1). */
#define S2S_HMAC_B64_LEN 45

/** S2S crypto state for a server link. */
struct S2SCryptoState {
  unsigned char link_key[S2S_HMAC_LEN];  /**< HMAC key derived from password + nonces */
  unsigned char local_nonce[S2S_NONCE_LEN];  /**< Our nonce for this link */
  unsigned char peer_nonce[S2S_NONCE_LEN];   /**< Peer's nonce */
  unsigned long msg_seq_tx;   /**< Outbound message sequence number */
  unsigned long msg_seq_rx;   /**< Inbound message sequence number (anti-replay) */
  int           active;       /**< 1 if crypto is negotiated on this link */
};

/** Initialize crypto state for a new server link.
 * Generates a random nonce and stores it in the crypto state.
 * @param state Crypto state to initialize.
 * @return 0 on success, -1 on failure.
 */
extern int s2s_crypto_init(struct S2SCryptoState *state);

/** Derive the link HMAC key from the password and exchanged nonces.
 * Uses HKDF-SHA256 with the concatenated nonces as salt.
 * @param state Crypto state (must have both nonces set).
 * @param password Link password.
 * @return 0 on success, -1 on failure.
 */
extern int s2s_crypto_derive_key(struct S2SCryptoState *state,
                                  const char *password);

/** Compute HMAC-SHA256 over a message buffer.
 * @param state Crypto state with derived key.
 * @param msg Message content (without HMAC tag).
 * @param msglen Length of message.
 * @param out Output buffer for raw HMAC (S2S_HMAC_LEN bytes).
 * @return 0 on success, -1 on failure.
 */
extern int s2s_hmac_compute(const struct S2SCryptoState *state,
                             const char *msg, size_t msglen,
                             unsigned char *out);

/** Sign an outbound S2S message by appending @hmac=<tag>.
 * Modifies the message buffer in-place.
 * @param state Crypto state.
 * @param buf Message buffer (must have space for tag).
 * @param buflen Current message length.
 * @param bufsize Total buffer capacity.
 * @return New message length, or -1 on failure.
 */
extern int s2s_hmac_sign(struct S2SCryptoState *state,
                          char *buf, int buflen, int bufsize);

/** Verify and strip the HMAC tag from an inbound S2S message.
 * @param state Crypto state.
 * @param buf Message buffer (tag is stripped in-place).
 * @param buflen Message length.
 * @return 0 on valid, -1 on invalid/missing tag.
 */
extern int s2s_hmac_verify(struct S2SCryptoState *state,
                            char *buf, int *buflen);

/** Encode raw HMAC to URL-safe base64.
 * @param raw Raw HMAC bytes (S2S_HMAC_LEN).
 * @param out Output buffer (at least S2S_HMAC_B64_LEN).
 */
extern void s2s_hmac_to_b64(const unsigned char *raw, char *out);

/** Decode URL-safe base64 back to raw HMAC.
 * @param b64 Base64 string.
 * @param out Output buffer (S2S_HMAC_LEN).
 * @return 0 on success, -1 on decode error.
 */
extern int s2s_hmac_from_b64(const char *b64, unsigned char *out);


/* ================================================================
 * SYSTEM 2: Post-Burst State Reconciliation
 *
 * After END_OF_BURST, both sides compute SHA-256 hashes of every
 * channel's state (members, modes, bans, topic, TS). These hashes
 * are exchanged in a new STATESYNC message. Mismatches trigger a
 * targeted re-BURST of the divergent channel.
 *
 * Wire format:
 *   STATESYNC <count>
 *   STATEHASH #channel <sha256-hex>
 *   STATEHASH #channel2 <sha256-hex>
 *   STATESYNC END
 *
 * On mismatch:
 *   STATERESYNC #channel
 * which triggers a full BURST for that channel only.
 *
 * This eliminates silent desync from netsplits.
 * ================================================================ */

/** SHA-256 hex digest length (64 chars + NUL). */
#define STATE_HASH_HEX_LEN 65

/** Compute SHA-256 hash of a channel's full state.
 * Hashes: channel name, creation TS, mode string, topic, topic TS,
 * member list (sorted by numnick), ban list, except list.
 * @param chptr Channel to hash.
 * @param out Output buffer (at least STATE_HASH_HEX_LEN).
 */
extern void channel_state_hash(const struct Channel *chptr, char *out);

/** Send STATESYNC + STATEHASH messages for all channels to a server.
 * Called after sending END_OF_BURST_ACK.
 * @param cptr Server link to send to.
 */
extern void send_state_sync(struct Client *cptr);

/** Handle incoming STATEHASH — compare with local channel state.
 * @param cptr Link the message arrived on.
 * @param sptr Source server.
 * @param chname Channel name.
 * @param hash_hex Remote channel state hash.
 * @return 0 on match, 1 on mismatch (STATERESYNC sent).
 */
extern int recv_state_hash(struct Client *cptr, struct Client *sptr,
                            const char *chname, const char *hash_hex);

/** Handle incoming STATERESYNC — re-burst a single channel.
 * @param cptr Link requesting resync.
 * @param chname Channel name to re-burst.
 * @return 0 on success.
 */
extern int send_state_resync(struct Client *cptr, const char *chname);


/* ================================================================
 * SYSTEM 3: Cryptographic SA* Command Authorization
 *
 * SA* commands (SAJOIN, SAPART, SAMODE, SANICK, SATOPIC, SAQUIT,
 * SAWHOIS, SAIDENT, SAINFO, SANOOP) are only valid when originating
 * from a designated services hub.
 *
 * The services hub is identified by:
 *   FEAT_SERVICES_HUB_NUMERIC — the server numeric of the services hub
 *
 * Every SA* command propagated S2S carries an authorization token:
 *   @saauth=<nonce>:<hmac>
 *
 * The HMAC is computed using a shared services key (FEAT_SERVICES_KEY)
 * over: command + parameters + nonce + source numeric.
 *
 * Non-hub servers verify the token before executing or propagating.
 * If FEAT_S2S_HMAC is enabled and no valid @saauth token is present,
 * the SA* command is dropped with a protocol violation notice.
 *
 * This prevents a compromised leaf server from issuing SA* commands
 * by spoofing the services hub's numeric.
 * ================================================================ */

/** Maximum services authorization token length. */
#define SA_AUTH_TOKEN_LEN 128

/** Compute SA* authorization token.
 * @param cmd Command name (e.g., "SAJOIN").
 * @param params Command parameters as a single string.
 * @param source_numeric Numeric of the originating server.
 * @param key Shared services key.
 * @param out Output buffer (at least SA_AUTH_TOKEN_LEN).
 * @return 0 on success, -1 on failure.
 */
extern int sa_auth_sign(const char *cmd, const char *params,
                         const char *source_numeric, const char *key,
                         char *out);

/** Verify an SA* authorization token.
 * @param cmd Command name.
 * @param params Command parameters as a single string.
 * @param source_numeric Numeric of the claimed source server.
 * @param key Shared services key.
 * @param token The @saauth=<nonce>:<hmac> token to verify.
 * @return 0 on valid, -1 on invalid.
 */
extern int sa_auth_verify(const char *cmd, const char *params,
                           const char *source_numeric, const char *key,
                           const char *token);

/** Check if an SA* command is authorized.
 * Enforces the services hub restriction and verifies the auth token.
 * @param cptr Link the command arrived on.
 * @param sptr Source of the command.
 * @param cmd Command name.
 * @param parv Parameter array.
 * @param parc Parameter count.
 * @return 1 if authorized, 0 if rejected (notice sent).
 */
extern int sa_command_authorized(struct Client *cptr, struct Client *sptr,
                                  const char *cmd, char *parv[], int parc);

#endif /* USE_SSL */
#endif /* INCLUDED_ircd_s2s_crypto_h */
