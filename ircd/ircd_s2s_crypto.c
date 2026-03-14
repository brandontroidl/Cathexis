/*
 * IRC - Internet Relay Chat, ircd/ircd_s2s_crypto.c
 * Copyright (C) 2026 Dexterous Network LLC
 *
 * Server-to-server cryptographic authentication for Cathexis IRCd.
 * Breaks P10 backward compatibility when FEAT_S2S_HMAC is enabled.
 *
 * Three subsystems:
 *   1. Per-message HMAC-SHA256 (prevents message injection/forgery)
 *   2. Post-burst state reconciliation (prevents silent desync)
 *   3. SA* command cryptographic authorization (prevents SA* spoofing)
 */
#include "config.h"

#ifdef USE_SSL

#include "ircd_s2s_crypto.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_alloc.h"
#include "ircd_crypto.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "list.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"
#include "s_debug.h"
#include "send.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 * Base64 utilities (URL-safe, no padding)
 * ================================================================ */

static const char b64_table[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void s2s_hmac_to_b64(const unsigned char *raw, char *out)
{
  int i, j = 0;
  for (i = 0; i < S2S_HMAC_LEN; i += 3) {
    unsigned int triplet = (raw[i] << 16);
    if (i + 1 < S2S_HMAC_LEN) triplet |= (raw[i+1] << 8);
    if (i + 2 < S2S_HMAC_LEN) triplet |= raw[i+2];
    out[j++] = b64_table[(triplet >> 18) & 0x3F];
    out[j++] = b64_table[(triplet >> 12) & 0x3F];
    if (i + 1 < S2S_HMAC_LEN)
      out[j++] = b64_table[(triplet >> 6) & 0x3F];
    if (i + 2 < S2S_HMAC_LEN)
      out[j++] = b64_table[triplet & 0x3F];
  }
  out[j] = '\0';
}

static int b64_decode_char(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int s2s_hmac_from_b64(const char *b64, unsigned char *out)
{
  int len = strlen(b64);
  int i, j = 0;
  for (i = 0; i < len && j < S2S_HMAC_LEN; i += 4) {
    int a = b64_decode_char(b64[i]);
    int b = (i+1 < len) ? b64_decode_char(b64[i+1]) : 0;
    int c = (i+2 < len) ? b64_decode_char(b64[i+2]) : 0;
    int d = (i+3 < len) ? b64_decode_char(b64[i+3]) : 0;
    if (a < 0 || b < 0) return -1;
    unsigned int triplet = (a << 18) | (b << 12) | (c << 6) | d;
    if (j < S2S_HMAC_LEN) out[j++] = (triplet >> 16) & 0xFF;
    if (j < S2S_HMAC_LEN && i+2 < len) out[j++] = (triplet >> 8) & 0xFF;
    if (j < S2S_HMAC_LEN && i+3 < len) out[j++] = triplet & 0xFF;
  }
  return (j >= S2S_HMAC_LEN) ? 0 : -1;
}


/* ================================================================
 * SYSTEM 1: Per-Message HMAC-SHA256
 * ================================================================ */

int s2s_crypto_init(struct S2SCryptoState *state)
{
  memset(state, 0, sizeof(*state));
  if (RAND_bytes(state->local_nonce, S2S_NONCE_LEN) != 1) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "s2s_crypto_init: RAND_bytes failed for nonce");
    return -1;
  }
  state->msg_seq_tx = 0;
  state->msg_seq_rx = 0;
  state->active = 0;
  return 0;
}

int s2s_crypto_derive_key(struct S2SCryptoState *state, const char *password)
{
  /* HKDF-SHA256: extract + expand
   * Salt = local_nonce || peer_nonce (order by lexicographic sort for
   *        deterministic derivation regardless of which side initiated)
   * IKM = link password
   * Info = "cathexis-s2s-hmac-v1"
   */
  EVP_PKEY_CTX *pctx;
  unsigned char salt[S2S_NONCE_LEN * 2];
  const char *info = "cathexis-s2s-hmac-v1";
  size_t keylen = S2S_HMAC_LEN;

  /* Deterministic salt ordering: lower nonce first */
  if (memcmp(state->local_nonce, state->peer_nonce, S2S_NONCE_LEN) <= 0) {
    memcpy(salt, state->local_nonce, S2S_NONCE_LEN);
    memcpy(salt + S2S_NONCE_LEN, state->peer_nonce, S2S_NONCE_LEN);
  } else {
    memcpy(salt, state->peer_nonce, S2S_NONCE_LEN);
    memcpy(salt + S2S_NONCE_LEN, state->local_nonce, S2S_NONCE_LEN);
  }

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (!pctx)
    return -1;

  if (EVP_PKEY_derive_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt)) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx, (const unsigned char *)password,
                                  strlen(password)) <= 0 ||
      EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info,
                                   strlen(info)) <= 0 ||
      EVP_PKEY_derive(pctx, state->link_key, &keylen) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    log_write(LS_SYSTEM, L_ERROR, 0,
              "s2s_crypto_derive_key: HKDF derivation failed");
    return -1;
  }

  EVP_PKEY_CTX_free(pctx);
  /* Clear the salt from stack */
  ircd_clearsecret(salt, sizeof(salt));
  state->active = 1;

  Debug((DEBUG_DEBUG, "s2s_crypto: link key derived successfully"));
  return 0;
}

int s2s_hmac_compute(const struct S2SCryptoState *state,
                      const char *msg, size_t msglen,
                      unsigned char *out)
{
  unsigned int outlen = S2S_HMAC_LEN;
  if (!HMAC(EVP_sha256(), state->link_key, S2S_HMAC_LEN,
            (const unsigned char *)msg, msglen, out, &outlen))
  {
    return -1;
  }
  return 0;
}

int s2s_hmac_sign(struct S2SCryptoState *state,
                   char *buf, int buflen, int bufsize)
{
  unsigned char hmac_raw[S2S_HMAC_LEN];
  char hmac_b64[S2S_HMAC_B64_LEN];
  char seq_buf[32];
  int tag_len;

  if (!state->active)
    return buflen; /* passthrough if not active */

  /* Include sequence number in HMAC to prevent replay.
   * Prepend seq to message for HMAC computation, but don't include
   * it in the wire format (both sides track independently). */
  state->msg_seq_tx++;
  ircd_snprintf(0, seq_buf, sizeof(seq_buf), "%lu:", state->msg_seq_tx);

  /* Compute HMAC over seq_buf + message content */
  {
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    unsigned int hmac_outlen = S2S_HMAC_LEN;

    /* Simple approach: HMAC(key, seq || msg) */
    HMAC_CTX *hctx = HMAC_CTX_new();
    if (!hctx) return -1;

    if (!HMAC_Init_ex(hctx, state->link_key, S2S_HMAC_LEN, EVP_sha256(), NULL) ||
        !HMAC_Update(hctx, (unsigned char *)seq_buf, strlen(seq_buf)) ||
        !HMAC_Update(hctx, (unsigned char *)buf, buflen) ||
        !HMAC_Final(hctx, hmac_raw, &hmac_outlen))
    {
      HMAC_CTX_free(hctx);
      return -1;
    }
    HMAC_CTX_free(hctx);
  }

  s2s_hmac_to_b64(hmac_raw, hmac_b64);

  /* Append @hmac=<b64> before the trailing \r\n */
  tag_len = strlen(hmac_b64) + 7; /* " @hmac=" + b64 */
  if (buflen + tag_len >= bufsize)
    return -1; /* no room */

  /* Strip trailing \r\n if present */
  if (buflen >= 2 && buf[buflen-2] == '\r' && buf[buflen-1] == '\n') {
    buflen -= 2;
    ircd_snprintf(0, buf + buflen, bufsize - buflen,
                  " @hmac=%s\r\n", hmac_b64);
    return buflen + tag_len + 2;
  } else {
    ircd_snprintf(0, buf + buflen, bufsize - buflen,
                  " @hmac=%s", hmac_b64);
    return buflen + tag_len;
  }
}

int s2s_hmac_verify(struct S2SCryptoState *state,
                     char *buf, int *buflen)
{
  char *tag;
  unsigned char claimed[S2S_HMAC_LEN];
  unsigned char computed[S2S_HMAC_LEN];
  char seq_buf[32];
  int msglen;
  unsigned int hmac_outlen = S2S_HMAC_LEN;
  HMAC_CTX *hctx;

  if (!state->active)
    return 0; /* passthrough */

  /* Find @hmac= tag */
  tag = strstr(buf, " @hmac=");
  if (!tag) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "s2s_hmac_verify: missing HMAC tag on S2S message");
    return -1;
  }

  /* Decode the claimed HMAC */
  if (s2s_hmac_from_b64(tag + 7, claimed) < 0)
    return -1;

  /* Message content is everything before the tag */
  msglen = tag - buf;

  /* Compute expected HMAC with next expected sequence number */
  state->msg_seq_rx++;
  ircd_snprintf(0, seq_buf, sizeof(seq_buf), "%lu:", state->msg_seq_rx);

  hctx = HMAC_CTX_new();
  if (!hctx) return -1;

  if (!HMAC_Init_ex(hctx, state->link_key, S2S_HMAC_LEN, EVP_sha256(), NULL) ||
      !HMAC_Update(hctx, (unsigned char *)seq_buf, strlen(seq_buf)) ||
      !HMAC_Update(hctx, (unsigned char *)buf, msglen) ||
      !HMAC_Final(hctx, computed, &hmac_outlen))
  {
    HMAC_CTX_free(hctx);
    state->msg_seq_rx--; /* rollback on failure */
    return -1;
  }
  HMAC_CTX_free(hctx);

  /* Constant-time comparison */
  if (CRYPTO_memcmp(claimed, computed, S2S_HMAC_LEN) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "s2s_hmac_verify: HMAC mismatch — message rejected");
    state->msg_seq_rx--; /* rollback — message not consumed */
    ircd_clearsecret(computed, S2S_HMAC_LEN);
    return -1;
  }

  ircd_clearsecret(computed, S2S_HMAC_LEN);

  /* Strip the HMAC tag from the buffer */
  *tag = '\0';
  *buflen = msglen;

  return 0;
}


/* ================================================================
 * SYSTEM 2: Post-Burst State Reconciliation
 * ================================================================ */

void channel_state_hash(const struct Channel *chptr, char *out)
{
  SHA256_CTX ctx;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  char buf[512];
  struct Membership *member;
  struct Ban *ban;
  int i;

  SHA256_Init(&ctx);

  /* Channel name */
  SHA256_Update(&ctx, chptr->chname, strlen(chptr->chname));

  /* Creation timestamp */
  ircd_snprintf(0, buf, sizeof(buf), ":%lu", (unsigned long)chptr->creationtime);
  SHA256_Update(&ctx, buf, strlen(buf));

  /* Mode string */
  ircd_snprintf(0, buf, sizeof(buf), ":+%s:%d:%s:%s",
                "", /* mode flags would go here — simplified */
                chptr->mode.limit,
                chptr->mode.key,
                chptr->mode.upass);
  SHA256_Update(&ctx, buf, strlen(buf));

  /* Topic + topic TS */
  if (chptr->topic[0]) {
    SHA256_Update(&ctx, ":T:", 3);
    SHA256_Update(&ctx, chptr->topic, strlen(chptr->topic));
    ircd_snprintf(0, buf, sizeof(buf), ":%lu",
                  (unsigned long)chptr->topic_time);
    SHA256_Update(&ctx, buf, strlen(buf));
  }

  /* Members sorted by numnick (the numnick itself is deterministic) */
  for (member = chptr->members; member; member = member->next_member) {
    const char *nn = cli_name(member->user);
    SHA256_Update(&ctx, ":M:", 3);
    SHA256_Update(&ctx, nn, strlen(nn));
    ircd_snprintf(0, buf, sizeof(buf), ":%u", member->status);
    SHA256_Update(&ctx, buf, strlen(buf));
  }

  /* Bans */
  for (ban = chptr->banlist; ban; ban = ban->next) {
    SHA256_Update(&ctx, ":B:", 3);
    SHA256_Update(&ctx, ban->banstr, strlen(ban->banstr));
  }

  SHA256_Final(digest, &ctx);

  /* Convert to hex */
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    ircd_snprintf(0, out + i*2, 3, "%02x", digest[i]);
  out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

void send_state_sync(struct Client *cptr)
{
  struct Channel *chptr;
  char hash[STATE_HASH_HEX_LEN];
  int count = 0;

  if (!feature_bool(FEAT_S2S_HMAC))
    return;

  /* Count channels */
  for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
    count++;

  sendcmdto_one(&me, CMD_PRIVATE, cptr, "%C :STATESYNC %d", cptr, count);

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    channel_state_hash(chptr, hash);
    sendcmdto_one(&me, CMD_PRIVATE, cptr,
                  "%C :STATEHASH %s %s", cptr, chptr->chname, hash);
  }

  sendcmdto_one(&me, CMD_PRIVATE, cptr, "%C :STATESYNC END", cptr);
}

int recv_state_hash(struct Client *cptr, struct Client *sptr,
                     const char *chname, const char *hash_hex)
{
  struct Channel *chptr;
  char local_hash[STATE_HASH_HEX_LEN];

  chptr = FindChannel(chname);
  if (!chptr) {
    /* Remote has a channel we don't — request resync */
    sendcmdto_one(&me, CMD_PRIVATE, cptr,
                  "%C :STATERESYNC %s", cptr, chname);
    return 1;
  }

  channel_state_hash(chptr, local_hash);

  if (strcmp(local_hash, hash_hex) != 0) {
    sendto_opmask_butone(0, SNO_NETWORK,
      "State desync detected for %s with %C — requesting resync",
      chname, sptr);
    sendcmdto_one(&me, CMD_PRIVATE, cptr,
                  "%C :STATERESYNC %s", cptr, chname);
    return 1;
  }

  return 0; /* match */
}

int send_state_resync(struct Client *cptr, const char *chname)
{
  struct Channel *chptr;

  chptr = FindChannel(chname);
  if (!chptr)
    return 0; /* nothing to resync */

  sendto_opmask_butone(0, SNO_NETWORK,
    "Resync requested for %s by %C — sending targeted burst",
    chname, cptr);

  /* The actual re-burst would call the existing burst_channel()
   * function here. For now, log the event. A full implementation
   * would extract burst_channel() from m_burst.c into a callable
   * function and invoke it for this single channel. */

  /* TODO: burst_channel(cptr, chptr); */

  return 0;
}


/* ================================================================
 * SYSTEM 3: SA* Command Cryptographic Authorization
 * ================================================================ */

int sa_auth_sign(const char *cmd, const char *params,
                  const char *source_numeric, const char *key,
                  char *out)
{
  unsigned char nonce[16];
  char nonce_hex[33];
  char msg[512];
  unsigned char hmac[S2S_HMAC_LEN];
  char hmac_b64[S2S_HMAC_B64_LEN];
  unsigned int hmac_len = S2S_HMAC_LEN;
  int i;

  /* Generate a random nonce for this command */
  if (RAND_bytes(nonce, 16) != 1)
    return -1;

  for (i = 0; i < 16; i++)
    ircd_snprintf(0, nonce_hex + i*2, 3, "%02x", nonce[i]);
  nonce_hex[32] = '\0';

  /* HMAC over: nonce + ":" + source_numeric + ":" + cmd + ":" + params */
  ircd_snprintf(0, msg, sizeof(msg), "%s:%s:%s:%s",
                nonce_hex, source_numeric, cmd, params);

  if (!HMAC(EVP_sha256(), key, strlen(key),
            (unsigned char *)msg, strlen(msg), hmac, &hmac_len))
    return -1;

  s2s_hmac_to_b64(hmac, hmac_b64);

  /* Token format: nonce:hmac_b64 */
  ircd_snprintf(0, out, SA_AUTH_TOKEN_LEN, "%s:%s", nonce_hex, hmac_b64);

  ircd_clearsecret(hmac, sizeof(hmac));
  ircd_clearsecret(msg, strlen(msg));

  return 0;
}

int sa_auth_verify(const char *cmd, const char *params,
                    const char *source_numeric, const char *key,
                    const char *token)
{
  char nonce_hex[33];
  char claimed_b64[S2S_HMAC_B64_LEN];
  unsigned char claimed[S2S_HMAC_LEN];
  unsigned char computed[S2S_HMAC_LEN];
  char msg[512];
  unsigned int hmac_len = S2S_HMAC_LEN;
  const char *colon;

  /* Parse token: nonce_hex:hmac_b64 */
  colon = strchr(token, ':');
  if (!colon || (colon - token) != 32)
    return -1;

  memcpy(nonce_hex, token, 32);
  nonce_hex[32] = '\0';
  ircd_strncpy(claimed_b64, colon + 1, S2S_HMAC_B64_LEN - 1);

  if (s2s_hmac_from_b64(claimed_b64, claimed) < 0)
    return -1;

  /* Recompute HMAC */
  ircd_snprintf(0, msg, sizeof(msg), "%s:%s:%s:%s",
                nonce_hex, source_numeric, cmd, params);

  if (!HMAC(EVP_sha256(), key, strlen(key),
            (unsigned char *)msg, strlen(msg), computed, &hmac_len))
  {
    ircd_clearsecret(msg, strlen(msg));
    return -1;
  }

  ircd_clearsecret(msg, strlen(msg));

  /* Constant-time comparison */
  if (CRYPTO_memcmp(claimed, computed, S2S_HMAC_LEN) != 0) {
    ircd_clearsecret(computed, S2S_HMAC_LEN);
    return -1;
  }

  ircd_clearsecret(computed, S2S_HMAC_LEN);
  return 0;
}

int sa_command_authorized(struct Client *cptr, struct Client *sptr,
                           const char *cmd, char *parv[], int parc)
{
  const char *services_hub;
  const char *services_key;
  const char *token = NULL;
  char params[512];
  int i, len = 0;

  if (!feature_bool(FEAT_S2S_HMAC))
    return 1; /* not enforcing — legacy mode */

  services_hub = feature_str(FEAT_SERVICES_HUB_NUMERIC);
  services_key = feature_str(FEAT_SERVICES_KEY);

  if (EmptyString(services_hub) || EmptyString(services_key)) {
    /* No services hub configured — reject all S2S SA* */
    sendto_opmask_butone(0, SNO_OLDSNO,
      "REJECTED: %s from %C — no SERVICES_HUB_NUMERIC configured",
      cmd, sptr);
    return 0;
  }

  /* Check if source server matches the designated services hub */
  if (IsServer(sptr)) {
    if (ircd_strcmp(cli_yxx(sptr), services_hub) != 0) {
      sendto_opmask_butone(0, SNO_OLDSNO,
        "REJECTED: %s from non-hub server %C (numeric %s, hub is %s)",
        cmd, sptr, cli_yxx(sptr), services_hub);
      return 0;
    }
  }

  /* Find the @saauth= token in the last parameter */
  if (parc > 1) {
    char *last = parv[parc - 1];
    char *auth_tag = strstr(last, "@saauth=");
    if (auth_tag) {
      token = auth_tag + 8;
      *auth_tag = '\0'; /* strip from params before verification */
      /* Trim trailing space */
      if (auth_tag > last && *(auth_tag-1) == ' ')
        *(auth_tag-1) = '\0';
    }
  }

  if (!token) {
    sendto_opmask_butone(0, SNO_OLDSNO,
      "REJECTED: %s from %C — missing @saauth token",
      cmd, sptr);
    return 0;
  }

  /* Reconstruct params string for verification */
  params[0] = '\0';
  for (i = 1; i < parc; i++) {
    if (i > 1 && len < (int)sizeof(params) - 1)
      params[len++] = ' ';
    len += ircd_snprintf(0, params + len, sizeof(params) - len,
                         "%s", parv[i]);
  }

  /* Verify the token */
  if (sa_auth_verify(cmd, params, cli_yxx(sptr), services_key, token) < 0) {
    sendto_opmask_butone(0, SNO_OLDSNO,
      "REJECTED: %s from %C — invalid @saauth signature",
      cmd, sptr);
    return 0;
  }

  Debug((DEBUG_DEBUG, "sa_command_authorized: %s from %C verified", cmd, sptr));
  return 1;
}

#endif /* USE_SSL */
