/** @file pq_crypto.c
 * @brief Post-quantum cryptographic primitives for Cathexis.
 * Copyright (C) 2026 Cathexis Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Implements dual-signature authentication (ML-DSA-87 + SLH-DSA-SHAKE-256f)
 * via liboqs, plus HMAC-SHA3-512 and HKDF-SHA3-512 via OpenSSL 3.5+.
 *
 * All secret material is zeroed via OPENSSL_cleanse() before freeing.
 * All signature verifications are constant-time via OQS_SIG_verify which
 * wraps the reference implementations with timing-safe comparisons.
 */

#include "config.h"

#ifdef USE_PQ

#include "pq_crypto.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_debug.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ----------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------- */

/* Resolve our numeric algorithm tag to an OQS algorithm name string. */
static const char *pq_alg_name(uint16_t alg)
{
  switch (alg) {
    case PQ_ALG_ML_DSA_65:    return OQS_SIG_alg_ml_dsa_65;
    case PQ_ALG_ML_DSA_87:    return OQS_SIG_alg_ml_dsa_87;
    case PQ_ALG_SLH_DSA_256F: return OQS_SIG_alg_sphincs_shake_256f_simple;
    case PQ_ALG_FALCON_1024:  return OQS_SIG_alg_falcon_1024;
    default:                  return NULL;
  }
}

/* Little-endian integer helpers for wire format. */
static void put_u16_le(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
}

static uint16_t get_u16_le(const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void put_u32_le(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t get_u32_le(const uint8_t *p)
{
  return  (uint32_t)p[0] |
         ((uint32_t)p[1] <<  8) |
         ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/* ----------------------------------------------------------------------
 * Subsystem lifecycle
 * -------------------------------------------------------------------- */

int pq_init(void)
{
  /* OQS_init() performs global initialization (CPU feature detection,
   * PRNG seeding). Safe to call multiple times. */
  OQS_init();

  /* Validate that required algorithms are present in this liboqs build.
   * Some minimal builds omit SPHINCS+ or lower-level variants. */
  if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_87)) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "PQ: liboqs missing ML-DSA-87 (required). "
              "Rebuild liboqs with -DOQS_ENABLE_SIG_ML_DSA_87=ON.");
    return -1;
  }
  if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_sphincs_shake_256f_simple)) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "PQ: liboqs missing SLH-DSA-SHAKE-256f-simple (required). "
              "Rebuild liboqs with -DOQS_ENABLE_SIG_SPHINCS=ON.");
    return -1;
  }

  log_write(LS_SYSTEM, L_INFO, 0,
            "PQ: initialized with ML-DSA-87 (primary) + "
            "SLH-DSA-SHAKE-256f (secondary)");
  return 0;
}

void pq_cleanup(void)
{
  OQS_destroy();
}

/* ----------------------------------------------------------------------
 * Keypair management
 * -------------------------------------------------------------------- */

int pq_keypair_generate(struct PQKeypair *kp)
{
  const char *primary_name;
  const char *secondary_name;
  OQS_STATUS rc;

  if (!kp) return -1;
  memset(kp, 0, sizeof(*kp));

  kp->primary_alg   = PQ_ALG_ML_DSA_87;
  kp->secondary_alg = PQ_ALG_SLH_DSA_256F;

  primary_name   = pq_alg_name(kp->primary_alg);
  secondary_name = pq_alg_name(kp->secondary_alg);

  kp->primary_sig   = OQS_SIG_new(primary_name);
  kp->secondary_sig = OQS_SIG_new(secondary_name);
  if (!kp->primary_sig || !kp->secondary_sig) {
    pq_keypair_free(kp);
    return -1;
  }

  kp->primary_priv_len = kp->primary_sig->length_secret_key;
  kp->primary_pub_len  = kp->primary_sig->length_public_key;
  kp->secondary_priv_len = kp->secondary_sig->length_secret_key;
  kp->secondary_pub_len  = kp->secondary_sig->length_public_key;

  kp->primary_priv   = OPENSSL_malloc(kp->primary_priv_len);
  kp->primary_pub    = OPENSSL_malloc(kp->primary_pub_len);
  kp->secondary_priv = OPENSSL_malloc(kp->secondary_priv_len);
  kp->secondary_pub  = OPENSSL_malloc(kp->secondary_pub_len);

  if (!kp->primary_priv || !kp->primary_pub ||
      !kp->secondary_priv || !kp->secondary_pub) {
    pq_keypair_free(kp);
    return -1;
  }

  rc = OQS_SIG_keypair(kp->primary_sig, kp->primary_pub, kp->primary_priv);
  if (rc != OQS_SUCCESS) {
    pq_keypair_free(kp);
    return -1;
  }
  rc = OQS_SIG_keypair(kp->secondary_sig, kp->secondary_pub, kp->secondary_priv);
  if (rc != OQS_SUCCESS) {
    pq_keypair_free(kp);
    return -1;
  }

  kp->active = 1;
  return 0;
}

void pq_keypair_free(struct PQKeypair *kp)
{
  if (!kp) return;
  if (kp->primary_priv) {
    OPENSSL_cleanse(kp->primary_priv, kp->primary_priv_len);
    OPENSSL_free(kp->primary_priv);
  }
  if (kp->primary_pub)    OPENSSL_free(kp->primary_pub);
  if (kp->secondary_priv) {
    OPENSSL_cleanse(kp->secondary_priv, kp->secondary_priv_len);
    OPENSSL_free(kp->secondary_priv);
  }
  if (kp->secondary_pub)  OPENSSL_free(kp->secondary_pub);
  if (kp->primary_sig)    OQS_SIG_free(kp->primary_sig);
  if (kp->secondary_sig)  OQS_SIG_free(kp->secondary_sig);
  memset(kp, 0, sizeof(*kp));
}

/* ----------------------------------------------------------------------
 * On-disk serialization
 *
 * File format (text, line-oriented):
 *   CATHEXIS-PQ-KEY v1
 *   PRIMARY-ALG <id>
 *   PRIMARY-PUB <base64>
 *   PRIMARY-PRIV <base64>
 *   SECONDARY-ALG <id>
 *   SECONDARY-PUB <base64>
 *   SECONDARY-PRIV <base64>
 *   END
 *
 * File mode is 0600. Loader refuses files readable by group or others.
 * -------------------------------------------------------------------- */

static int b64_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
  int n = EVP_EncodeBlock((unsigned char *)out, in, (int)inlen);
  if (n < 0 || (size_t)n + 1 > outlen) return -1;
  out[n] = '\0';
  return n;
}

static int b64_decode(const char *in, uint8_t *out, size_t outlen,
                      size_t *written)
{
  int n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)strlen(in));
  if (n < 0) return -1;
  /* EVP_DecodeBlock pads — strip trailing '=' bytes by input length */
  size_t inlen = strlen(in);
  while (inlen > 0 && in[inlen - 1] == '=') {
    n--;
    inlen--;
  }
  if ((size_t)n > outlen) return -1;
  if (written) *written = (size_t)n;
  return 0;
}

int pq_keypair_save(const struct PQKeypair *kp, const char *path)
{
  FILE *fp;
  char *enc = NULL;
  size_t enc_cap;
  int fd;
  int rc = -1;

  if (!kp || !kp->active || !path) return -1;

  /* Base64 expands by 4/3; allocate a single reusable buffer big enough
   * for the largest key (SLH-DSA private ~128 bytes, ML-DSA private
   * ~4900 bytes). Round up. */
  enc_cap = 4 * (kp->primary_priv_len > kp->secondary_priv_len ?
                 kp->primary_priv_len : kp->secondary_priv_len) / 3 + 16;
  enc = OPENSSL_malloc(enc_cap);
  if (!enc) return -1;

  /* O_EXCL so we don't silently overwrite an existing keyfile */
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) goto out;
  fp = fdopen(fd, "w");
  if (!fp) { close(fd); goto out; }

  fprintf(fp, "CATHEXIS-PQ-KEY v1\n");

  fprintf(fp, "PRIMARY-ALG %u\n", (unsigned)kp->primary_alg);
  if (b64_encode(kp->primary_pub, kp->primary_pub_len, enc, enc_cap) < 0) goto fail;
  fprintf(fp, "PRIMARY-PUB %s\n", enc);
  if (b64_encode(kp->primary_priv, kp->primary_priv_len, enc, enc_cap) < 0) goto fail;
  fprintf(fp, "PRIMARY-PRIV %s\n", enc);

  fprintf(fp, "SECONDARY-ALG %u\n", (unsigned)kp->secondary_alg);
  if (b64_encode(kp->secondary_pub, kp->secondary_pub_len, enc, enc_cap) < 0) goto fail;
  fprintf(fp, "SECONDARY-PUB %s\n", enc);
  if (b64_encode(kp->secondary_priv, kp->secondary_priv_len, enc, enc_cap) < 0) goto fail;
  fprintf(fp, "SECONDARY-PRIV %s\n", enc);

  fprintf(fp, "END\n");

  if (fflush(fp) == 0 && fsync(fileno(fp)) == 0)
    rc = 0;

fail:
  fclose(fp);
  if (rc != 0) unlink(path);
out:
  if (enc) {
    OPENSSL_cleanse(enc, enc_cap);
    OPENSSL_free(enc);
  }
  return rc;
}

/* Helper: parse one "KEY VALUE" line from a file into (key, value). */
static int parse_kv(char *line, char **key, char **value)
{
  char *sp = strchr(line, ' ');
  if (!sp) return -1;
  *sp = '\0';
  *key = line;
  *value = sp + 1;
  /* Trim trailing newline */
  char *nl = strchr(*value, '\n');
  if (nl) *nl = '\0';
  return 0;
}

int pq_keypair_load(struct PQKeypair *kp, const char *path)
{
  FILE *fp = NULL;
  char line[16384];
  int rc = -1;
  const char *primary_name, *secondary_name;
  struct stat st;

  if (!kp || !path) return -1;
  memset(kp, 0, sizeof(*kp));

  /* Refuse world/group-readable keyfiles */
  if (stat(path, &st) < 0) return -1;
  if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "PQ: refusing to load keyfile %s: mode %o too permissive "
              "(should be 0600)", path, (unsigned)(st.st_mode & 0777));
    return -1;
  }

  fp = fopen(path, "r");
  if (!fp) return -1;

  if (!fgets(line, sizeof(line), fp) ||
      strncmp(line, "CATHEXIS-PQ-KEY v1", 18) != 0) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "PQ: keyfile %s: bad magic (expected CATHEXIS-PQ-KEY v1)", path);
    goto out;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *k, *v;
    if (parse_kv(line, &k, &v) < 0) continue;

    if (!strcmp(k, "PRIMARY-ALG")) {
      kp->primary_alg = (uint16_t)atoi(v);
    } else if (!strcmp(k, "SECONDARY-ALG")) {
      kp->secondary_alg = (uint16_t)atoi(v);
    } else if (!strcmp(k, "PRIMARY-PUB")) {
      if (!kp->primary_sig) {
        primary_name = pq_alg_name(kp->primary_alg);
        if (!primary_name) goto out;
        kp->primary_sig = OQS_SIG_new(primary_name);
        if (!kp->primary_sig) goto out;
        kp->primary_pub_len = kp->primary_sig->length_public_key;
        kp->primary_priv_len = kp->primary_sig->length_secret_key;
      }
      kp->primary_pub = OPENSSL_malloc(kp->primary_pub_len);
      if (!kp->primary_pub) goto out;
      size_t wrote;
      if (b64_decode(v, kp->primary_pub, kp->primary_pub_len, &wrote) < 0 ||
          wrote != kp->primary_pub_len) goto out;
    } else if (!strcmp(k, "PRIMARY-PRIV")) {
      if (!kp->primary_sig) goto out; /* order violation */
      kp->primary_priv = OPENSSL_malloc(kp->primary_priv_len);
      if (!kp->primary_priv) goto out;
      size_t wrote;
      if (b64_decode(v, kp->primary_priv, kp->primary_priv_len, &wrote) < 0 ||
          wrote != kp->primary_priv_len) goto out;
    } else if (!strcmp(k, "SECONDARY-PUB")) {
      if (!kp->secondary_sig) {
        secondary_name = pq_alg_name(kp->secondary_alg);
        if (!secondary_name) goto out;
        kp->secondary_sig = OQS_SIG_new(secondary_name);
        if (!kp->secondary_sig) goto out;
        kp->secondary_pub_len = kp->secondary_sig->length_public_key;
        kp->secondary_priv_len = kp->secondary_sig->length_secret_key;
      }
      kp->secondary_pub = OPENSSL_malloc(kp->secondary_pub_len);
      if (!kp->secondary_pub) goto out;
      size_t wrote;
      if (b64_decode(v, kp->secondary_pub, kp->secondary_pub_len, &wrote) < 0 ||
          wrote != kp->secondary_pub_len) goto out;
    } else if (!strcmp(k, "SECONDARY-PRIV")) {
      if (!kp->secondary_sig) goto out;
      kp->secondary_priv = OPENSSL_malloc(kp->secondary_priv_len);
      if (!kp->secondary_priv) goto out;
      size_t wrote;
      if (b64_decode(v, kp->secondary_priv, kp->secondary_priv_len, &wrote) < 0 ||
          wrote != kp->secondary_priv_len) goto out;
    } else if (!strcmp(k, "END")) {
      break;
    }
  }

  /* Validate that all required fields were populated */
  if (!kp->primary_pub || !kp->primary_priv ||
      !kp->secondary_pub || !kp->secondary_priv) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "PQ: keyfile %s: missing required fields", path);
    goto out;
  }

  kp->active = 1;
  rc = 0;

out:
  if (fp) fclose(fp);
  if (rc != 0) pq_keypair_free(kp);
  return rc;
}

/* ----------------------------------------------------------------------
 * Dual signature: produce and verify
 * -------------------------------------------------------------------- */

int pq_sign_dual(uint8_t *out, size_t *outlen,
                 const struct PQKeypair *kp,
                 const uint8_t *msg, size_t msglen)
{
  OQS_STATUS rc;
  size_t p_siglen, s_siglen;
  size_t needed;
  uint8_t *p;

  if (!out || !outlen || !kp || !kp->active || !msg) return -1;

  /* Reserve enough space. Signatures have variable size up to max_length. */
  p_siglen = kp->primary_sig->length_signature;
  s_siglen = kp->secondary_sig->length_signature;
  needed = 2 + 4 + p_siglen + 2 + 4 + s_siglen;
  if (*outlen < needed) { *outlen = needed; return -1; }

  p = out;

  /* Primary block */
  put_u16_le(p, kp->primary_alg);              p += 2;
  uint8_t *p_lenslot = p;                      p += 4;
  rc = OQS_SIG_sign(kp->primary_sig, p, &p_siglen, msg, msglen, kp->primary_priv);
  if (rc != OQS_SUCCESS) return -1;
  put_u32_le(p_lenslot, (uint32_t)p_siglen);
  p += p_siglen;

  /* Secondary block */
  put_u16_le(p, kp->secondary_alg);            p += 2;
  uint8_t *s_lenslot = p;                      p += 4;
  rc = OQS_SIG_sign(kp->secondary_sig, p, &s_siglen, msg, msglen, kp->secondary_priv);
  if (rc != OQS_SUCCESS) return -1;
  put_u32_le(s_lenslot, (uint32_t)s_siglen);
  p += s_siglen;

  *outlen = (size_t)(p - out);
  return 0;
}

int pq_verify_dual(const uint8_t *sig, size_t siglen,
                   const struct PQKeypair *kp,
                   const uint8_t *msg, size_t msglen)
{
  OQS_STATUS rc;
  const uint8_t *p = sig;
  const uint8_t *end = sig + siglen;
  uint16_t alg;
  uint32_t len;

  if (!sig || !kp || !kp->primary_sig || !kp->secondary_sig || !msg) return -1;

  /* Primary */
  if (end - p < 6) return -1;
  alg = get_u16_le(p); p += 2;
  len = get_u32_le(p); p += 4;
  if (alg != kp->primary_alg) return 0;
  if ((size_t)(end - p) < len) return -1;
  rc = OQS_SIG_verify(kp->primary_sig, msg, msglen, p, len, kp->primary_pub);
  if (rc != OQS_SUCCESS) return 0;
  p += len;

  /* Secondary */
  if (end - p < 6) return -1;
  alg = get_u16_le(p); p += 2;
  len = get_u32_le(p); p += 4;
  if (alg != kp->secondary_alg) return 0;
  if ((size_t)(end - p) < len) return -1;
  rc = OQS_SIG_verify(kp->secondary_sig, msg, msglen, p, len, kp->secondary_pub);
  if (rc != OQS_SUCCESS) return 0;

  return 1;
}

/* ----------------------------------------------------------------------
 * Symmetric primitives: HMAC-SHA3-512 and HKDF-SHA3-512
 * -------------------------------------------------------------------- */

int pq_hmac_sha3_512(const void *key, size_t keylen,
                     const void *data, size_t datalen,
                     unsigned char *mac)
{
  EVP_MAC *emac;
  EVP_MAC_CTX *ctx;
  OSSL_PARAM params[2];
  size_t outlen = 64;
  int rc = -1;

  if (!key || !data || !mac) return -1;

  emac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!emac) return -1;
  ctx = EVP_MAC_CTX_new(emac);
  if (!ctx) { EVP_MAC_free(emac); return -1; }

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA3-512", 0);
  params[1] = OSSL_PARAM_construct_end();

  if (EVP_MAC_init(ctx, (const unsigned char *)key, keylen, params) &&
      EVP_MAC_update(ctx, (const unsigned char *)data, datalen) &&
      EVP_MAC_final(ctx, mac, &outlen, 64))
    rc = 0;

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(emac);
  return rc;
}

int pq_hkdf_sha3_512(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *okm, size_t okm_len)
{
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
  OSSL_PARAM params[5];
  int rc = -1;

  if (!ikm || !okm) return -1;
  if (okm_len > 255 * 64) return -1;  /* RFC 5869 limit */

  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (!kdf) return -1;
  kctx = EVP_KDF_CTX_new(kdf);
  if (!kctx) { EVP_KDF_free(kdf); return -1; }

  int p = 0;
  params[p++] = OSSL_PARAM_construct_utf8_string("digest", "SHA3-512", 0);
  params[p++] = OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikm_len);
  if (salt && salt_len)
    params[p++] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
  if (info && info_len)
    params[p++] = OSSL_PARAM_construct_octet_string("info", (void *)info, info_len);
  params[p] = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kctx, okm, okm_len, params) == 1)
    rc = 0;

  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);
  return rc;
}

int pq_derive_s2s_mac_key(uint8_t key[64], const char *passwd)
{
  static const uint8_t label[] = "cathexis-s2s-hmac-sha3-v2";
  if (!key || !passwd) return -1;
  return pq_hkdf_sha3_512((const uint8_t *)passwd, strlen(passwd),
                          NULL, 0,
                          label, sizeof(label) - 1,
                          key, 64);
}

#endif /* USE_PQ */
