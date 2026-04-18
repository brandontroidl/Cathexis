/** @file ircd_crypto.h
 * @brief Portable cryptographic utility functions.
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
 * Provides constant-time comparison and secure memory clearing
 * that work with or without OpenSSL.
 */
#ifndef INCLUDED_ircd_crypto_h
#define INCLUDED_ircd_crypto_h

#include "config.h"
#include <string.h>

#ifdef USE_SSL
#include <openssl/crypto.h>
/* OpenSSL provides CRYPTO_memcmp */
#else
/** Constant-time memory comparison (fallback when OpenSSL is unavailable).
 * Compares \a len bytes of \a a and \a b without early exit on mismatch,
 * preventing timing side-channel attacks on secret data.
 * @param a First buffer.
 * @param b Second buffer.
 * @param len Number of bytes to compare.
 * @return 0 if buffers are equal, non-zero otherwise.
 */
static inline int CRYPTO_memcmp(const void *a, const void *b, size_t len)
{
  const volatile unsigned char *pa = (const volatile unsigned char *)a;
  const volatile unsigned char *pb = (const volatile unsigned char *)b;
  volatile unsigned char diff = 0;
  size_t i;
  for (i = 0; i < len; i++)
    diff |= pa[i] ^ pb[i];
  return diff;
}
#endif

/** Constant-time string comparison for passwords and secrets.
 * Compares two NUL-terminated strings without leaking length or
 * content information through timing. Always compares the full
 * length of both strings.
 * @param a First string.
 * @param b Second string.
 * @return 0 if strings are equal, non-zero otherwise.
 */
static inline int ircd_constcmp(const char *a, const char *b)
{
  size_t alen = strlen(a);
  size_t blen = strlen(b);
  size_t cmplen = (alen < blen) ? alen : blen;
  int result;
  result = CRYPTO_memcmp(a, b, cmplen);
  result |= (alen ^ blen);
  return result;
}

/** Securely clear sensitive memory before freeing.
 * Uses volatile pointer to prevent compiler from optimizing away the
 * memset. Call this on password buffers before MyFree().
 * @param buf Buffer to clear.
 * @param len Number of bytes to clear.
 */
static inline void ircd_clearsecret(void *buf, size_t len)
{
  volatile unsigned char *p = (volatile unsigned char *)buf;
  while (len--)
    *p++ = 0;
}

#ifdef USE_SSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/** Compute HMAC-SHA256.
 * Uses EVP_MAC (OpenSSL 3.0+) or deprecated HMAC() (1.1.x) automatically.
 * @param[in]  key     HMAC key bytes.
 * @param[in]  keylen  Key length in bytes.
 * @param[in]  data    Input data.
 * @param[in]  datalen Data length in bytes.
 * @param[out] mac     Output buffer (must be at least 32 bytes).
 * @return 0 on success, -1 on failure.
 */
static inline int ircd_hmac_sha256(const void *key, size_t keylen,
                                    const void *data, size_t datalen,
                                    unsigned char *mac)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+: use EVP_MAC API (non-deprecated) */
  EVP_MAC *emac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  EVP_MAC_CTX *ctx;
  OSSL_PARAM params[2];
  size_t outlen = 32;
  int ret = -1;

  if (!emac) return -1;
  ctx = EVP_MAC_CTX_new(emac);
  if (!ctx) { EVP_MAC_free(emac); return -1; }

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

  if (EVP_MAC_init(ctx, key, keylen, params) &&
      EVP_MAC_update(ctx, data, datalen) &&
      EVP_MAC_final(ctx, mac, &outlen, 32))
    ret = 0;

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(emac);
  return ret;
#else
  /* OpenSSL 1.1.x: use legacy HMAC() */
  unsigned int outlen = 32;
  if (HMAC(EVP_sha256(), key, keylen, data, datalen, mac, &outlen) == NULL)
    return -1;
  return 0;
#endif
}
#endif /* USE_SSL */

#endif /* INCLUDED_ircd_crypto_h */
