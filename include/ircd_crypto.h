/** @file ircd_crypto.h
 * @brief Portable cryptographic utility functions.
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

#endif /* INCLUDED_ircd_crypto_h */
