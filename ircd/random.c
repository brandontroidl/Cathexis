/*
 * IRC - Internet Relay Chat, ircd/random.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief Cryptographically strong random number generator.
 *
 * Cathexis 1.2.0: Replaced the MD5-based PRNG with /dev/urandom reads.
 * When OpenSSL is available, uses RAND_bytes() which is seeded from the
 * OS entropy pool. Falls back to /dev/urandom on non-SSL builds.
 *
 * The old MD5-based PRNG used gettimeofday() as its primary entropy
 * source, which is predictable and cryptographically weak.
 */
#include "config.h"

#include "random.h"
#include "client.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "send.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef USE_SSL
#include "ircd_crypto.h"
#endif

/** Read random bytes from the best available source.
 * @param[out] buf Buffer to fill with random bytes.
 * @param[in] len Number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
static int crypto_random_bytes(unsigned char *buf, size_t len)
{
#ifdef USE_SSL
  /* OpenSSL RAND_bytes uses the OS entropy pool (getrandom/urandom)
   * and is CSPRNG-grade. */
  if (RAND_bytes(buf, len) == 1)
    return 0;
  /* Fall through to /dev/urandom if OpenSSL fails */
#endif

  {
    int fd;
    ssize_t n;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
      return -1;

    n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
  }
}

/** Seed the PRNG with a string.
 * In the modernized implementation, this adds the seed string to OpenSSL's
 * entropy pool when available. Without OpenSSL, this is a no-op since
 * /dev/urandom manages its own entropy.
 *
 * @param[in] from Client setting the seed (may be NULL).
 * @param[in] fields Input arguments (fields[0] is used).
 * @param[in] count Number of input arguments.
 * @return Non-zero on success, zero on error.
 */
int
random_seed_set(struct Client* from, const char* const* fields, int count)
{
  if (count < 1) {
    if (from)
      return need_more_params(from, "SET");
    else {
      log_write(LS_CONFIG, L_ERROR, 0, "Not enough fields in F line");
      return 0;
    }
  }

#ifdef USE_SSL
  /* Feed the seed into OpenSSL's entropy pool as additional randomness */
  RAND_seed(fields[0], strlen(fields[0]));
#endif

  return 1;
}

/** Generate a cryptographically strong pseudo-random 32-bit number.
 * Uses RAND_bytes (OpenSSL) or /dev/urandom directly.
 * @return A 32-bit random number.
 */
unsigned int ircrandom(void)
{
  unsigned int val;

  if (crypto_random_bytes((unsigned char *)&val, sizeof(val)) == 0)
    return val;

  /* Absolute last resort — should never happen on a sane system.
   * Log a warning so the admin knows something is very wrong. */
  log_write(LS_SYSTEM, L_WARNING, 0,
            "ircrandom: failed to read from entropy source");
  return 0;
}
