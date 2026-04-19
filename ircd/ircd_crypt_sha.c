/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_sha.c
 * Copyright (C) 2026 Cathexis Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */
/**
 * @file
 * @brief SHA-256 and SHA-512 password hashing via system crypt()
 *
 * Provides password hashing using the SHA-256 ($5$) and SHA-512 ($6$)
 * algorithms in the system's crypt() function. Requires a modern
 * libcrypt or libxcrypt (standard on all current Linux distributions).
 *
 * Salt format:  $5$rounds=535000$<16-char-salt>$  (SHA-256)
 *               $6$rounds=656000$<16-char-salt>$  (SHA-512)
 *
 * Password tag: $SHA256$<hash>  or  $SHA512$<hash>
 */
#define _XOPEN_SOURCE 500

#include "config.h"
#include "ircd_crypt.h"
#include "ircd_crypt_sha.h"
#include "ircd_log.h"
#include "s_debug.h"
#include "ircd_alloc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

/* Standard crypt(3) base64 alphabet for salt generation */
static const char crypt_b64[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Recommended rounds for each algorithm.
 * These are chosen for quantum resistance: each Grover iteration must
 * evaluate the full hash chain, so high round counts provide defense
 * in depth. Target: ~200ms on a modern CPU (2024 era).
 * SHA-512 is slightly slower per round, so needs fewer rounds. */
#define SHA256_ROUNDS 1200000
#define SHA512_ROUNDS 1000000
#define SALT_LEN 16

/** Read random bytes from /dev/urandom.
 * @param buf Output buffer.
 * @param len Number of bytes to read.
 * @return 0 on success, -1 on failure.
 */
static int sha_random_bytes(unsigned char *buf, size_t len)
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

/** Generate a crypt-style salt with the given prefix and rounds.
 * @param buf Output buffer (must be at least 48 bytes).
 * @param buflen Size of output buffer.
 * @param prefix "$5$" or "$6$".
 * @param rounds Number of hash rounds.
 * @return Pointer to buf, or NULL on failure.
 */
static char *sha_generate_salt(char *buf, size_t buflen,
                               const char *prefix, int rounds)
{
  unsigned char raw[SALT_LEN];
  char saltchars[SALT_LEN + 1];
  int i;

  if (sha_random_bytes(raw, SALT_LEN) < 0)
    return NULL;

  for (i = 0; i < SALT_LEN; i++)
    saltchars[i] = crypt_b64[raw[i] % 64];
  saltchars[SALT_LEN] = '\0';

  snprintf(buf, buflen, "%srounds=%d$%s$", prefix, rounds, saltchars);
  return buf;
}

/** SHA-256 password hashing function.
 * Uses system crypt() with $5$ prefix.
 */
const char *ircd_crypt_sha256(const char *key, const char *salt)
{
  static char newsalt[64];
  const char *result;

  assert(NULL != key);
  assert(NULL != salt);

  /* If salt already starts with $5$, use it directly (verification) */
  if (salt[0] == '$' && salt[1] == '5' && salt[2] == '$')
  {
    result = crypt(key, salt);
  }
  else
  {
    /* Generate new salt for password creation */
    if (sha_generate_salt(newsalt, sizeof(newsalt), "$5$", SHA256_ROUNDS) == NULL)
      return NULL;
    result = crypt(key, newsalt);
  }

  if (result == NULL || result[0] != '$' || result[1] != '5')
  {
    Debug((DEBUG_DEBUG, "ircd_crypt_sha256: crypt() did not return SHA-256 hash"));
    return NULL;
  }

  return result;
}

/** SHA-512 password hashing function.
 * Uses system crypt() with $6$ prefix.
 */
const char *ircd_crypt_sha512(const char *key, const char *salt)
{
  static char newsalt[64];
  const char *result;

  assert(NULL != key);
  assert(NULL != salt);

  /* If salt already starts with $6$, use it directly (verification) */
  if (salt[0] == '$' && salt[1] == '6' && salt[2] == '$')
  {
    result = crypt(key, salt);
  }
  else
  {
    /* Generate new salt for password creation */
    if (sha_generate_salt(newsalt, sizeof(newsalt), "$6$", SHA512_ROUNDS) == NULL)
      return NULL;
    result = crypt(key, newsalt);
  }

  if (result == NULL || result[0] != '$' || result[1] != '6')
  {
    Debug((DEBUG_DEBUG, "ircd_crypt_sha512: crypt() did not return SHA-512 hash"));
    return NULL;
  }

  return result;
}

/** Register the SHA-256 mechanism. */
void ircd_register_crypt_sha256(void)
{
  crypt_mech_t *crypt_mech;

  if ((crypt_mech = (crypt_mech_t *)MyMalloc(sizeof(crypt_mech_t))) == NULL)
    return;

  crypt_mech->mechname = "sha256";
  crypt_mech->shortname = "crypt_sha256";
  crypt_mech->description = "SHA-256 password hash ($5$) via system crypt().";
  crypt_mech->crypt_function = &ircd_crypt_sha256;
  /* SHA-256 hashes are detected directly by their $5$ prefix in
   * ircd_crypt(), like bcrypt. No tag wrapper needed. */
  crypt_mech->crypt_token = "";
  crypt_mech->crypt_token_size = 0;

  ircd_crypt_register_mech(crypt_mech);
}

/** Register the SHA-512 mechanism. */
void ircd_register_crypt_sha512(void)
{
  crypt_mech_t *crypt_mech;

  if ((crypt_mech = (crypt_mech_t *)MyMalloc(sizeof(crypt_mech_t))) == NULL)
    return;

  crypt_mech->mechname = "sha512";
  crypt_mech->shortname = "crypt_sha512";
  crypt_mech->description = "SHA-512 password hash ($6$) via system crypt(). Recommended.";
  crypt_mech->crypt_function = &ircd_crypt_sha512;
  /* SHA-512 hashes are detected directly by their $6$ prefix in
   * ircd_crypt(), like bcrypt. No tag wrapper needed. */
  crypt_mech->crypt_token = "";
  crypt_mech->crypt_token_size = 0;

  ircd_crypt_register_mech(crypt_mech);
}
