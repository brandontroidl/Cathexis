/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_argon2.c
 * Copyright (C) 2026 Cathexis Development
 *
 * Argon2id password hashing — memory-hard, GPU/ASIC-resistant.
 * Winner of the Password Hashing Competition (2015).
 * Quantum-safe: hash functions are not broken by Grover's algorithm
 * at these output sizes (256-bit hash → 128-bit post-quantum security).
 *
 * Parameters (tuned for IRC server — fast enough for OPER auth,
 * strong enough to resist offline brute-force):
 *   Memory:      19456 KB (19 MB)
 *   Iterations:  2
 *   Parallelism: 1
 *   Salt:        16 bytes (random via RAND_bytes)
 *   Hash:        32 bytes
 *   Format:      $argon2id$v=19$m=19456,t=2,p=1$<b64salt>$<b64hash>
 *
 * Requires: libargon2 (apt install libargon2-dev)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

#include "config.h"

#ifdef USE_ARGON2

#include "ircd_crypt.h"
#include "ircd_crypt_argon2.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "s_debug.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <argon2.h>

#ifdef USE_SSL
#include "ircd_crypto.h"
#endif

/* ── Argon2id parameters ───────────────────────────────── */

#define ARGON2_T_COST    2       /* iterations */
#define ARGON2_M_COST    19456   /* memory in KB (19 MB) */
#define ARGON2_P_COST    1       /* parallelism */
#define ARGON2_SALTLEN   16      /* salt bytes */
#define ARGON2_HASHLEN   32      /* hash output bytes */
#define ARGON2_ENCODED_MAX 256   /* max encoded string length */

/* ── Static buffers ────────────────────────────────────── */

static char encoded_buf[ARGON2_ENCODED_MAX];

/* ── Generate random salt ──────────────────────────────── */

static int generate_salt(unsigned char *salt, size_t len)
{
#ifdef USE_SSL
  if (RAND_bytes(salt, len) == 1)
    return 0;
#endif
  /* Fallback: /dev/urandom */
  {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, salt, len);
      close(fd);
      if ((size_t)n == len)
        return 0;
    }
  }
  return -1;
}

/* ── Hash a password ───────────────────────────────────── */

const char *ircd_crypt_argon2(const char *password)
{
  unsigned char salt[ARGON2_SALTLEN];
  int ret;

  if (!password || !password[0])
    return NULL;

  if (generate_salt(salt, sizeof(salt)) != 0) {
    Debug((DEBUG_ERROR, "Argon2: failed to generate salt"));
    return NULL;
  }

  ret = argon2id_hash_encoded(
    ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST,
    password, strlen(password),
    salt, ARGON2_SALTLEN,
    ARGON2_HASHLEN,
    encoded_buf, sizeof(encoded_buf)
  );

  if (ret != ARGON2_OK) {
    Debug((DEBUG_ERROR, "Argon2: hash failed: %s", argon2_error_message(ret)));
    return NULL;
  }

  return encoded_buf;
}

/* ── Verify a password ─────────────────────────────────── */

int ircd_crypt_argon2_verify(const char *password, const char *hash)
{
  if (!password || !hash)
    return -1;

  return argon2id_verify(hash, password, strlen(password));
}

/* ── Crypt mechanism wrapper for ircd_crypt.c ──────────── */

static const char *argon2_crypt_func(const char *key, const char *salt)
{
  /* salt parameter is ignored — we generate our own random salt */
  (void)salt;
  return ircd_crypt_argon2(key);
}

static crypt_mech_t argon2_mech = {
  "crypt_argon2",                   /* shortname */
  "Argon2id password hashing",      /* description */
  "$argon2",                        /* prefix */
  argon2_crypt_func,                /* crypt_function */
  NULL,                             /* crypt_token (auto-detect by prefix) */
  0                                 /* flags */
};

void ircd_register_crypt_argon2(void)
{
  ircd_crypt_register_mech(&argon2_mech);
  Debug((DEBUG_INFO, "Argon2: registered Argon2id password mechanism"));
}

#else /* !USE_ARGON2 */

/* Stub when libargon2 is not available */

#include "ircd_crypt_argon2.h"
#include "ircd_log.h"
#include "s_debug.h"

const char *ircd_crypt_argon2(const char *password)
{
  (void)password;
  return NULL;
}

int ircd_crypt_argon2_verify(const char *password, const char *hash)
{
  (void)password;
  (void)hash;
  return -1;
}

void ircd_register_crypt_argon2(void)
{
  Debug((DEBUG_INFO, "Argon2: not compiled (install libargon2-dev and reconfigure)"));
}

#endif /* USE_ARGON2 */
