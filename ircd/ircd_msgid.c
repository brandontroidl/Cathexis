/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * ircd/ircd_msgid.c — IRCv3 message ID generation.
 */

#include "config.h"
#include "ircd_msgid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_SSL
#include <openssl/rand.h>
#include <openssl/crypto.h>
#endif

void ircd_msgid_generate(char *buf, size_t buflen)
{
  unsigned char raw[16];
  static const char hex[] = "0123456789abcdef";
  int i, ok = 0;

  if (!buf || buflen < MSGID_LEN + 1) {
    if (buf && buflen > 0)
      buf[0] = '\0';
    return;
  }

#ifdef USE_SSL
  /* Generate 16 random bytes via OpenSSL */
  if (RAND_bytes(raw, sizeof(raw)) == 1)
    ok = 1;
#endif

  if (!ok) {
    /* Fallback: should never happen with OpenSSL, but produce something unique */
    snprintf(buf, buflen, "%08lx%08lx%08lx%08lx",
             (unsigned long)time(NULL), (unsigned long)getpid(),
             (unsigned long)rand(), (unsigned long)rand());
    return;
  }

  /* Hex encode */
  for (i = 0; i < 16 && (size_t)(i * 2 + 1) < buflen; i++) {
    buf[i * 2]     = hex[(raw[i] >> 4) & 0x0f];
    buf[i * 2 + 1] = hex[raw[i] & 0x0f];
  }
  buf[MSGID_LEN] = '\0';

#ifdef USE_SSL
  OPENSSL_cleanse(raw, sizeof(raw));
#endif
}
