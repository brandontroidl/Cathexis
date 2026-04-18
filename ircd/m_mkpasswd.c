/*
 * IRC - Internet Relay Chat, ircd/m_mkpasswd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2026 Cathexis Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_crypt.h"
#include "ircd_crypt_native.h"
#include "ircd_crypt_plain.h"
#include "ircd_crypt_argon2.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "random.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <crypt.h>

static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

static char *make_sha_salt(int variant)
{
  static char salt[24];
  int i;
  salt[0] = '$';
  salt[1] = (variant == 512) ? '6' : '5';
  salt[2] = '$';
  for (i = 3; i < 19; i++)
    salt[i] = saltChars[ircrandom() % 64];
  salt[19] = '$';
  salt[20] = '\0';
  return salt;
}

/*
 * m_mkpasswd - generate password hashes
 *
 * Usage: MKPASSWD <password> [ARGON2|BCRYPT|SHA512|SHA256|PLAIN]
 * Default (no type): ARGON2 if available, SHA512 otherwise
 */
int m_mkpasswd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *pass = NULL;

  if (parc < 2)
    return need_more_params(sptr, "MKPASSWD");

  if (parc >= 3) {
    if (!ircd_strcmp(parv[2], "ARGON2")) {
#ifdef USE_ARGON2
      pass = ircd_crypt_argon2(parv[1]);
      if (!pass) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :MKPASSWD: Argon2id hashing failed", sptr);
        return 0;
      }
#else
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :MKPASSWD: Argon2 not compiled (install libargon2-dev)", sptr);
      return 0;
#endif
    } else if (!ircd_strcmp(parv[2], "BCRYPT")) {
      pass = ircd_crypt_native(parv[1], "$2b$12$xxxxxxxxxxxxxxxxxxxx..");
    } else if (!ircd_strcmp(parv[2], "SHA512")) {
      pass = crypt(parv[1], make_sha_salt(512));
    } else if (!ircd_strcmp(parv[2], "SHA256")) {
      pass = crypt(parv[1], make_sha_salt(256));
    } else if (!ircd_strcmp(parv[2], "PLAIN")) {
      pass = ircd_crypt_plain(parv[1], "plain");
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :MKPASSWD <pass> [ARGON2|BCRYPT|SHA512|SHA256|PLAIN]",
                    sptr);
      return 0;
    }
  } else {
    /* Default: ARGON2 if available, SHA512 otherwise */
#ifdef USE_ARGON2
    pass = ircd_crypt_argon2(parv[1]);
#endif
    if (!pass)
      pass = crypt(parv[1], make_sha_salt(512));
  }

  if (pass)
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Encryption for [%s]: %s",
                  sptr, parv[1], pass);
  else
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :MKPASSWD: hashing failed",
                  sptr);

  return 0;
}
