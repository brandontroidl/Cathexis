/*
 * IRC - Internet Relay Chat, ircd/m_register.c
 * Copyright (C) 2026 Cathexis Development
 *
 * IRCv3 draft/account-registration — register accounts via REGISTER command.
 *
 * Bridges to NickServ: converts REGISTER into a PRIVMSG to NickServ's
 * REGISTER command, then returns standard-replies to the client.
 *
 * REGISTER <account> {<email> | "*"} <password>
 * VERIFY <account> <code>
 */
#include "config.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include <string.h>

/** Handle REGISTER from a local client.
 *
 * REGISTER <account> {<email> | "*"} <password>
 *
 * If account is "*", use the client's current nick.
 * Bridges to NickServ REGISTER command internally.
 */
int m_register(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account, *email, *password;
  struct Client *nickserv;

  if (!HasCap(sptr, CAP_ACCREG)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
      "%C :FAIL REGISTER COMPLETE_CONNECTION_REQUIRED * "
      ":Registration via REGISTER requires draft/account-registration CAP",
      sptr);
    return 0;
  }

  if (parc < 4)
    return need_more_params(sptr, "REGISTER");

  account  = parv[1];
  email    = parv[2];
  password = parv[parc - 1];

  /* If account is *, use current nick */
  if (account[0] == '*' && account[1] == '\0')
    account = cli_name(sptr);

  /* Check if already logged in */
  if (IsAccount(sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
      "%C :FAIL REGISTER ALREADY_AUTHENTICATED %s :You are already logged in",
      sptr, account);
    return 0;
  }

  /* Find NickServ */
  nickserv = FindUser("NickServ");
  if (!nickserv) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
      "%C :FAIL REGISTER TEMPORARILY_UNAVAILABLE %s "
      ":Account registration service is not available",
      sptr, account);
    return 0;
  }

  /* Bridge to NickServ: send REGISTER command as a PRIVMSG from the user.
   * NickServ's REGISTER handler expects: REGISTER <password> [<email>]
   * The NickServ account name is always the sender's current nick.
   */
  if (email[0] != '*' || email[1] != '\0') {
    /* With email */
    sendcmdto_one(sptr, CMD_PRIVATE, nickserv,
      "%C :REGISTER %s %s", nickserv, password, email);
  } else {
    /* Without email */
    sendcmdto_one(sptr, CMD_PRIVATE, nickserv,
      "%C :REGISTER %s", nickserv, password);
  }

  /* Send a note to the client that registration was forwarded */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
    "%C :NOTE REGISTER REGISTERING %s "
    ":Your registration request has been sent to NickServ. "
    "Check for a reply from NickServ.",
    sptr, account);

  return 0;
}

/** Handle VERIFY from a local client (email verification).
 *
 * VERIFY <account> <code>
 */
int m_verify(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *nickserv;

  if (parc < 3)
    return need_more_params(sptr, "VERIFY");

  nickserv = FindUser("NickServ");
  if (!nickserv) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
      "%C :FAIL VERIFY TEMPORARILY_UNAVAILABLE %s "
      ":Verification service is not available",
      sptr, parv[1]);
    return 0;
  }

  /* Bridge to NickServ VERIFY/CONFIRM */
  sendcmdto_one(sptr, CMD_PRIVATE, nickserv,
    "%C :VERIFY %s", nickserv, parv[2]);

  return 0;
}
