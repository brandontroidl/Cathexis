/*
 * IRC - Internet Relay Chat, ircd/m_setname.c
 * Copyright (C) 2024 Nefarious Development
 *
 * IRCv3 SETNAME command - allows clients to change their realname (GECOS).
 * Spec: https://ircv3.net/specs/extensions/setname
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 SETNAME command handler - client and server.
 */

#include "config.h"

#include "client.h"
#include "capab.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_tags.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_user.h"

#include <string.h>

/** Validate a realname: reject CR and LF characters.
 * @param[in] name Proposed realname.
 * @return 1 if valid, 0 if invalid.
 */
static int
valid_realname(const char *name)
{
  const char *p;
  if (!name || !*name)
    return 0;
  for (p = name; *p; p++) {
    if (*p == '\r' || *p == '\n')
      return 0;
  }
  return 1;
}

/** Send SETNAME notifications to common channels and propagate.
 * @param[in] sptr Client whose realname changed.
 * @param[in] cptr Connection the change came from.
 */
static void
setname_propagate(struct Client *sptr, struct Client *cptr)
{
  struct TagSet tags;

  tagset_init(&tags);
  make_server_time_tag(&tags);
  make_account_tag(&tags, sptr);

  sendtagcmdto_common_channels_capab_butone(&tags, sptr, CMD_SETNAME, sptr,
                                            CAP_SETNAME, CAP_NONE,
                                            ":%s", cli_info(sptr));

  if (MyConnect(sptr) && CapActive(sptr, CAP_SETNAME))
    sendtagcmdto_one(&tags, sptr, CMD_SETNAME, sptr,
                     ":%s", cli_info(sptr));

  tagset_clear(&tags);

  sendcmdto_serv_butone(sptr, CMD_SETNAME, cptr, ":%s", cli_info(sptr));
}

/** Handle SETNAME from a local client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message (== cptr for local).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int m_setname(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *newname;

  assert(cptr == sptr);

  /* IRCv3: require the setname capability */
  if (!CapActive(sptr, CAP_SETNAME))
    return 0;

  if (parc < 2 || EmptyString(parv[1])) {
    sendcmdto_one(&me, CMD_STDRPL_FAIL, sptr,
                  "SETNAME NEED_MORE_PARAMS :Missing parameters");
    return 0;
  }

  newname = parv[1];

  if (!valid_realname(newname)) {
    sendcmdto_one(&me, CMD_STDRPL_FAIL, sptr,
                  "SETNAME INVALID_REALNAME :Realname contains invalid characters");
    return 0;
  }

  if (strlen(newname) > REALLEN) {
    sendcmdto_one(&me, CMD_STDRPL_FAIL, sptr,
                  "SETNAME INVALID_REALNAME :Realname too long");
    return 0;
  }

  ircd_strncpy(cli_info(sptr), newname, REALLEN);

  setname_propagate(sptr, cptr);

  return 0;
}

/** Handle SETNAME from a peer server.
 * @param[in] cptr Server that sent us the message.
 * @param[in] sptr Original source (remote user).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_setname(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  assert(IsServer(cptr));

  if (parc < 2 || EmptyString(parv[1]))
    return protocol_violation(cptr, "SETNAME with no parameter from %C", sptr);

  ircd_strncpy(cli_info(sptr), parv[1], REALLEN);

  setname_propagate(sptr, cptr);

  return 0;
}
