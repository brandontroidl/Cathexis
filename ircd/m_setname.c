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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include "monitor.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Validate a realname string.
 * Rejects CR (0x0D) and LF (0x0A) to prevent IRC message injection.
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

/** Send SETNAME notifications to common channels and propagate to servers.
 * @param[in] sptr Client whose realname changed.
 * @param[in] cptr Connection the change came from.
 */
static void
setname_propagate(struct Client *sptr, struct Client *cptr)
{
  /* Notify channel members who have the setname capability enabled */
  sendcmdto_common_channels_capab_butone(sptr, CMD_SETNAME, sptr,
                                         CAP_SETNAME, 0,
                                         ":%s", cli_info(sptr));
  monitor_notify_setname(sptr); /* IRCv3 extended-monitor */

  /* Echo back to the source if local and capable */
  if (MyConnect(sptr) && CapActive(sptr, CAP_SETNAME))
    sendcmdto_one(sptr, CMD_SETNAME, sptr, ":%s", cli_info(sptr));

  /* Propagate to all peer servers except the source */
  sendcmdto_serv_butone(sptr, CMD_SETNAME, cptr, ":%s", cli_info(sptr));
}

/** Handle a SETNAME command from a local client.
 *
 * Requires the setname IRCv3 capability to be negotiated.
 * Validates the realname for length and forbidden characters.
 *
 * parv[0] = sender prefix
 * parv[1] = new realname
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message (== cptr for local clients).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success or error.
 */
int m_setname(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *newname;

  assert(cptr == sptr);

  /* IRCv3: require the setname capability to be negotiated */
  if (!CapActive(sptr, CAP_SETNAME))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "SETNAME");

  newname = parv[1];

  /* Reject embedded CR/LF (prevents IRC message injection) */
  if (!valid_realname(newname)) {
    /* IRCv3 standard-replies: FAIL SETNAME INVALID_REALNAME */
    sendrawto_one(sptr, "FAIL SETNAME INVALID_REALNAME :Realname is not valid");
    return 0;
  }

  /* Enforce length limit */
  if (strlen(newname) > REALLEN) {
    /* IRCv3 standard-replies: FAIL SETNAME INVALID_REALNAME */
    sendrawto_one(sptr, "FAIL SETNAME INVALID_REALNAME :Realname is too long");
    return 0;
  }

  /* Apply the change using bounded copy */
  ircd_strncpy(cli_info(sptr), newname, REALLEN);

  /* Notify channels and propagate to servers */
  setname_propagate(sptr, cptr);

  return 0;
}

/** Handle a SETNAME command from a peer server.
 *
 * Trusts the peer server (already authenticated).
 * Does NOT send error replies back across the network.
 *
 * parv[0] = sender prefix (numnick)
 * parv[1] = new realname
 *
 * @param[in] cptr Server link that sent us the message.
 * @param[in] sptr Original source client (remote user).
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int ms_setname(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  assert(IsServer(cptr));

  if (parc < 2 || EmptyString(parv[1]))
    return protocol_violation(cptr, "SETNAME with no parameter from %C", sptr);

  /* Trust peer but truncate for safety */
  ircd_strncpy(cli_info(sptr), parv[1], REALLEN);

  /* Notify local channel members and propagate to other servers */
  setname_propagate(sptr, cptr);

  return 0;
}
