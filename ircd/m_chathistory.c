/*
 * IRC - Internet Relay Chat, ircd/m_chathistory.c
 * Copyright (C) 2026 Cathexis Development Team

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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * IRCv3 CHATHISTORY command for Cathexis IRCd.
 * Informed by Ergo's irc/handlers.go chathistoryHandler and the
 * IRCv3 chathistory specification. This allows services (Sigil/X3)
 * to provide history replay by proxying CHATHISTORY requests.
 *
 * Wire format (client→server):
 *   CHATHISTORY <subcommand> <target> <timestamp/msgid> <limit>
 *
 * Subcommands: LATEST, BEFORE, AFTER, AROUND, BETWEEN
 *
 * The IRCd forwards these to services via the S2S XQUERY mechanism
 * (same pattern Cathexis uses for SASL: forward to a designated
 * services agent). Services respond with BATCH of historical messages.
 */
#include "config.h"

#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_user.h"

#include <string.h>
#include <stdlib.h>

/*
 * m_chathistory - client message handler
 *
 * Forward CHATHISTORY requests to the designated history services agent
 * using XQUERY, which is the same S2S extension Cathexis uses for SASL
 * and other services queries.
 *
 * parv[0] = sender prefix
 * parv[1] = subcommand (LATEST, BEFORE, AFTER, AROUND, BETWEEN)
 * parv[2] = target (#channel or nick)
 * parv[3] = reference (timestamp= or msgid=)
 * parv[4] = limit
 * parv[5] = (optional, for BETWEEN) end reference
 */
int m_chathistory(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  char *subcmd;
  const char *histserv;

  if (!IsRegistered(sptr))
    return 0;

  if (parc < 4)
    return need_more_params(sptr, "CHATHISTORY");

  subcmd = parv[1];

  /* Validate subcommand (Ergo pattern: only allow defined subcommands) */
  if (strcmp(subcmd, "LATEST") && strcmp(subcmd, "BEFORE") &&
      strcmp(subcmd, "AFTER") && strcmp(subcmd, "AROUND") &&
      strcmp(subcmd, "BETWEEN")) {
    send_reply(sptr, ERR_UNKNOWNCOMMAND, "CHATHISTORY");
    return 0;
  }

  /* BETWEEN requires 5 params */
  if (!strcmp(subcmd, "BETWEEN") && parc < 5) {
    return need_more_params(sptr, "CHATHISTORY BETWEEN");
  }

  /* Forward to history services agent via XQUERY
   * (same pattern as SASL forwarding in m_sasl.c) */
  histserv = feature_str(FEAT_HIS_SERVERNAME);
  if (!histserv || !*histserv)
    histserv = "*";

  if (!strcmp(histserv, "*")) {
    /* No history server configured, send empty response */
    send_reply(sptr, ERR_UNKNOWNCOMMAND, "CHATHISTORY");
    return 0;
  }

  acptr = find_match_server((char *)histserv);
  if (!acptr) {
    send_reply(sptr, ERR_NOSUCHSERVER, histserv);
    return 0;
  }

  /* Forward via XQUERY: <server> XQ <target_server> <uid> CHATHISTORY <args...> */
  if (parc > 5) {
    sendcmdto_one(sptr, CMD_XQUERY, acptr, "%C :%s %s %s %s %s",
                  acptr, subcmd, parv[2], parv[3], parv[4], parv[5]);
  } else if (parc > 4) {
    sendcmdto_one(sptr, CMD_XQUERY, acptr, "%C :%s %s %s %s",
                  acptr, subcmd, parv[2], parv[3], parv[4]);
  } else {
    sendcmdto_one(sptr, CMD_XQUERY, acptr, "%C :%s %s %s",
                  acptr, subcmd, parv[2], parv[3]);
  }

  return 0;
}
