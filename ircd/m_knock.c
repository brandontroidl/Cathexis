/*
 * IRC - Internet Relay Chat, ircd/m_knock.c
 * Copyright (C) 2026 Cathexis Development

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
 * KNOCK <#channel> - Request an invite to an invite-only channel.
 *
 * Security hardening (FIX-4):
 *   - Per-user rate limit via target_limit infrastructure
 *   - MyConnect check
 *   - Channel validation
 */
#include "config.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_user.h"

#include <string.h>

int m_knock(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;

  if (!MyConnect(sptr))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "KNOCK");

  if (!IsChannelName(parv[1]))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  chptr = FindChannel(parv[1]);
  if (!chptr)
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  /* Already in channel */
  if (find_member_link(chptr, sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :You are already in %s.", sptr, chptr->chname);
    return 0;
  }

  /* Channel must be +i */
  if (!(chptr->mode.mode & MODE_INVITEONLY)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :%s is not invite-only.", sptr, chptr->chname);
    return 0;
  }

  /* Check for +K (NOKNOCK) */
  if (chptr->mode.exmode & EXMODE_NOKNOCK) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Cannot KNOCK on %s (+K is set).", sptr, chptr->chname);
    return 0;
  }

  /* Check if banned */
  if (find_ban(sptr, chptr->banlist, 0, 0)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :You are banned from %s.", sptr, chptr->chname);
    return 0;
  }

  /* FIX-4: Rate limit via target_limit infrastructure.
   * check_target_limit returns non-zero if throttled. */
  if (check_target_limit(sptr, chptr, chptr->chname, 0))
    return 0;

  /* Send knock notification to channel ops */
  sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, sptr, SKIP_NONOPS,
                           '\0', "%H :[Knock] %C (%s@%s) has requested an invite.",
                           chptr, sptr, cli_user(sptr)->username,
                           cli_user(sptr)->host);

  /* Confirm to the user */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :Knock sent to %s.", sptr, chptr->chname);

  return 0;
}
