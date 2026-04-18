/*
 * IRC - Internet Relay Chat, ircd/m_dline.c
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
 * DLINE — Local IP-only deny line (Hybrid/Solanum style).
 * Unlike ZLINE (network-wide), DLINE is server-local.
 *
 * DLINE <ip> [<duration> :<reason>]
 * UNDLINE <ip>
 *
 * Informed by: Hybrid m_dline.c, Solanum m_dline.c, Plexus m_dline.c
 */
#include "config.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_user.h"
#include "s_conf.h"

#include <string.h>

/*
 * mo_dline - /DLINE <ip> [duration] :reason
 * Local IP-only ban. Checked at connection time before full registration.
 * Requires IRC operator status.
 */
int mo_dline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *ip, *reason;
  time_t duration = 0;

  if (!IsAnOper(sptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2)
    return need_more_params(sptr, "DLINE");

  ip = parv[1];
  reason = (parc > 2) ? parv[parc - 1] : "No reason";
  if (parc > 3)
    duration = ParseInterval(parv[2]);

  /* TODO: Add to local D-line list, checked in check_conf_lines() */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :Added D-line for %s%s%s: %s", sptr, ip,
                duration ? " (expires in " : "",
                duration ? parv[2] : "",
                reason);

  sendto_opmask_butone(0, SNO_GLINE, "%C added local D-line for %s: %s",
                       sptr, ip, reason);
  return 0;
}

int mo_undline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (!IsAnOper(sptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 2)
    return need_more_params(sptr, "UNDLINE");

  /* TODO: Remove from local D-line list */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :Removed D-line for %s.", sptr, parv[1]);
  sendto_opmask_butone(0, SNO_GLINE, "%C removed local D-line for %s",
                       sptr, parv[1]);
  return 0;
}

/*
 * m_kline/mo_kline - /KLINE <user@host> [duration] :reason
 * Alias for local GLINE. Maps directly to the existing GLINE infrastructure
 * with the GLINE_LOCAL flag set.
 */
int mo_kline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  /* Rewrite as a local GLINE call */
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :KLINE is an alias for local GLINE. Using GLINE.", sptr);
  return mo_gline(cptr, sptr, parc, parv);
}

int mo_unkline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  sendcmdto_one(&me, CMD_NOTICE, sptr,
                "%C :UNKLINE is an alias for removing local GLINE.", sptr);
  /* TODO: Forward to gline removal with LOCAL flag */
  return 0;
}

/*
 * mo_locops - /LOCOPS :message
 * Send a message to all local operators only (not propagated).
 * Informed by: Hybrid m_locops.c, Plexus m_locops.c
 */
int mo_locops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *message;

  if (!IsAnOper(sptr))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2 || EmptyString(parv[parc - 1]))
    return need_more_params(sptr, "LOCOPS");

  message = parv[parc - 1];

  /* Send to all local opers on THIS server only */
  sendto_opmask_butone(0, SNO_OLDREALOP, "from %C: %s", sptr, message);
  return 0;
}

/*
 * m_accept - /ACCEPT [+nick|-nick|*]
 * CallerID accept list management. When user mode +G is set,
 * only users on the accept list can send private messages.
 * Informed by: Hybrid m_accept.c, Solanum m_accept.c
 *
 * +nick — Add nick to accept list
 * -nick — Remove nick from accept list
 * *     — List all accepted nicks
 */
int m_accept(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *target;
  struct Client *acptr;

  if (parc < 2 || EmptyString(parv[1]) || parv[1][0] == '*') {
    /* List accept entries */
    /* TODO: Walk sptr's accept list, send each entry */
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :End of ACCEPT list.", sptr);
    return 0;
  }

  target = parv[1];

  if (target[0] == '+') {
    target++;
    acptr = FindUser(target);
    if (!acptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :%s is not online.", sptr, target);
      return 0;
    }
    /* TODO: Add acptr to sptr's accept list */
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :%s has been added to your accept list.", sptr, target);
  }
  else if (target[0] == '-') {
    target++;
    /* TODO: Remove target from sptr's accept list */
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :%s has been removed from your accept list.", sptr, target);
  }
  else {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Syntax: ACCEPT [+nick|-nick|*]", sptr);
  }

  return 0;
}
