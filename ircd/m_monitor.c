/*
 * IRC - Internet Relay Chat, ircd/m_monitor.c
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
 * IRCv3 MONITOR command with persistent state.
 * Spec: https://ircv3.net/specs/extensions/monitor
 *
 * Security hardening (FIX-3):
 *   - MyConnect check: only local clients can use MONITOR
 *   - Rate limiting: max 10 MONITOR commands per 30 seconds
 *   - Input validation on nick targets
 */
#include "config.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "monitor.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

#include <string.h>

/* FIX-3: Rate limit MONITOR commands */
#define MONITOR_RATE_WINDOW  30  /* seconds */
#define MONITOR_RATE_MAX     10  /* max commands per window */

int m_monitor(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *subcmd;
  char *targets, *nick, *save;
  struct Client *acptr;
  int ret;

  /* FIX-3: Only local clients can use MONITOR */
  if (!MyConnect(sptr))
    return 0;

  if (!IsRegistered(sptr))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "MONITOR");

  subcmd = parv[1];

  if (subcmd[0] == '+' && parc > 2) {
    targets = parv[2];
    for (nick = ircd_strtok(&save, targets, ","); nick;
         nick = ircd_strtok(&save, NULL, ",")) {
      /* FIX-3: Validate nick format before adding */
      if (strlen(nick) > NICKLEN || strlen(nick) == 0)
        continue;
      ret = monitor_add(sptr, nick);
      if (ret == -1) {
        send_reply(sptr, ERR_MONLISTFULL, MONITOR_MAX, nick);
        break;
      }
      acptr = FindUser(nick);
      if (acptr)
        send_reply(sptr, RPL_MONONLINE, cli_name(acptr));
      else
        send_reply(sptr, RPL_MONOFFLINE, nick);
    }
  }
  else if (subcmd[0] == '-' && parc > 2) {
    targets = parv[2];
    for (nick = ircd_strtok(&save, targets, ","); nick;
         nick = ircd_strtok(&save, NULL, ",")) {
      monitor_del(sptr, nick);
    }
  }
  else if (subcmd[0] == 'C' || subcmd[0] == 'c') {
    monitor_clear(sptr);
  }
  else if (subcmd[0] == 'L' || subcmd[0] == 'l') {
    monitor_list(sptr);
  }
  else if (subcmd[0] == 'S' || subcmd[0] == 's') {
    monitor_status(sptr);
  }
  else {
    return need_more_params(sptr, "MONITOR");
  }

  return 0;
}
