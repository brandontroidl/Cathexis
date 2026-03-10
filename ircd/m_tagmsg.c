/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
 * Copyright (C) 2026 Cathexis Development
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
 */

/** @file
 * @brief Handlers for the IRCv3 TAGMSG command.
 *
 * TAGMSG is a message that carries only IRCv3 tags and no text body.
 * It is used for typing indicators, reactions, and other tag-only
 * metadata between clients that negotiate the message-tags capability.
 *
 * Since this codebase does not yet have full ircd_tags relay
 * infrastructure, TAGMSG is accepted but silently dropped.
 * This prevents ERR_UNKNOWNCOMMAND for modern clients (IRCCloud,
 * The Lounge, gamja, etc.) that send TAGMSG.
 */

#include "config.h"

#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a TAGMSG from a local client.
 *
 * TAGMSG carries only IRCv3 message tags (typing indicators, reactions,
 * etc.) and has no text body. We accept the command to prevent
 * ERR_UNKNOWNCOMMAND, but do not relay since tag infrastructure is not
 * yet implemented.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector. parv[1] is the target.
 * @return Zero on success.
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  /* Must have a target */
  if (parc < 2 || EmptyString(parv[1])) {
    return send_reply(sptr, ERR_NORECIPIENT, MSG_TAGMSG);
  }

  /* Validate target exists, but don't relay
   * (tag relay requires ircd_tags infrastructure) */
  if (IsChannelName(parv[1])) {
    if (!FindChannel(parv[1]))
      return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
  } else {
    if (!FindUser(parv[1]))
      return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
  }

  /* Silently accept - tags were already stripped by parse_client() */
  return 0;
}
