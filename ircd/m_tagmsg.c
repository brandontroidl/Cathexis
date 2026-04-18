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
 * Raw client tags are preserved during parsing and relayed to channel
 * members (or DM targets) who have the message-tags CAP enabled.
 * Server-time and msgid tags are added to outgoing messages.
 */

#include "config.h"

#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_msgid.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "struct.h"

#include <string.h>
#include <sys/time.h>

/** Handle a TAGMSG from a local client.
 *
 * TAGMSG carries only IRCv3 message tags (typing indicators, reactions,
 * etc.) and has no text body. Relay to channel/user members who have
 * the message-tags CAP enabled.
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector. parv[1] is the target.
 * @return Zero on success.
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  const char *raw_tags;
  char sendbuf[512];
  int len;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* Must have a target */
  if (parc < 2 || EmptyString(parv[1])) {
    return send_reply(sptr, ERR_NORECIPIENT, MSG_TAGMSG);
  }

  /* Must have message-tags CAP */
  if (!HasCap(sptr, CAP_MSGTAGS))
    return 0;

  /* Get the raw tags from the parse cycle */
  raw_tags = parse_get_raw_tags();
  if (!raw_tags || !*raw_tags)
    return 0;  /* No tags = nothing to relay */

  if (IsChannelName(parv[1])) {
    struct Membership *member;
    struct Membership *cmember;

    chptr = FindChannel(parv[1]);
    if (!chptr)
      return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

    /* Check if sender is in the channel */
    member = find_member_link(chptr, sptr);
    if (!member && !IsChannelService(sptr))
      return send_reply(sptr, ERR_CANNOTSENDTOCHAN, parv[1]);

    /* Build the TAGMSG line with server-time and msgid */
    /* Relay to each channel member with message-tags CAP */
    for (cmember = chptr->members; cmember; cmember = cmember->next_member) {
      struct Client *acptr = cmember->user;
      if (acptr == sptr)  /* skip sender */
        continue;
      if (!MyConnect(acptr))  /* local clients only */
        continue;
      if (!HasCap(acptr, CAP_MSGTAGS))  /* need message-tags */
        continue;

      /* Build tagged message: @<client-tags>;server-tags :source TAGMSG target */
      {
        char timebuf[64];
        char msgidbuf[MSGID_LEN + 1];
        struct tm *tmptr;
        time_t now_t = CurrentTime;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        tmptr = gmtime(&now_t);
        snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 tmptr->tm_year + 1900, tmptr->tm_mon + 1, tmptr->tm_mday,
                 tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec,
                 (int)(tv.tv_usec / 1000));
        ircd_msgid_generate(msgidbuf, sizeof(msgidbuf));

        len = snprintf(sendbuf, sizeof(sendbuf),
                       "@%s;time=%s;msgid=%s :%s!%s@%s TAGMSG %s",
                       raw_tags, timebuf, msgidbuf,
                       cli_name(sptr), cli_user(sptr)->username,
                       cli_user(sptr)->host, parv[1]);
        if (len > 0 && len < (int)sizeof(sendbuf))
          sendrawto_one(acptr, "%s", sendbuf);
      }
    }

    /* Echo back to sender if echo-message CAP */
    if (HasCap(sptr, CAP_ECHOMSG)) {
      char timebuf[64];
      char msgidbuf[MSGID_LEN + 1];
      struct tm *tmptr;
      time_t now_t = CurrentTime;
      struct timeval tv;

      gettimeofday(&tv, NULL);
      tmptr = gmtime(&now_t);
      snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
               tmptr->tm_year + 1900, tmptr->tm_mon + 1, tmptr->tm_mday,
               tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec,
               (int)(tv.tv_usec / 1000));
      ircd_msgid_generate(msgidbuf, sizeof(msgidbuf));

      len = snprintf(sendbuf, sizeof(sendbuf),
                     "@%s;time=%s;msgid=%s :%s!%s@%s TAGMSG %s",
                     raw_tags, timebuf, msgidbuf,
                     cli_name(sptr), cli_user(sptr)->username,
                     cli_user(sptr)->host, parv[1]);
      if (len > 0 && len < (int)sizeof(sendbuf))
        sendrawto_one(sptr, "%s", sendbuf);
    }
  } else {
    /* Private TAGMSG to a user */
    struct Client *acptr = FindUser(parv[1]);
    if (!acptr)
      return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

    if (MyConnect(acptr) && HasCap(acptr, CAP_MSGTAGS)) {
      char timebuf[64];
      char msgidbuf[MSGID_LEN + 1];
      struct tm *tmptr;
      time_t now_t = CurrentTime;
      struct timeval tv;

      gettimeofday(&tv, NULL);
      tmptr = gmtime(&now_t);
      snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
               tmptr->tm_year + 1900, tmptr->tm_mon + 1, tmptr->tm_mday,
               tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec,
               (int)(tv.tv_usec / 1000));
      ircd_msgid_generate(msgidbuf, sizeof(msgidbuf));

      len = snprintf(sendbuf, sizeof(sendbuf),
                     "@%s;time=%s;msgid=%s :%s!%s@%s TAGMSG %s",
                     raw_tags, timebuf, msgidbuf,
                     cli_name(sptr), cli_user(sptr)->username,
                     cli_user(sptr)->host, parv[1]);
      if (len > 0 && len < (int)sizeof(sendbuf))
        sendrawto_one(acptr, "%s", sendbuf);
    }
  }

  return 0;
}
