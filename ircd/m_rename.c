/*
 * IRC - Internet Relay Chat, ircd/m_rename.c
 * Copyright (C) 2026 Cathexis Development
 *
 * IRCv3 draft/channel-rename — rename a channel preserving all state.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */
#include "config.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_debug.h"
#include "s_user.h"
#include <string.h>

/** Handle a RENAME from a local client.
 *
 * RENAME #old #new [:reason]
 *
 * Renames a channel preserving membership, modes, bans, topic.
 * Clients with draft/channel-rename CAP see RENAME.
 * Clients without it see PART + JOIN + topic + names (fallback).
 */
int m_rename(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct Channel *target;
  struct Membership *member;
  const char *oldname, *newname, *reason;

  if (parc < 3)
    return need_more_params(sptr, "RENAME");

  oldname = parv[1];
  newname = parv[2];
  reason  = (parc > 3) ? parv[parc - 1] : "";

  /* Validate old channel exists */
  if (!(chptr = FindChannel(oldname)))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, oldname);

  /* Validate caller is on the channel */
  if (!(member = find_member_link(chptr, sptr)))
    return send_reply(sptr, ERR_NOTONCHANNEL, oldname);

  /* Validate caller has ops */
  if (!IsChanOp(member) && !IsChannelManager(member))
    return send_reply(sptr, ERR_CHANOPRIVSNEEDED, oldname);

  /* Validate new channel name */
  if (!IsChannelName(newname) || strlen(newname) > CHANNELLEN) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :FAIL RENAME CANNOT_RENAME %s %s :Invalid channel name",
                  sptr, oldname, newname);
    return 0;
  }

  /* Check new name not already in use (case-insensitive compare) */
  if ((target = FindChannel(newname)) && target != chptr) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :FAIL RENAME CHANNEL_NAME_IN_USE %s %s :Channel name already in use",
                  sptr, oldname, newname);
    return 0;
  }

  /* Don't allow changing prefix type (# -> & etc) */
  if (oldname[0] != newname[0]) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :FAIL RENAME CANNOT_RENAME %s %s :Cannot change channel prefix type",
                  sptr, oldname, newname);
    return 0;
  }

  /* Perform the rename */
  hRemChannel(chptr);
  ircd_strncpy(chptr->chname, newname, CHANNELLEN + 1);
  hAddChannel(chptr);

  /* Notify all members */
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *acptr = member->user;

    if (HasCap(acptr, CAP_CHANNELRENAME)) {
      /* Client supports RENAME — send the rename message */
      sendcmdto_one(sptr, CMD_RENAME, acptr, "%s %s :%s",
                    oldname, newname, reason);
    } else {
      /* Fallback: PART old, JOIN new + topic + names */
      sendcmdto_one(acptr, CMD_PART, acptr, "%s :%s",
                    oldname, *reason ? reason : "Channel renamed");

      /* Send JOIN for new name */
      sendcmdto_one(acptr, CMD_JOIN, acptr, "%s", newname);

      /* Send topic if set */
      if (chptr->topic[0]) {
        send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname,
                   chptr->topic_nick, chptr->topic_time);
      }

      /* Send names */
      do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
    }
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname, newname, reason);

  return 0;
}

/** Handle a RENAME from a server (S2S propagation).
 */
int ms_rename(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct Membership *member;
  const char *oldname, *newname, *reason;

  if (parc < 3)
    return need_more_params(sptr, "RENAME");

  oldname = parv[1];
  newname = parv[2];
  reason  = (parc > 3) ? parv[parc - 1] : "";

  if (!(chptr = FindChannel(oldname)))
    return 0; /* Channel doesn't exist locally, ignore */

  /* Perform the rename */
  hRemChannel(chptr);
  ircd_strncpy(chptr->chname, newname, CHANNELLEN + 1);
  hAddChannel(chptr);

  /* Notify local members */
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *acptr = member->user;

    if (!MyConnect(acptr))
      continue;

    if (HasCap(acptr, CAP_CHANNELRENAME)) {
      sendcmdto_one(sptr, CMD_RENAME, acptr, "%s %s :%s",
                    oldname, newname, reason);
    } else {
      sendcmdto_one(acptr, CMD_PART, acptr, "%s :%s",
                    oldname, *reason ? reason : "Channel renamed");
      sendcmdto_one(acptr, CMD_JOIN, acptr, "%s", newname);
      if (chptr->topic[0]) {
        send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname,
                   chptr->topic_nick, chptr->topic_time);
      }
      do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
    }
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_RENAME, cptr, "%s %s :%s",
                        oldname, newname, reason);

  return 0;
}
