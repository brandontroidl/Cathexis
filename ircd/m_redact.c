/*
 * IRC - Internet Relay Chat, ircd/m_redact.c
 * Copyright (C) 2026 Cathexis Development
 *
 * IRCv3 draft/message-redaction — delete a previously sent message.
 *
 * REDACT <target> <msgid> [:<reason>]
 *
 * Only forwarded to clients with draft/message-redaction CAP.
 * Clients without the CAP never see the REDACT.
 */
#include "config.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include <string.h>

/** Handle REDACT from a local client.
 *
 * REDACT <target> <msgid> [:<reason>]
 *
 * If target is a channel, forward to members with CAP_MSGREDACT.
 * If target is a user, forward to that user if they have CAP_MSGREDACT.
 */
int m_redact(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target, *msgid, *reason;
  struct Channel *chptr;
  struct Client *acptr;
  struct Membership *member;

  if (parc < 3)
    return need_more_params(sptr, "REDACT");

  target = parv[1];
  msgid  = parv[2];
  reason = (parc > 3) ? parv[parc - 1] : NULL;

  if (IsChannelName(target)) {
    /* Channel REDACT */
    if (!(chptr = FindChannel(target)))
      return send_reply(sptr, ERR_NOSUCHCHANNEL, target);

    if (!find_member_link(chptr, sptr))
      return send_reply(sptr, ERR_NOTONCHANNEL, target);

    /* Forward to channel members with the CAP */
    for (member = chptr->members; member; member = member->next_member) {
      acptr = member->user;
      if (!MyConnect(acptr))
        continue;
      if (!HasCap(acptr, CAP_MSGREDACT))
        continue;
      if (reason)
        sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s :%s",
                      target, msgid, reason);
      else
        sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s",
                      target, msgid);
    }
  } else {
    /* DM REDACT */
    if (!(acptr = FindUser(target)))
      return send_reply(sptr, ERR_NOSUCHNICK, target);

    if (MyConnect(acptr) && HasCap(acptr, CAP_MSGREDACT)) {
      if (reason)
        sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s :%s",
                      target, msgid, reason);
      else
        sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s",
                      target, msgid);
    }

    /* Echo back to sender if they have echo-message */
    if (MyConnect(sptr) && HasCap(sptr, CAP_ECHOMSG)
        && HasCap(sptr, CAP_MSGREDACT)) {
      if (reason)
        sendcmdto_one(sptr, CMD_REDACT, sptr, "%s %s :%s",
                      target, msgid, reason);
      else
        sendcmdto_one(sptr, CMD_REDACT, sptr, "%s %s",
                      target, msgid);
    }
  }

  return 0;
}
