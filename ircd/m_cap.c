/*
 * IRC - Internet Relay Chat, ircd/m_cap.c
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 * @brief Capability negotiation commands
 * @version $Id: m_cap.c 1620 2006-02-16 03:49:55Z entrope $
 */

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_auth.h"
#include "s_user.h"

#include <stdlib.h>
#include <string.h>

typedef int (*bqcmp)(const void *, const void *);

static struct capabilities {
  enum Capab cap;
  char *capstr;
  unsigned long flags;
  char *name;
  int namelen;
  int feat;
  const char *value;  /**< IRCv3 CAP value (for CAP LS 302), NULL if none */
} capab_list[] = {
#define _CAP(cap, flags, name, feat) \
    { CAP_ ## cap, #cap, (flags), (name), sizeof(name) - 1, feat, NULL }
#define _CAPV(cap, flags, name, feat, val) \
    { CAP_ ## cap, #cap, (flags), (name), sizeof(name) - 1, feat, val }
  _CAP(NONE, CAPFL_HIDDEN|CAPFL_PROHIBIT, "none", 0),
  _CAP(NAMESX, 0, "multi-prefix", FEAT_CAP_multi_prefix),
  _CAP(UHNAMES, 0, "userhost-in-names", FEAT_CAP_userhost_in_names),
  _CAP(EXTJOIN, 0, "extended-join", FEAT_CAP_extended_join),
  _CAP(AWAYNOTIFY, 0, "away-notify", FEAT_CAP_away_notify),
  _CAP(ACCNOTIFY, 0, "account-notify", FEAT_CAP_account_notify),
  _CAPV(SASL, 0, "sasl", FEAT_CAP_sasl, "PLAIN,EXTERNAL"),
  _CAP(TLS, 0, "tls", FEAT_CAP_tls),
  /* IRCv3.2+ capabilities */
  _CAP(CAPNOTIFY, 0, "cap-notify", FEAT_CAP_cap_notify),
  _CAP(SERVERTIME, 0, "server-time", FEAT_CAP_server_time),
  _CAP(ACCOUNTTAG, 0, "account-tag", FEAT_CAP_account_tag),
  _CAP(MSGTAGS, 0, "message-tags", FEAT_CAP_message_tags),
  _CAP(ECHOMSG, 0, "echo-message", FEAT_CAP_echo_message),
  _CAP(INVITENOTIFY, 0, "invite-notify", FEAT_CAP_invite_notify),
  _CAP(CHGHOST, 0, "chghost", FEAT_CAP_chghost),
  _CAP(SETNAME, 0, "setname", FEAT_CAP_setname),
  _CAP(BATCH, 0, "batch", FEAT_CAP_batch),
  _CAP(LABELEDRESP, 0, "labeled-response", FEAT_CAP_labeled_response),
  _CAP(STDREPLIES, 0, "standard-replies", FEAT_CAP_standard_replies),
  /* IRCv3 STS — see FEAT_CAP_STS_ENABLED / _PORT / _DURATION / _PRELOAD */
  _CAP(STS, 0, "sts", FEAT_CAP_STS_ENABLED),
  /* IRCv3 ratified — additional */
  _CAP(MSGID, 0, "message-ids", FEAT_CAP_message_ids),
  _CAP(MONITOR, 0, "monitor", FEAT_CAP_monitor),
  /* IRCv3 draft specs */
  _CAP(BOTMODE, 0, "draft/bot-mode", FEAT_CAP_bot_mode),
  _CAP(CHATHISTORY, 0, "draft/chathistory", FEAT_CAP_chathistory),
  _CAP(TYPING, 0, "draft/typing", FEAT_CAP_typing),
  _CAP(NOIMPLICITNAMES, 0, "no-implicit-names", FEAT_CAP_no_implicit_names),
  _CAP(CHANNELRENAME, 0, "draft/channel-rename", FEAT_CAP_channel_rename),
  _CAP(READMARKER, 0, "draft/read-marker", FEAT_CAP_read_marker),
  _CAPV(MULTILINE, 0, "draft/multiline", FEAT_CAP_multiline, "max-bytes=4096"),
  _CAP(PREAWAY, 0, "draft/pre-away", FEAT_CAP_pre_away),
  _CAPV(ACCREG, 0, "draft/account-registration", FEAT_CAP_account_registration, "before-connect"),
  _CAP(EXTMONITOR, 0, "draft/extended-monitor", FEAT_CAP_extended_monitor),
  _CAP(MSGREDACT, 0, "draft/message-redaction", FEAT_CAP_message_redaction),
/*  CAPLIST */
#undef _CAP
#undef _CAPV
};

#define CAPAB_LIST_LEN (sizeof(capab_list) / sizeof(struct capabilities))

static int
capab_sort(const struct capabilities *cap1, const struct capabilities *cap2)
{
  return ircd_strcmp(cap1->name, cap2->name);
}

static int
capab_search(const char *key, const struct capabilities *cap)
{
  const char *rb = cap->name;
  while (ToLower(*key) == ToLower(*rb)) /* walk equivalent part of strings */
    if (!*key++) /* hit the end, all right... */
      return 0;
    else /* OK, let's move on... */
      rb++;

  /* If the character they differ on happens to be a space, and it happens
   * to be the same length as the capability name, then we've found a
   * match; otherwise, return the difference of the two.
   */
  return (IsSpace(*key) && !*rb) ? 0 : (ToLower(*key) - ToLower(*rb));
}

static struct capabilities *
find_cap(const char **caplist_p, int *neg_p)
{
  static int inited = 0;
  const char *caplist = *caplist_p;
  struct capabilities *cap = 0;

  *neg_p = 0; /* clear negative flag... */

  if (!inited) { /* First, let's sort the array... */
    qsort(capab_list, CAPAB_LIST_LEN, sizeof(struct capabilities),
          (bqcmp)capab_sort);
    inited++; /* remember that we've done this step... */
  }

  /* Next, find first non-whitespace character... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* We are now at the beginning of an element of the list; is it negative? */
  if (*caplist == '-') {
    caplist++; /* yes; step past the flag... */
    *neg_p = 1; /* remember that it is negative... */
  }

  /* OK, now see if we can look up the capability... */
  if (*caplist) {
    if (!(cap = (struct capabilities *)bsearch(caplist, capab_list,
                 CAPAB_LIST_LEN,
                 sizeof(struct capabilities),
                 (bqcmp)capab_search))) {
      /* Couldn't find the capability; advance to first whitespace character */
      while (*caplist && !IsSpace(*caplist))
        caplist++;
    } else
      caplist += cap->namelen; /* advance to end of capability name */
  }

  assert(caplist != *caplist_p || !*caplist); /* we *must* advance */

  /* skip past any trailing whitespace... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* move ahead in capability list string--or zero pointer if we hit end */
  *caplist_p = *caplist ? caplist : 0;

  return cap; /* and return the capability (if any) */
}

/** Send a CAP \a subcmd list of capability changes to \a sptr.
 * If more than one line is necessary, each line before the last has
 * an added "*" parameter before that line's capability list.
 * @param[in] sptr Client receiving capability list.
 * @param[in] set Capabilities to show as set (with ack and sticky modifiers).
 * @param[in] rem Capabalities to show as removed (with no other modifier).
 * @param[in] subcmd Name of capability subcommand.
 */
static int
send_caplist(struct Client *sptr, const struct CapSet *set,
             const struct CapSet *rem, const char *subcmd)
{
  char capbuf[BUFSIZE] = "", pfx[16];
  struct MsgBuf *mb;
  int i, loc, len, flags, pfx_len;

  /* set up the buffer for the final LS message... */
  mb = msgq_make(sptr, "%:#C " MSG_CAP " %s %s :", &me,
                 BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), subcmd);

  for (i = 0, loc = 0; i < CAPAB_LIST_LEN; i++) {
    flags = capab_list[i].flags;
    /* This is a little bit subtle, but just involves applying de
     * Morgan's laws to the obvious check: We must display the
     * capability if (and only if) it is set in \a rem or \a set, or
     * if both are null and the capability is hidden.
     */
    if (!(rem && CapHas(rem, capab_list[i].cap))
        && !(set && CapHas(set, capab_list[i].cap))
        && (rem || set || (flags & CAPFL_HIDDEN)
            || (capab_list[i].feat && (!feature_bool(capab_list[i].feat)))))
      continue;

    /* Build the prefix (space separator and any modifiers needed). */
    pfx_len = 0;
    if (loc)
      pfx[pfx_len++] = ' ';
    if (rem && CapHas(rem, capab_list[i].cap))
        pfx[pfx_len++] = '-';
    else {
      if (flags & CAPFL_PROTO)
        pfx[pfx_len++] = '~';
      if (flags & CAPFL_STICKY)
        pfx[pfx_len++] = '=';
    }
    pfx[pfx_len] = '\0';

    len = capab_list[i].namelen + pfx_len; /* how much we'd add... */

    /* IRCv3 STS: generate value dynamically from features.
     * Format: sts=port=<port>,duration=<seconds>[,preload]
     * Only advertised on CAP LS (not REQ), only with 302+, only when
     * FEAT_CAP_STS_ENABLED is true. */
    static char sts_value[96];
    const char *effective_value = capab_list[i].value;

    if (capab_list[i].cap == CAP_STS && MyConnect(sptr) &&
        con_capver(cli_connect(sptr)) >= 302 &&
        feature_bool(FEAT_CAP_STS_ENABLED)) {
      int sts_port = feature_int(FEAT_CAP_STS_PORT);
      int sts_dur  = feature_int(FEAT_CAP_STS_DURATION);
      int preload  = feature_bool(FEAT_CAP_STS_PRELOAD);
      if (sts_port > 0) {
        ircd_snprintf(0, sts_value, sizeof(sts_value),
                       "port=%d,duration=%d%s",
                       sts_port, sts_dur,
                       preload ? ",preload" : "");
        effective_value = sts_value;
      }
    }

    /* IRCv3.2 CAP 302: include =value for caps that have one */
    if (effective_value && MyConnect(sptr) &&
        con_capver(cli_connect(sptr)) >= 302)
      len += 1 + strlen(effective_value); /* +1 for '=' */

    if (msgq_bufleft(mb) < loc + len + 2) { /* would add too much; must flush */
      sendcmdto_one(&me, CMD_CAP, sptr, "%s %s :%s",
                    BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr),  subcmd, capbuf);
      capbuf[(loc = 0)] = '\0'; /* re-terminate the buffer... */
    }

    if (effective_value && MyConnect(sptr) &&
        con_capver(cli_connect(sptr)) >= 302)
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s=%s",
                           pfx, capab_list[i].name, effective_value);
    else
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s",
                           pfx, capab_list[i].name);
  }

  msgq_append(0, mb, "%s", capbuf); /* append capabilities to the final cmd */
  send_buffer(sptr, mb, 0); /* send them out... */
  msgq_clean(mb); /* and release the buffer */

  return 0; /* convenience return */
}

static int
cap_ls(struct Client *sptr, const char *caplist)
{
  if (IsUnknown(sptr) && cli_auth(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  /* IRCv3.2 CAP LS 302 - track version and implicitly enable cap-notify */
  if (caplist && atoi(caplist) >= 302) {
    if (MyConnect(sptr))
      con_capver(cli_connect(sptr)) = 302;
    /* cap-notify is implicitly enabled for 302 clients */
    CapSet(cli_capab(sptr), CAP_CAPNOTIFY);
    CapSet(cli_active(sptr), CAP_CAPNOTIFY);
  }

  return send_caplist(sptr, 0, 0, "LS"); /* send list of capabilities */
}

static int
cap_req(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  struct CapSet set, rem;
  struct CapSet cs = *cli_capab(sptr); /* capability set */
  struct CapSet as = *cli_active(sptr); /* active set */
  int neg;

  if (IsUnknown(sptr) && cli_auth(sptr)) /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  memset(&set, 0, sizeof(set));
  memset(&rem, 0, sizeof(rem));
  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) /* look up capability... */
        || (!neg && (cap->flags & CAPFL_PROHIBIT)) /* is it prohibited? */
        || (neg && (cap->flags & CAPFL_STICKY))) { /* is it sticky? */
      sendcmdto_one(&me, CMD_CAP, sptr, "%s NAK :%s",
                    BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr), caplist);
      return 0; /* can't complete requested op... */
    }

    if (neg) { /* set or clear the capability... */
      CapSet(&rem, cap->cap);
      CapClr(&set, cap->cap);
      CapClr(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
        CapClr(&as, cap->cap);
    } else {
      CapClr(&rem, cap->cap);
      CapSet(&set, cap->cap);
      CapSet(&cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
        CapSet(&as, cap->cap);
    }
  }

  /* Notify client of accepted changes and copy over results. */
  send_caplist(sptr, &set, &rem, "ACK");
  *cli_capab(sptr) = cs;
  *cli_active(sptr) = as;


  return 0;
}

static int
cap_ack(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  int neg;

  /* Coming from the client, this generally indicates that the client
   * is using a new backwards-incompatible protocol feature.  As such,
   * it does not require further response from the server.
   */
  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) || /* look up capability... */
        (neg ? HasCap(sptr, cap->cap) : !HasCap(sptr, cap->cap))) /* uh... */
      continue;

    if (neg) { /* set or clear the active capability... */
      if (cap->flags & CAPFL_STICKY)
        continue; /* but don't clear sticky capabilities */
      CapClr(cli_active(sptr), cap->cap);
    } else {
      if (cap->flags & CAPFL_PROHIBIT)
        continue; /* and don't set prohibited ones */
      CapSet(cli_active(sptr), cap->cap);
    }
  }

  return 0;
}

static int
cap_clear(struct Client *sptr, const char *caplist)
{
  struct CapSet cleared;
  struct capabilities *cap;
  unsigned int ii;

  /* XXX: If we ever add a capab list sorted by capab value, it would
   * be good cache-wise to use it here. */
  memset(&cleared, 0, sizeof(cleared));
  for (ii = 0; ii < CAPAB_LIST_LEN; ++ii) {
    cap = &capab_list[ii];
    /* Only clear active non-sticky capabilities. */
    if (!HasCap(sptr, cap->cap) || (cap->flags & CAPFL_STICKY))
      continue;
    CapSet(&cleared, cap->cap);
    CapClr(cli_capab(sptr), cap->cap);
    if (!(cap->flags & CAPFL_PROTO))
      CapClr(cli_active(sptr), cap->cap);
  }
  send_caplist(sptr, 0, &cleared, "ACK");

  return 0;
}

static int
cap_end(struct Client *sptr, const char *caplist)
{
  if (!IsUnknown(sptr) || !cli_auth(sptr)) /* registration has completed... */
    return 0; /* so just ignore the message... */

  return auth_cap_done(cli_auth(sptr));
}

static int
cap_list(struct Client *sptr, const char *caplist)
{
  /* Send the list of the client's capabilities */
  return send_caplist(sptr, cli_capab(sptr), 0, "LIST");
}

static struct subcmd {
  char *cmd;
  int (*proc)(struct Client *sptr, const char *caplist);
} cmdlist[] = {
  { "ACK",   cap_ack   },
  { "CLEAR", cap_clear },
  { "END",   cap_end   },
  { "LIST",  cap_list  },
  { "LS",    cap_ls    },
  { "NAK",   0         },
  { "REQ",   cap_req   }
};

static int
subcmd_search(const char *cmd, const struct subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

/** Handle a capability request or response from a client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int
m_cap(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd, *caplist = 0;
  struct subcmd *cmd;

  if (parc < 2) /* a subcommand is required */
    return 0;
  subcmd = parv[1];
  if (parc > 2) /* a capability list was provided */
    caplist = parv[2];

  /* find the subcommand handler */
  if (!(cmd = (struct subcmd *)bsearch(subcmd, cmdlist,
      sizeof(cmdlist) / sizeof(struct subcmd),
      sizeof(struct subcmd),
      (bqcmp)subcmd_search)))
    return send_reply(sptr, ERR_UNKNOWNCAPCMD, subcmd);

  /* then execute it... */
  return cmd->proc ? (cmd->proc)(sptr, caplist) : 0;
}

void client_check_caps(struct Client *client, struct Client *replyto)
{
  char outbuf[BUFSIZE];
  int i = 0;
  static char capbufp[BUFSIZE] = "";
  size_t pos = 0;

  capbufp[0] = '\0';

  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (CapActive(client, capab_list[i].cap)) {
      if (pos + capab_list[i].namelen + 4 > 70) {
        capbufp[pos] = '\0';
        ircd_snprintf(0, outbuf, sizeof(outbuf), "   Capabilities:: %s", capbufp);
        send_reply(replyto, RPL_DATASTR, outbuf);
        pos = 0;
      }

      if (pos + capab_list[i].namelen + 2 < sizeof(capbufp)) {
        memcpy(capbufp + pos, capab_list[i].name, capab_list[i].namelen);
        pos += capab_list[i].namelen;
        capbufp[pos++] = ' ';
      }
    }
  }

  if (pos > 0) {
    capbufp[pos] = '\0';
    ircd_snprintf(0, outbuf, sizeof(outbuf), "   Capabilities:: %s", capbufp);
    send_reply(replyto, RPL_DATASTR, outbuf);
  }
}
