/*
 * IRC - Internet Relay Chat, ircd/m_sa.c
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
 * SA* (Server Admin) commands for Network Administrators.
 * All require PRIV_NETADMIN (+N) — no external services needed.
 *
 * Each command has:
 *   mo_sa*  — oper handler (local opers issue the command)
 *   ms_sa*  — server handler (propagated across the network via S2S)
 *
 * Commands: SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, SATOPIC, SAWHOIS,
 *           SAIDENT, SAINFO, SANOOP
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "s2s_crypto.h"
#include "numnicks.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

#include <string.h>
#include <stdlib.h>

/** Verify that a server is authorized to send SA* commands.
 *
 * When SERVICES_HUB_NUMERIC is configured, only the server with that
 * numeric can originate SA* commands. This replaces the P10 trust model
 * where any server could send SA* commands.
 *
 * When SERVICES_HUB_NUMERIC is not set, the legacy behavior applies
 * (any server's SA* commands are accepted).
 *
 * @param[in] sptr Source server of the SA* command.
 * @param[in] cmd  Command name for logging.
 * @return 1 if authorized, 0 if rejected.
 */
static int s2s_sa_authorized(struct Client *sptr, const char *cmd)
{
  const char *hub_numeric;

  /* If no services hub configured, fall back to legacy trust */
  hub_numeric = feature_str(FEAT_SERVICES_HUB_NUMERIC);
  if (!hub_numeric || !*hub_numeric)
    return 1;

  /* Find the originating server */
  if (IsServer(sptr)) {
    /* sptr is the server itself — check its numeric */
    if (!strncmp(cli_yxx(sptr), hub_numeric, 2))
      return 1;
  } else if (cli_user(sptr) && cli_user(sptr)->server) {
    /* sptr is a pseudo-client on the services hub */
    struct Client *srv = cli_user(sptr)->server;
    if (!strncmp(cli_yxx(srv), hub_numeric, 2))
      return 1;
  }

  /* Rejected — log it */
  sendto_opmask_butone(0, SNO_OLDSNO,
    "S2S-AUTH: Rejected %s from %s (not services hub %s)",
    cmd, cli_name(sptr), hub_numeric);
  return 0;
}

/* ================================================================
 * SAJOIN — Force a user to join channel(s)
 * ================================================================ */

int mo_sajoin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  char *p = 0;
  char *name;
  char chanbuf[BUFSIZE];

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3)
    return need_more_params(sptr, "SAJOIN");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SAJOIN to force %C into %s",
                        sptr, acptr, parv[2]);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SAJOIN, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }

  ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
  joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());

  for (name = ircd_strtok(&p, chanbuf, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    if (!IsChannelName(name) || !strIsIrcCh(name))
      continue;
    if (!(chptr = FindChannel(name))) {
      if (((name[0] == '&') && !feature_bool(FEAT_LOCAL_CHANNELS))
          || strlen(name) > IRCD_MIN(CHANNELLEN, feature_int(FEAT_CHANNELLEN)))
        continue;
      if (!(chptr = get_channel(acptr, name, CGT_CREATE)))
        continue;
      joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
    } else if (find_member_link(chptr, acptr)) {
      continue;
    } else {
      int flags = CHFL_DEOPPED;
      if (chptr->users == 0 && !chptr->mode.apass[0]
          && !(chptr->mode.exmode & EXMODE_PERSIST)) {
        flags = CHFL_CHANOP;
        chptr->creationtime++;
      }
      joinbuf_join(&join, chptr, flags);
    }
    del_invite(acptr, chptr);
    if (chptr->topic[0]) {
      send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
  }
  joinbuf_flush(&join);
  joinbuf_flush(&create);
  return 0;
}

int ms_sajoin(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (parc < 3)
    return need_more_params(sptr, "SAJOIN");
  if (!s2s_sa_authorized(sptr, "SAJOIN")) return 0;
  if (!(acptr = findNUser(parv[1])))
    return 0;
  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(sptr, CMD_SAJOIN, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }
  /* Execute locally by building a synthetic call */
  {
    char *lparv[4];
    lparv[0] = cli_name(sptr);
    lparv[1] = cli_name(acptr);
    lparv[2] = parv[2];
    lparv[3] = NULL;
    /* Bypass priv check — already validated by originating server */
    ircd_strncpy(lparv[2], parv[2], BUFSIZE - 1);

    /* Directly join the user using the joinbuf infrastructure */
    {
      struct Channel *chptr;
      struct JoinBuf join, create;
      char chanbuf[BUFSIZE];
      char *p = 0, *name;
      ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
      joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
      joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());
      for (name = ircd_strtok(&p, chanbuf, ","); name;
           name = ircd_strtok(&p, 0, ",")) {
        if (!IsChannelName(name) || !strIsIrcCh(name)) continue;
        if (!(chptr = FindChannel(name))) {
          if (!(chptr = get_channel(acptr, name, CGT_CREATE))) continue;
          joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
        } else if (!find_member_link(chptr, acptr)) {
          joinbuf_join(&join, chptr, CHFL_DEOPPED);
        }
        del_invite(acptr, chptr);
        if (chptr->topic[0]) {
          send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
          send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick, chptr->topic_time);
        }
        do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
      }
      joinbuf_flush(&join);
      joinbuf_flush(&create);
    }
  }
  return 0;
}

/* ================================================================
 * SAPART — Force a user to part channel(s)
 * ================================================================ */

int mo_sapart(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  char *p = 0, *name, *comment;
  char chanbuf[BUFSIZE];
  unsigned int flags;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3)
    return need_more_params(sptr, "SAPART");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  comment = (parc > 3 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;
  sendto_opmask_butone(0, SNO_SACMD, "%C used SAPART to force %C from %s", sptr, acptr, parv[2]);

  if (!MyUser(acptr)) {
    if (comment)
      sendcmdto_serv_butone(&me, CMD_SAPART, cptr, "%C %s :%s", acptr, parv[2], comment);
    else
      sendcmdto_serv_butone(&me, CMD_SAPART, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }

  ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, comment, 0);
  for (name = ircd_strtok(&p, chanbuf, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    flags = 0;
    chptr = get_channel(acptr, name, CGT_NO_CREATE);
    if (!chptr || !(member = find_member_link(chptr, acptr))) continue;
    if (IsZombie(member)) flags |= CHFL_ZOMBIE;
    if (IsDelayedJoin(member)) flags |= CHFL_DELAYED;
    joinbuf_join(&parts, chptr, flags);
  }
  return joinbuf_flush(&parts);
}

int ms_sapart(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (parc < 3) return need_more_params(sptr, "SAPART");
  if (!s2s_sa_authorized(sptr, "SAPART")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  if (!MyUser(acptr)) {
    if (parc > 3 && !EmptyString(parv[parc - 1]))
      sendcmdto_serv_butone(sptr, CMD_SAPART, cptr, "%C %s :%s", acptr, parv[2], parv[parc - 1]);
    else
      sendcmdto_serv_butone(sptr, CMD_SAPART, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }
  {
    struct Channel *chptr;
    struct Membership *member;
    struct JoinBuf parts;
    char chanbuf[BUFSIZE], *p = 0, *name;
    char *comment = (parc > 3 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;
    unsigned int flags;
    ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
    joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, comment, 0);
    for (name = ircd_strtok(&p, chanbuf, ","); name; name = ircd_strtok(&p, 0, ",")) {
      flags = 0;
      chptr = get_channel(acptr, name, CGT_NO_CREATE);
      if (!chptr || !(member = find_member_link(chptr, acptr))) continue;
      if (IsZombie(member)) flags |= CHFL_ZOMBIE;
      if (IsDelayedJoin(member)) flags |= CHFL_DELAYED;
      joinbuf_join(&parts, chptr, flags);
    }
    joinbuf_flush(&parts);
  }
  return 0;
}

/* ================================================================
 * SACYCLE — Force a user to part and rejoin channel(s)
 * Ported from UnrealIRCd third/sacycle by Valerie Pond.
 * ================================================================ */

int mo_sacycle(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts, join, create;
  char *p = 0, *name;
  char chanbuf[BUFSIZE];
  unsigned int flags;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3)
    return need_more_params(sptr, "SACYCLE");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SACYCLE to force %C to cycle %s",
                        sptr, acptr, parv[2]);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SACYCLE, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }

  ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);

  /* Phase 1: Part all specified channels */
  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, "Cycling", 0);
  for (name = ircd_strtok(&p, chanbuf, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    flags = 0;
    chptr = get_channel(acptr, name, CGT_NO_CREATE);
    if (!chptr || !(member = find_member_link(chptr, acptr))) continue;
    if (IsZombie(member)) flags |= CHFL_ZOMBIE;
    if (IsDelayedJoin(member)) flags |= CHFL_DELAYED;
    joinbuf_join(&parts, chptr, flags);
  }
  joinbuf_flush(&parts);

  /* Phase 2: Rejoin all specified channels */
  ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
  p = 0;
  joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());
  for (name = ircd_strtok(&p, chanbuf, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    if (!IsChannelName(name) || !strIsIrcCh(name)) continue;
    if (!(chptr = FindChannel(name))) {
      if (((name[0] == '&') && !feature_bool(FEAT_LOCAL_CHANNELS))
          || strlen(name) > IRCD_MIN(CHANNELLEN, feature_int(FEAT_CHANNELLEN)))
        continue;
      if (!(chptr = get_channel(acptr, name, CGT_CREATE))) continue;
      joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
    } else if (find_member_link(chptr, acptr)) {
      continue;
    } else {
      int jflags = CHFL_DEOPPED;
      if (chptr->users == 0 && !chptr->mode.apass[0]
          && !(chptr->mode.exmode & EXMODE_PERSIST)) {
        jflags = CHFL_CHANOP;
        chptr->creationtime++;
      }
      joinbuf_join(&join, chptr, jflags);
    }
    del_invite(acptr, chptr);
    if (chptr->topic[0]) {
      send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
                 chptr->topic_time);
    }
    do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
  }
  joinbuf_flush(&join);
  joinbuf_flush(&create);

  sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :*** You were forced to cycle %s", acptr, parv[2]);
  return 0;
}

int ms_sacycle(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (parc < 3) return need_more_params(sptr, "SACYCLE");
  if (!s2s_sa_authorized(sptr, "SACYCLE")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(sptr, CMD_SACYCLE, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }
  /* Execute locally — reuse mo_sacycle logic without priv check */
  {
    struct Channel *chptr;
    struct Membership *member;
    struct JoinBuf parts, join, create;
    char chanbuf[BUFSIZE], *p = 0, *name;
    unsigned int flags;

    /* Phase 1: Part */
    ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
    joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, "Cycling", 0);
    for (name = ircd_strtok(&p, chanbuf, ","); name;
         name = ircd_strtok(&p, 0, ",")) {
      flags = 0;
      chptr = get_channel(acptr, name, CGT_NO_CREATE);
      if (!chptr || !(member = find_member_link(chptr, acptr))) continue;
      if (IsZombie(member)) flags |= CHFL_ZOMBIE;
      if (IsDelayedJoin(member)) flags |= CHFL_DELAYED;
      joinbuf_join(&parts, chptr, flags);
    }
    joinbuf_flush(&parts);

    /* Phase 2: Rejoin */
    ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);
    p = 0;
    joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
    joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());
    for (name = ircd_strtok(&p, chanbuf, ","); name;
         name = ircd_strtok(&p, 0, ",")) {
      if (!IsChannelName(name) || !strIsIrcCh(name)) continue;
      if (!(chptr = FindChannel(name))) {
        if (!(chptr = get_channel(acptr, name, CGT_CREATE))) continue;
        joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
      } else if (!find_member_link(chptr, acptr)) {
        joinbuf_join(&join, chptr, CHFL_DEOPPED);
      }
      del_invite(acptr, chptr);
      if (chptr->topic[0]) {
        send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick, chptr->topic_time);
      }
      do_names(acptr, chptr, NAMES_ALL|NAMES_EON);
    }
    joinbuf_flush(&join);
    joinbuf_flush(&create);

    sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :*** You were forced to cycle %s", acptr, parv[2]);
  }
  return 0;
}

/* ================================================================
 * SANICK — Force a user to change nickname
 * ================================================================ */

int mo_sanick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr, *acptr2;
  char nick[NICKLEN + 2];
  char *arg;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SANICK");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
  if (ircd_strcmp(cli_name(acptr), parv[2]) == 0) return 0;

  arg = parv[2];
  if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
    arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';
  ircd_strncpy(nick, arg, sizeof(nick) - 1);
  nick[sizeof(nick) - 1] = '\0';

  if (0 == do_nick_name(nick))
    return send_reply(sptr, ERR_ERRONEUSNICKNAME, parv[2]);
  if (isNickJuped(nick))
    return send_reply(sptr, ERR_NICKNAMEINUSE, nick);
  if ((acptr2 = SeekClient(nick)) && acptr != acptr2)
    return send_reply(sptr, ERR_NICKNAMEINUSE, nick);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SANICK to change %C to %s", sptr, acptr, nick);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SANICK, cptr, "%C %s", acptr, nick);
    return 0;
  }
  set_nick_name(acptr, acptr, nick, parc, parv, 1);
  sendcmdto_serv_butone(&me, CMD_SANICK, cptr, "%C %s", acptr, nick);
  return 0;
}

int ms_sanick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char nick[NICKLEN + 2];

  if (parc < 3) return need_more_params(sptr, "SANICK");
  if (!s2s_sa_authorized(sptr, "SANICK")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  ircd_strncpy(nick, parv[2], NICKLEN);
  nick[NICKLEN] = '\0';
  if (ircd_strcmp(cli_name(acptr), nick) == 0) return 0;
  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(sptr, CMD_SANICK, cptr, "%s %s", parv[1], nick);
    return 0;
  }
  if (!do_nick_name(nick)) return 0;
  if (SeekClient(nick) && SeekClient(nick) != acptr) return 0;
  set_nick_name(acptr, acptr, nick, parc, parv, 1);
  sendcmdto_serv_butone(sptr, CMD_SANICK, cptr, "%s %s", parv[1], nick);
  return 0;
}

/* ================================================================
 * SAMODE — Force mode changes on a user or channel
 * ================================================================ */

int mo_samode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct ModeBuf mbuf;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SAMODE");

  if (IsChannelName(parv[1])) {
    if (!(chptr = FindChannel(parv[1])))
      return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

    /* Build full mode string with parameters for the SNO notice */
    {
      char modeparams[512];
      int len, j;
      len = ircd_snprintf(0, modeparams, sizeof(modeparams), "%s", parv[2]);
      for (j = 3; j < parc && len < (int)sizeof(modeparams) - 2; j++)
        len += ircd_snprintf(0, modeparams + len, sizeof(modeparams) - len,
                             " %s", parv[j]);
      sendto_opmask_butone(0, SNO_SACMD, "%C used SAMODE on %s: %s",
                            sptr, parv[1], modeparams);
    }

    /* Call mode_parse directly with FORCE — bypasses all permission checks
     * including CONFIG_OPERCMDS and PRIV_OPMODE. This is the correct path
     * for services-level mode changes. */
    modebuf_init(&mbuf, sptr, cptr, chptr,
                 (MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER |
                  MODEBUF_DEST_OPMODE  | MODEBUF_DEST_LOG));
    mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
               (MODE_PARSE_SET | MODE_PARSE_FORCE), NULL);
    modebuf_flush(&mbuf);
    return 0;
  }

  /* User mode */
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SAMODE on %C: %s", sptr, acptr, parv[2]);
  if (MyUser(acptr)) {
    char *param[4];
    param[0] = cli_name(acptr); param[1] = cli_name(acptr);
    param[2] = parv[2]; param[3] = NULL;
    set_user_mode(acptr, acptr, 3, param, ALLOWMODES_ANY | ALLOWMODES_SAMODE);
  } else {
    sendcmdto_serv_butone(&me, CMD_SAMODE, cptr, "%C %s", acptr, parv[2]);
  }
  return 0;
}

int ms_samode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  struct Channel *chptr;
  struct ModeBuf mbuf;

  if (parc < 3) return need_more_params(sptr, "SAMODE");
  if (!s2s_sa_authorized(sptr, "SAMODE")) return 0;

  /* Channel mode from server */
  if (IsChannelName(parv[1])) {
    if (!(chptr = FindChannel(parv[1])))
      return 0;

    modebuf_init(&mbuf, sptr, cptr, chptr,
                 (MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER |
                  MODEBUF_DEST_OPMODE  | MODEBUF_DEST_LOG));
    mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
               (MODE_PARSE_SET | MODE_PARSE_FORCE), NULL);
    modebuf_flush(&mbuf);
    return 0;
  }

  /* User mode from server */
  if (!(acptr = findNUser(parv[1]))) return 0;
  if (MyUser(acptr)) {
    char *param[4];
    param[0] = cli_name(acptr); param[1] = cli_name(acptr);
    param[2] = parv[2]; param[3] = NULL;
    set_user_mode(acptr, acptr, 3, param, ALLOWMODES_ANY | ALLOWMODES_SAMODE);
  } else
    sendcmdto_serv_butone(sptr, CMD_SAMODE, cptr, "%s %s", parv[1], parv[2]);
  return 0;
}

/* ================================================================
 * SAQUIT — Force a user to disconnect
 * ================================================================ */

int mo_saquit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *comment;
  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 2) return need_more_params(sptr, "SAQUIT");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  comment = (parc > 2 && !BadPtr(parv[parc - 1])) ? parv[parc - 1] : "Quit";
  sendto_opmask_butone(0, SNO_SACMD, "%C used SAQUIT on %C (%s)", sptr, acptr, comment);
  if (MyConnect(acptr))
    return exit_client_msg(acptr, acptr, acptr, "%s", comment);
  sendcmdto_serv_butone(&me, CMD_SAQUIT, cptr, "%C :%s", acptr, comment);
  return 0;
}

int ms_saquit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *comment;
  if (parc < 2) return need_more_params(sptr, "SAQUIT");
  if (!s2s_sa_authorized(sptr, "SAQUIT")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  comment = (parc > 2 && !BadPtr(parv[parc - 1])) ? parv[parc - 1] : "Quit";
  if (MyConnect(acptr))
    return exit_client_msg(acptr, acptr, acptr, "%s", comment);
  if (parc > 2)
    sendcmdto_serv_butone(sptr, CMD_SAQUIT, cptr, "%C :%s", acptr, comment);
  else
    sendcmdto_serv_butone(sptr, CMD_SAQUIT, cptr, "%C", acptr);
  return 0;
}

/* ================================================================
 * SATOPIC — Force a topic change
 * ================================================================ */

int mo_satopic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SATOPIC");
  if (!(chptr = FindChannel(parv[1])))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SATOPIC on %s: %s",
                        sptr, chptr->chname, parv[parc - 1]);
  ircd_strncpy(chptr->topic, parv[parc - 1], TOPICLEN);
  ircd_strncpy(chptr->topic_nick, cli_name(sptr), NICKLEN);
  chptr->topic_time = TStime();
  sendcmdto_channel_butserv_butone(sptr, CMD_TOPIC, chptr, NULL, 0,
                                    "%H :%s", chptr, chptr->topic);
  sendcmdto_serv_butone(sptr, CMD_TOPIC, cptr, "%H %s %Tu %Tu :%s", chptr,
                         chptr->topic_nick, chptr->creationtime,
                         chptr->topic_time, chptr->topic);
  return 0;
}

/* ================================================================
 * SAWHOIS — Set/clear custom WHOIS line
 * ================================================================ */

int mo_sawhois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *swhois;
  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 2) return need_more_params(sptr, "SAWHOIS");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  swhois = (parc > 2 && !EmptyString(parv[2])) ? parv[2] : "";
  sendto_opmask_butone(0, SNO_SACMD, "%C used SAWHOIS on %C: %s",
                        sptr, acptr, EmptyString(swhois) ? "(cleared)" : swhois);
  ircd_strncpy(cli_user(acptr)->swhois, swhois, BUFSIZE);
  if (!EmptyString(swhois))
    sendcmdto_serv_butone(&me, CMD_SAWHOIS, cptr, "%C :%s", acptr, swhois);
  else
    sendcmdto_serv_butone(&me, CMD_SAWHOIS, cptr, "%C", acptr);
  return 0;
}

int ms_sawhois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *swhois = "";
  if (!s2s_sa_authorized(sptr, "SAWHOIS")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  if (parc > 2 && !EmptyString(parv[2])) swhois = parv[2];
  ircd_strncpy(cli_user(acptr)->swhois, swhois, BUFSIZE + 1);
  if (!EmptyString(swhois))
    sendcmdto_serv_butone(sptr, CMD_SAWHOIS, cptr, "%C :%s", acptr, swhois);
  else
    sendcmdto_serv_butone(sptr, CMD_SAWHOIS, cptr, "%C", acptr);
  return 0;
}

/* ================================================================
 * SAIDENT — Force a user's ident/username change
 * ================================================================ */

int mo_saident(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char newident[USERLEN+1];
  char *s;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SAIDENT");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);
  if (strlen(parv[2]) > USERLEN)
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "SAIDENT");

  ircd_strncpy(newident, parv[2], USERLEN + 1);
  for (s = newident; *s; s++) {
    if (!IsUserChar(*s))
      return send_reply(sptr, ERR_NEEDMOREPARAMS, "SAIDENT");
  }

  sendto_opmask_butone(0, SNO_SACMD, "%C used SAIDENT to change %C ident to %s",
                        sptr, acptr, newident);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SAIDENT, cptr, "%C %s", acptr, newident);
    return 0;
  }
  ircd_strncpy(cli_user(acptr)->username, newident, USERLEN + 1);
  ircd_strncpy(cli_username(acptr), newident, USERLEN + 1);
  sendcmdto_serv_butone(&me, CMD_SAIDENT, cptr, "%C %s", acptr, cli_username(acptr));
  return 0;
}

int ms_saident(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char newident[USERLEN+1];
  char *s;

  if (parc < 3) return need_more_params(sptr, "SAIDENT");
  if (!s2s_sa_authorized(sptr, "SAIDENT")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  if (IsChannelService(acptr)) return 0;
  if (strlen(parv[2]) > USERLEN)
    return protocol_violation(sptr, "Ident too long in SAIDENT command");

  ircd_strncpy(newident, parv[2], USERLEN + 1);
  for (s = newident; *s; s++) {
    if (!IsUserChar(*s))
      return protocol_violation(sptr, "Illegal characters in SAIDENT ident");
  }

  ircd_strncpy(cli_user(acptr)->username, newident, USERLEN + 1);
  ircd_strncpy(cli_username(acptr), newident, USERLEN + 1);
  sendcmdto_serv_butone(sptr, CMD_SAIDENT, cptr, "%C %s", acptr, cli_username(acptr));
  return 0;
}

/* ================================================================
 * SAINFO — Force a user's realname (GECOS) change
 * ================================================================ */

int mo_sainfo(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SAINFO");
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_SACMD, "%C used SAINFO to change %C realname to: %s",
                        sptr, acptr, parv[parc - 1]);
  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SAINFO, cptr, "%C :%s", acptr, parv[parc - 1]);
    return 0;
  }
  ircd_strncpy(cli_info(acptr), parv[parc - 1], REALLEN);
  sendcmdto_serv_butone(&me, CMD_SAINFO, cptr, "%C :%s", acptr, cli_info(acptr));
  return 0;
}

int ms_sainfo(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (parc < 3) return need_more_params(sptr, "SAINFO");
  if (!s2s_sa_authorized(sptr, "SAINFO")) return 0;
  if (!(acptr = findNUser(parv[1]))) return 0;
  ircd_strncpy(cli_info(acptr), parv[parc - 1], REALLEN);
  sendcmdto_serv_butone(sptr, CMD_SAINFO, cptr, "%C :%s", acptr, acptr->cli_info);
  return 0;
}

/* ================================================================
 * SANOOP — Toggle NOOP mode on a server
 * ================================================================ */

int mo_sanoop(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);
  if (parc < 3) return need_more_params(sptr, "SANOOP");

  sendto_opmask_butone(0, SNO_SACMD, "%C used SANOOP on %s: %s", sptr, parv[1], parv[2]);

  if (!(acptr = FindNServer(parv[1]))) {
    if (!(acptr = FindServer(parv[1])))
      return send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);
  }
  if (!IsMe(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SANOOP, cptr, "%s %s", parv[1], parv[2]);
    return 0;
  }
  if (*parv[2] == '+') {
    SetServerNoop(&me);
    sendto_opmask_butone(0, SNO_OLDSNO, "NOOP enabled on this server");
  } else {
    ClearServerNoop(&me);
    sendto_opmask_butone(0, SNO_OLDSNO, "NOOP disabled on this server");
  }
  sendcmdto_serv_butone(&me, CMD_SANOOP, cptr, "%s %s", parv[1], parv[2]);
  return 0;
}

int ms_sanoop(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  if (parc < 3) return need_more_params(sptr, "SANOOP");
  if (!s2s_sa_authorized(sptr, "SANOOP")) return 0;
  if (!(acptr = FindNServer(parv[1]))) return 0;
  if (!IsMe(acptr)) {
    sendcmdto_serv_butone(sptr, CMD_SANOOP, cptr, "%s %s", parv[1], parv[2]);
    return 0;
  }
  if (*parv[2] == '+') {
    SetServerNoop(&me);
    sendto_opmask_butone(0, SNO_OLDSNO, "NOOP enabled by %s", cli_name(sptr));
  } else {
    ClearServerNoop(&me);
    sendto_opmask_butone(0, SNO_OLDSNO, "NOOP disabled by %s", cli_name(sptr));
  }
  sendcmdto_serv_butone(sptr, CMD_SANOOP, cptr, "%s %s", parv[1], parv[2]);
  return 0;
}
