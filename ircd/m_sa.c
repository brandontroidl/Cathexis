/*
 * IRC - Internet Relay Chat, ircd/m_sa.c
 * Copyright (C) 2026 Cathexis Development
 *
 * SA* (Server Admin) commands for Network Administrators.
 * These are the oper-facing equivalents of the SVS* S2S protocol.
 * All require PRIV_NETADMIN (+N).
 *
 * Commands: SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, SATOPIC, SAWHOIS
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
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

/*
 * mo_sajoin - SAJOIN <nick> <#channel>
 *
 * Forces a user to join one or more channels.
 * Requires PRIV_NETADMIN.
 */
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

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAJOIN to force %C into %s",
                        sptr, acptr, parv[2]);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SVSJOIN, cptr, "%C %s", acptr, parv[2]);
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
      if (chptr->users == 0 && !chptr->mode.apass[0] && !(chptr->mode.exmode & EXMODE_PERSIST)) {
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

/*
 * mo_sapart - SAPART <nick> <#channel> [:<reason>]
 *
 * Forces a user to part one or more channels.
 * Requires PRIV_NETADMIN.
 */
int mo_sapart(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  char *p = 0;
  char *name;
  char *comment = (parc > 3 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;
  char chanbuf[BUFSIZE];

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 3)
    return need_more_params(sptr, "SAPART");

  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAPART to force %C from %s",
                        sptr, acptr, parv[2]);

  if (!MyUser(acptr)) {
    if (comment)
      sendcmdto_serv_butone(&me, CMD_SVSPART, cptr, "%C %s :%s", acptr, parv[2], comment);
    else
      sendcmdto_serv_butone(&me, CMD_SVSPART, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }

  ircd_strncpy(chanbuf, parv[2], sizeof(chanbuf) - 1);

  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, comment, 0);

  for (name = ircd_strtok(&p, chanbuf, ","); name;
       name = ircd_strtok(&p, 0, ",")) {
    unsigned int flags = 0;

    chptr = get_channel(acptr, name, CGT_NO_CREATE);
    if (!chptr || !(member = find_member_link(chptr, acptr)))
      continue;

    if (IsZombie(member))
      flags |= CHFL_ZOMBIE;
    if (IsDelayedJoin(member))
      flags |= CHFL_DELAYED;

    joinbuf_join(&parts, chptr, flags);
  }

  return joinbuf_flush(&parts);
}

/*
 * mo_sanick - SANICK <nick> <newnick>
 *
 * Forces a user to change their nickname.
 * Requires PRIV_NETADMIN.
 */
int mo_sanick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Client *acptr2;
  char nick[NICKLEN + 2];
  char *arg;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 3)
    return need_more_params(sptr, "SANICK");

  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  if (ircd_strcmp(cli_name(acptr), parv[2]) == 0)
    return 0;

  arg = parv[2];
  if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
    arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

  ircd_strncpy(nick, arg, sizeof(nick) - 1);
  nick[sizeof(nick) - 1] = '\0';

  if (0 == do_nick_name(nick)) {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, parv[2]);
    return 0;
  }

  if (isNickJuped(nick)) {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    return 0;
  }

  if ((acptr2 = SeekClient(nick))) {
    if (acptr != acptr2) {
      send_reply(sptr, ERR_NICKNAMEINUSE, nick);
      return 0;
    }
  }

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SANICK to change %C to %s",
                        sptr, acptr, nick);

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(&me, CMD_SVSNICK, cptr, "%C %s", acptr, nick);
    return 0;
  }

  set_nick_name(acptr, acptr, nick, parc, parv, 1);
  sendcmdto_serv_butone(&me, CMD_SVSNICK, cptr, "%C %s", acptr, nick);
  return 0;
}

/*
 * mo_samode - SAMODE <nick|#channel> <modes> [params]
 *
 * Forces mode changes on a user or channel.
 * Requires PRIV_NETADMIN.
 */
int mo_samode(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 3)
    return need_more_params(sptr, "SAMODE");

  /* Channel mode - delegate to OPMODE logic */
  if (IsChannelName(parv[1])) {
    sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAMODE on %s: %s",
                          sptr, parv[1], parv[2]);
    /* Reuse the OPMODE path which already handles channel modes with override */
    parv[0] = cli_name(sptr);
    return mo_opmode(cptr, sptr, parc, parv);
  }

  /* User mode */
  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAMODE on %C: %s",
                        sptr, acptr, parv[2]);

  if (MyUser(acptr)) {
    char *param[4];
    param[0] = cli_name(acptr);
    param[1] = cli_name(acptr);
    param[2] = parv[2];
    param[3] = NULL;
    set_user_mode(acptr, acptr, 3, param, ALLOWMODES_ANY | ALLOWMODES_SVSMODE);
  } else {
    sendcmdto_serv_butone(&me, CMD_SVSMODE, cptr, "%C %s", acptr, parv[2]);
  }

  return 0;
}

/*
 * mo_saquit - SAQUIT <nick> [:<reason>]
 *
 * Forces a user to disconnect.
 * Requires PRIV_NETADMIN.
 */
int mo_saquit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *comment;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2)
    return need_more_params(sptr, "SAQUIT");

  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  comment = (parc > 2 && !BadPtr(parv[parc - 1])) ? parv[parc - 1] : "Quit";

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAQUIT on %C (%s)",
                        sptr, acptr, comment);

  if (MyConnect(acptr)) {
    return exit_client_msg(acptr, acptr, acptr, "%s", comment);
  }

  sendcmdto_serv_butone(&me, CMD_SVSQUIT, cptr, "%C :%s", acptr, comment);
  return 0;
}

/*
 * mo_satopic - SATOPIC <#channel> :<topic>
 *
 * Forces a topic change on a channel, bypassing +t restrictions.
 * Requires PRIV_NETADMIN.
 */
int mo_satopic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *topic;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 3)
    return need_more_params(sptr, "SATOPIC");

  if (!(chptr = FindChannel(parv[1])))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

  topic = parv[parc - 1];

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SATOPIC on %s",
                        sptr, chptr->chname);

  ircd_strncpy(chptr->topic, topic, TOPICLEN);
  ircd_strncpy(chptr->topic_nick, cli_name(sptr), NICKLEN);
  chptr->topic_time = TStime();

  sendcmdto_channel_butserv_butone(sptr, CMD_TOPIC, chptr, NULL, 0,
                                    "%H :%s", chptr, chptr->topic);
  sendcmdto_serv_butone(sptr, CMD_TOPIC, cptr, "%H %s %Tu %Tu :%s", chptr,
                         chptr->topic_nick, chptr->creationtime,
                         chptr->topic_time, chptr->topic);
  return 0;
}

/*
 * mo_sawhois - SAWHOIS <nick> [:<text>]
 *
 * Sets or clears a custom WHOIS line for a user.
 * Requires PRIV_NETADMIN.
 */
int mo_sawhois(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *swhois;

  if (!HasPriv(sptr, PRIV_NETADMIN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2)
    return need_more_params(sptr, "SAWHOIS");

  if (!(acptr = FindUser(parv[1])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

  swhois = (parc > 2 && !EmptyString(parv[2])) ? parv[2] : "";

  sendto_opmask_butone(0, SNO_OLDSNO, "%C used SAWHOIS on %C: %s",
                        sptr, acptr, EmptyString(swhois) ? "(cleared)" : swhois);

  ircd_strncpy(cli_user(acptr)->swhois, swhois, BUFSIZE);

  if (!EmptyString(swhois))
    sendcmdto_serv_butone(&me, CMD_SWHOIS, cptr, "%C :%s", acptr, swhois);
  else
    sendcmdto_serv_butone(&me, CMD_SWHOIS, cptr, "%C", acptr);

  return 0;
}
