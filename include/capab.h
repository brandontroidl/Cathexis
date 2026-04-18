#ifndef INCLUDED_capab_h
#define INCLUDED_capab_h
/*
 * IRC - Internet Relay Chat, include/capab.h
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Interface and public definitions for capabilities extension
 */

#ifndef INCLUDED_client_h
#include "client.h"
#endif

#define CAPFL_HIDDEN	0x0001	/**< Do not advertize this capability */
#define CAPFL_PROHIBIT	0x0002	/**< Client may not set this capability */
#define CAPFL_PROTO	0x0004	/**< Cap must be acknowledged by client */
#define CAPFL_STICKY    0x0008  /**< Cap may not be cleared once set */

#define CAPLIST	\
	_CAP(USERPFX, 0, "undernet.org/userpfx")

/** Client capabilities - IRCv3 */
enum Capab {
#define _CAP(cap, flags, name, feat)	CAP_ ## cap
  _CAP(NONE, CAPFL_HIDDEN|CAPFL_PROHIBIT, "none", 0),
  /* IRCv3.1 capabilities */
  _CAP(NAMESX, 0, "multi-prefix", 0),
  _CAP(UHNAMES, 0, "userhost-in-names", 0),
  _CAP(EXTJOIN, 0, "extended-join", 0),
  _CAP(AWAYNOTIFY, 0, "away-notify", 0),
  _CAP(ACCNOTIFY, 0, "account-notify", 0),
  _CAP(SASL, 0, "sasl", 0),
#ifdef USE_SSL
  _CAP(TLS, 0, "tls", 0),
#endif
  /* IRCv3.2+ capabilities */
  _CAP(CAPNOTIFY, 0, "cap-notify", 0),
  _CAP(SERVERTIME, 0, "server-time", 0),
  _CAP(ACCOUNTTAG, 0, "account-tag", 0),
  _CAP(MSGTAGS, 0, "message-tags", 0),
  _CAP(ECHOMSG, 0, "echo-message", 0),
  _CAP(INVITENOTIFY, 0, "invite-notify", 0),
  _CAP(CHGHOST, 0, "chghost", 0),
  _CAP(SETNAME, 0, "setname", 0),
  _CAP(BATCH, 0, "batch", 0),
  _CAP(LABELEDRESP, 0, "labeled-response", 0),
  _CAP(STDREPLIES, 0, "standard-replies", 0),
  _CAP(STS, CAPFL_PROHIBIT, "sts", 0),
  /* IRCv3 ratified specs — additional */
  _CAP(MSGID, 0, "message-ids", 0),
  _CAP(MONITOR, 0, "monitor", 0),
  /* IRCv3 draft specs */
  _CAP(BOTMODE, 0, "draft/bot-mode", 0),
  _CAP(CHATHISTORY, 0, "draft/chathistory", 0),
  _CAP(TYPING, 0, "draft/typing", 0),
  _CAP(NOIMPLICITNAMES, 0, "no-implicit-names", 0),
  _CAP(CHANNELRENAME, 0, "draft/channel-rename", 0),
  _CAP(READMARKER, 0, "draft/read-marker", 0),
  _CAP(MULTILINE, 0, "draft/multiline", 0),
  _CAP(PREAWAY, 0, "draft/pre-away", 0),
  _CAP(ACCREG, 0, "draft/account-registration", 0),
  _CAP(EXTMONITOR, 0, "draft/extended-monitor", 0),
  _CAP(MSGREDACT, 0, "draft/message-redaction", 0),
/*  CAPLIST, */
#undef _CAP
  _CAP_LAST_CAP
};

DECLARE_FLAGSET(CapSet, _CAP_LAST_CAP);

#define CapHas(cs, cap)	FlagHas(cs, cap)
#define CapSet(cs, cap)	FlagSet(cs, cap)
#define CapClr(cs, cap)	FlagClr(cs, cap)

/** CAP 302 version tracking */
#define CAP_VERSION_NONE  0
#define CAP_VERSION_302   302

extern void client_check_caps(struct Client *client, struct Client *replyto);

#endif /* INCLUDED_capab_h */
