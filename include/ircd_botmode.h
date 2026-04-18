/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * include/ircd_botmode.h — IRCv3 bot-mode (+B) support.
 *
 * Integration points:
 *   - client.h: Add FLAG_BOT to the flags enum
 *   - s_user.c: Handle +B/-B in set_user_mode()
 *   - whocmds.c: Show 'B' flag in WHO responses
 *   - s_misc.c: Show +B in WHOIS mode line
 *   - m_cap.c: Add "draft/bot-mode" to capab_list[]
 *   - send.c: msgtags_inject_for_source() checks FLAG_BOT
 */

#ifndef INCLUDED_ircd_botmode_h
#define INCLUDED_ircd_botmode_h

struct Client;

/** User mode character for bot identification */
#define UMODE_BOT 'B'

/** CAP name for bot-mode */
#define CAP_BOTMODE_NAME "draft/bot-mode"

/** Check if a client has bot mode set */
#define IsBotMode(x) HasFlag(x, FLAG_BOT)

/** Set bot mode on a client */
#define SetBotMode(x) SetFlag(x, FLAG_BOT)

/** Clear bot mode on a client */
#define ClearBotMode(x) ClrFlag(x, FLAG_BOT)

#endif /* INCLUDED_ircd_botmode_h */
