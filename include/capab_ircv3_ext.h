/*
 * IRC - Internet Relay Chat, include/capab_ircv3_ext.h
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
 */
#ifndef INCLUDED_capab_ircv3_ext_h
#define INCLUDED_capab_ircv3_ext_h

#define CAP_CHATHISTORY     0x00100000
#define CAP_READMARKER      0x00200000
#define CAP_PREAWAY         0x00400000
#define CAP_STDREPLY        0x00800000
#define CAP_SETNAME         0x01000000
#define CAP_LABELEDRESP     0x02000000
#define CAP_ECHOMSG         0x04000000
#define CAP_BATCH           0x08000000
#define CAP_ACCOUNTTAG      0x10000000
#define CAP_MSGTAGS         0x20000000
#define CAP_CHGHOST         0x40000000  /**< chghost */
#define CAP_INVITENOTIFY    0x80000000  /**< invite-notify */
#define CAP_MONITOR_CAP     0x00000001  /**< monitor (client cap, separate namespace) */
#define CAP_STDREPLY        0x00000002  /**< standard-replies (FAIL/WARN/NOTE) */

#define SCAP_HMAC256        0x00000001
#define SCAP_PQKEX          0x00000002
#define SCAP_EXTACCOUNT     0x00000004
#define SCAP_SASL           0x00000008
#define SCAP_CHATHISTORY    0x00000010

#endif
