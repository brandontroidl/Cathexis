/*
 * IRC - Internet Relay Chat, include/extban_ext.h
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
 * Extended ban type additions.
 */
#ifndef INCLUDED_extban_ext_h
#define INCLUDED_extban_ext_h

#define EBAN_SERVER     0x00000400  /**< ~s match server name */
#define EBAN_CERTFP     0x00000800  /**< ~f match TLS cert fingerprint */
#define EBAN_OPER       0x00001000  /**< ~o match IRC operators */
#define EBAN_REGNICK    0x00002000  /**< ~R match registered users */
#define EBAN_TEXTBAN    0x00000004  /**< ~T text/content ban */
#define EBAN_NOCTCP     0x00000008  /**< ~C block CTCPs */
#define EBAN_NONOTICE   0x00004000  /**< ~N block notices */

#endif /* INCLUDED_extban_ext_h */
