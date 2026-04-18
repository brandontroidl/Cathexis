/*
 * IRC - Internet Relay Chat, include/snomask_ext.h
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
 * Extended server notice mask types.
 */
#ifndef INCLUDED_snomask_ext_h
#define INCLUDED_snomask_ext_h

#define SNO_SHUN        0x100000  /**< S - shun add/remove/expire */
#define SNO_ZLINE       0x200000  /**< Z - Z-line add/remove/expire */
#define SNO_SASL        0x400000  /**< a - SASL auth success/failure */
#define SNO_SACMD       0x800000  /**< C - SA* command usage */
#define SNO_FLOOD       0x1000000 /**< F - flood/excess notices */
#define SNO_TLS         0x2000000 /**< T - TLS connection info */
#define SNO_ACCOUNT     0x4000000 /**< R - account registration/changes */
#define SNO_SPAMF       0x8000000 /**< P - spamfilter matches */

#endif /* INCLUDED_snomask_ext_h */
