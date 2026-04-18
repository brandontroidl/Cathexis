/*
 * ircd_batch.h — IRCv3 batch and labeled-response support for Cathexis
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
#ifndef INCLUDED_ircd_batch_h
#define INCLUDED_ircd_batch_h

#include "client.h"

#define BATCH_REFLEN    24   /* Max batch reference tag length */
#define LABEL_MAXLEN    64   /* Max label length (IRCv3: 64 bytes) */

extern void batch_generate_ref(char *buf, size_t len);
extern void batch_start(struct Client *to, const char *ref,
                        const char *type, const char *args);
extern void batch_end(struct Client *to, const char *ref);
extern void label_set_pending(struct Client *cptr, const char *label);

#endif /* INCLUDED_ircd_batch_h */
