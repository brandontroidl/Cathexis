/*
 * ircd_batch.c — IRCv3 batch and labeled-response for Cathexis
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
#include "config.h"
#include "ircd_batch.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_string.h"
#include "send.h"

#include <string.h>

/* ── Batch ──────────────────────────────────────────────── */

void batch_generate_ref(char *buf, size_t len)
{
  static const char chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static unsigned int ctr = 0;
  unsigned int val = (unsigned int)CurrentTime ^ (++ctr * 2654435761u);
  size_t i;
  for (i = 0; i < len - 1 && i < BATCH_REFLEN; i++) {
    buf[i] = chars[val % 62];
    val = val * 1103515245 + 12345;
  }
  buf[i] = '\0';
}

void batch_start(struct Client *to, const char *ref, const char *type,
                 const char *args)
{
  if (!to || !ref || !type || !CapActive(to, CAP_BATCH))
    return;
  if (args && *args)
    sendrawto_one(to, "BATCH +%s %s %s", ref, type, args);
  else
    sendrawto_one(to, "BATCH +%s %s", ref, type);
}

void batch_end(struct Client *to, const char *ref)
{
  if (!to || !ref || !CapActive(to, CAP_BATCH))
    return;
  sendrawto_one(to, "BATCH -%s", ref);
}

/* ── Labeled-Response ───────────────────────────────────── */

void label_set_pending(struct Client *cptr, const char *label)
{
  if (!cptr || !label || !MyConnect(cptr))
    return;
  ircd_strncpy(cli_label(cptr), label, sizeof(cli_label(cptr)) - 1);
  cli_label(cptr)[sizeof(cli_label(cptr)) - 1] = '\0';
}
