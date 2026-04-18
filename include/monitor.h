/*
 * monitor.h — IRCv3 MONITOR notification list for Cathexis
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
 *
 * Global nick hash → watcher lists; per-client entry lists.
 * Notifications fired on nick change, connect, disconnect.
 */
#ifndef INCLUDED_monitor_h
#define INCLUDED_monitor_h

#include "config.h"
#include "ircd_defs.h"
#include <stddef.h>

struct Client;
struct SLink;

#define MONITOR_MAX  128

struct MonitorNick {
  struct MonitorNick *mn_next;
  struct SLink       *mn_watchers;
  char                mn_nick[NICKLEN + 1];
};

struct MonitorEntry {
  struct MonitorEntry *me_next;
  struct MonitorNick  *me_mnode;
};

extern void monitor_init(void);
extern int  monitor_add(struct Client *cptr, const char *nick);
extern int  monitor_del(struct Client *cptr, const char *nick);
extern void monitor_clear(struct Client *cptr);
extern void monitor_notify_online(const char *nick);
extern void monitor_notify_offline(const char *nick);
extern void monitor_notify_away(struct Client *cptr);
extern void monitor_notify_account(struct Client *cptr);
extern void monitor_notify_chghost(struct Client *cptr);
extern void monitor_notify_setname(struct Client *cptr);
extern void monitor_list(struct Client *cptr);
extern void monitor_status(struct Client *cptr);
extern void monitor_count_memory(size_t *count_out, size_t *bytes_out);

#endif /* INCLUDED_monitor_h */
