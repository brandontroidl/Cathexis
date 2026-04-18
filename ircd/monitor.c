/*
 * monitor.c — IRCv3 MONITOR for Cathexis
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
#include "monitor.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_user.h"
#include <string.h>

/* ── Global Nick Hash ───────────────────────────────────── */

#define MON_HASH_SIZE  1024
#define MON_HASH_MASK  (MON_HASH_SIZE - 1)

static struct MonitorNick *mon_hash[MON_HASH_SIZE];

static unsigned int mon_hashfn(const char *nick)
{
  unsigned int h = 0;
  for (; *nick; nick++)
    h = (h << 4) + ToLower(*nick);
  return h & MON_HASH_MASK;
}

static struct MonitorNick *mon_find(const char *nick)
{
  struct MonitorNick *mn;
  for (mn = mon_hash[mon_hashfn(nick)]; mn; mn = mn->mn_next)
    if (0 == ircd_strcmp(mn->mn_nick, nick))
      return mn;
  return NULL;
}

static struct MonitorNick *mon_create(const char *nick)
{
  unsigned int b = mon_hashfn(nick);
  struct MonitorNick *mn = (struct MonitorNick *)MyCalloc(1, sizeof(*mn));
  ircd_strncpy(mn->mn_nick, nick, NICKLEN);
  mn->mn_next = mon_hash[b];
  mon_hash[b] = mn;
  return mn;
}

static void mon_remove(struct MonitorNick *mn)
{
  unsigned int b = mon_hashfn(mn->mn_nick);
  struct MonitorNick **pp;
  for (pp = &mon_hash[b]; *pp; pp = &(*pp)->mn_next)
    if (*pp == mn) { *pp = mn->mn_next; MyFree(mn); return; }
}

/* ── Watcher Links ──────────────────────────────────────── */

static int watcher_has(struct MonitorNick *mn, struct Client *c)
{
  struct SLink *lp;
  for (lp = mn->mn_watchers; lp; lp = lp->next)
    if (lp->value.cptr == c) return 1;
  return 0;
}

static void watcher_add(struct MonitorNick *mn, struct Client *c)
{
  struct SLink *lp = make_link();
  lp->value.cptr = c;
  lp->next = mn->mn_watchers;
  mn->mn_watchers = lp;
}

/* Remove watcher; returns 1 if list now empty. */
static int watcher_del(struct MonitorNick *mn, struct Client *c)
{
  struct SLink **pp, *lp;
  for (pp = &mn->mn_watchers; *pp; pp = &(*pp)->next)
    if ((*pp)->value.cptr == c) {
      lp = *pp; *pp = lp->next; free_link(lp);
      return mn->mn_watchers == NULL;
    }
  return 0;
}

/* ── Per-Client List (side hash) ────────────────────────── */

#define CLI_HASH_SIZE  512
#define CLI_HASH_MASK  (CLI_HASH_SIZE - 1)

struct CliMon {
  struct Client      *client;
  struct MonitorEntry *list;
  unsigned int        count;
  struct CliMon      *next;
};

static struct CliMon *cli_hash[CLI_HASH_SIZE];

static unsigned int cli_hashfn(struct Client *c)
{ return ((unsigned long)c >> 4) & CLI_HASH_MASK; }

static struct CliMon *cli_find(struct Client *c)
{
  struct CliMon *h;
  for (h = cli_hash[cli_hashfn(c)]; h; h = h->next)
    if (h->client == c) return h;
  return NULL;
}

static struct CliMon *cli_create(struct Client *c)
{
  unsigned int b = cli_hashfn(c);
  struct CliMon *h = (struct CliMon *)MyCalloc(1, sizeof(*h));
  h->client = c;
  h->next = cli_hash[b];
  cli_hash[b] = h;
  return h;
}

static void cli_destroy(struct CliMon *h)
{
  unsigned int b = cli_hashfn(h->client);
  struct CliMon **pp;
  for (pp = &cli_hash[b]; *pp; pp = &(*pp)->next)
    if (*pp == h) { *pp = h->next; MyFree(h); return; }
}

/* ── Public API ─────────────────────────────────────────── */

void monitor_init(void)
{
  memset(mon_hash, 0, sizeof(mon_hash));
  memset(cli_hash, 0, sizeof(cli_hash));
}

int monitor_add(struct Client *cptr, const char *nick)
{
  struct CliMon *h;
  struct MonitorNick *mn;
  struct MonitorEntry *me;

  if (!cptr || !nick || !*nick)
    return -1;
  h = cli_find(cptr);
  if (!h) h = cli_create(cptr);
  if (h->count >= MONITOR_MAX)
    return -1;

  mn = mon_find(nick);
  if (!mn) mn = mon_create(nick);
  if (watcher_has(mn, cptr))
    return 1;

  watcher_add(mn, cptr);
  me = (struct MonitorEntry *)MyCalloc(1, sizeof(*me));
  me->me_mnode = mn;
  me->me_next = h->list;
  h->list = me;
  h->count++;
  return 0;
}

int monitor_del(struct Client *cptr, const char *nick)
{
  struct CliMon *h;
  struct MonitorNick *mn;
  struct MonitorEntry **pp, *me;

  if (!cptr || !nick) return -1;
  h = cli_find(cptr);
  if (!h) return -1;
  mn = mon_find(nick);
  if (!mn) return -1;

  for (pp = &h->list; *pp; pp = &(*pp)->me_next)
    if ((*pp)->me_mnode == mn) {
      me = *pp; *pp = me->me_next; h->count--; MyFree(me); break;
    }
  if (watcher_del(mn, cptr))
    mon_remove(mn);
  if (h->count == 0)
    cli_destroy(h);
  return 0;
}

void monitor_clear(struct Client *cptr)
{
  struct CliMon *h;
  struct MonitorEntry *me, *next;

  h = cli_find(cptr);
  if (!h) return;
  for (me = h->list; me; me = next) {
    next = me->me_next;
    if (me->me_mnode && watcher_del(me->me_mnode, cptr))
      mon_remove(me->me_mnode);
    MyFree(me);
  }
  cli_destroy(h);
}

void monitor_notify_online(const char *nick)
{
  struct MonitorNick *mn = mon_find(nick);
  struct SLink *lp;
  if (!mn) return;
  for (lp = mn->mn_watchers; lp; lp = lp->next)
    if (MyConnect(lp->value.cptr))
      send_reply(lp->value.cptr, RPL_MONONLINE, nick);
}

void monitor_notify_offline(const char *nick)
{
  struct MonitorNick *mn = mon_find(nick);
  struct SLink *lp;
  if (!mn) return;
  for (lp = mn->mn_watchers; lp; lp = lp->next)
    if (MyConnect(lp->value.cptr))
      send_reply(lp->value.cptr, RPL_MONOFFLINE, nick);
}

void monitor_list(struct Client *cptr)
{
  struct CliMon *h = cli_find(cptr);
  struct MonitorEntry *me;
  if (h)
    for (me = h->list; me; me = me->me_next)
      if (me->me_mnode)
        send_reply(cptr, RPL_MONLIST, me->me_mnode->mn_nick);
  send_reply(cptr, RPL_ENDOFMONLIST);
}

void monitor_status(struct Client *cptr)
{
  struct CliMon *h = cli_find(cptr);
  struct MonitorEntry *me;
  struct Client *acptr;
  if (!h) return;
  for (me = h->list; me; me = me->me_next) {
    if (!me->me_mnode) continue;
    acptr = FindUser(me->me_mnode->mn_nick);
    send_reply(cptr, acptr ? RPL_MONONLINE : RPL_MONOFFLINE,
               acptr ? cli_name(acptr) : me->me_mnode->mn_nick);
  }
}

void monitor_count_memory(size_t *count_out, size_t *bytes_out)
{
  size_t count = 0, bytes = 0;
  int i;
  struct MonitorNick *mn;
  for (i = 0; i < MON_HASH_SIZE; i++)
    for (mn = mon_hash[i]; mn; mn = mn->mn_next) {
      count++; bytes += sizeof(*mn);
    }
  if (count_out) *count_out = count;
  if (bytes_out) *bytes_out = bytes;
}

/** IRCv3 extended-monitor: notify MONITOR watchers of AWAY changes.
 * Only sent to watchers who have both CAP_EXTMONITOR and CAP_AWAYNOTIFY.
 * @param[in] cptr Client whose away status changed.
 */
void monitor_notify_away(struct Client *cptr)
{
  struct MonitorNick *mn;
  struct SLink *lp;

  if (!cptr)
    return;
  mn = mon_find(cli_name(cptr));
  if (!mn)
    return;
  for (lp = mn->mn_watchers; lp; lp = lp->next) {
    if (!MyConnect(lp->value.cptr))
      continue;
    if (!HasCap(lp->value.cptr, CAP_EXTMONITOR))
      continue;
    if (!HasCap(lp->value.cptr, CAP_AWAYNOTIFY))
      continue;
    if (cli_user(cptr) && cli_user(cptr)->away)
      sendcmdto_one(cptr, CMD_AWAY, lp->value.cptr, ":%s",
                    cli_user(cptr)->away);
    else
      sendcmdto_one(cptr, CMD_AWAY, lp->value.cptr, "");
  }
}

/** IRCv3 extended-monitor: notify MONITOR watchers of ACCOUNT changes.
 * Only sent to watchers who have both CAP_EXTMONITOR and CAP_ACCNOTIFY.
 * @param[in] cptr Client whose account changed.
 */
void monitor_notify_account(struct Client *cptr)
{
  struct MonitorNick *mn;
  struct SLink *lp;
  const char *account;

  if (!cptr)
    return;
  mn = mon_find(cli_name(cptr));
  if (!mn)
    return;
  account = (cli_user(cptr) && cli_user(cptr)->account[0])
            ? cli_user(cptr)->account : "*";
  for (lp = mn->mn_watchers; lp; lp = lp->next) {
    if (!MyConnect(lp->value.cptr))
      continue;
    if (!HasCap(lp->value.cptr, CAP_EXTMONITOR))
      continue;
    if (!HasCap(lp->value.cptr, CAP_ACCNOTIFY))
      continue;
    sendcmdto_one(cptr, CMD_ACCOUNT, lp->value.cptr, "%s", account);
  }
}

/** IRCv3 extended-monitor: notify MONITOR watchers of SETNAME changes.
 * Only sent to watchers who have both CAP_EXTMONITOR and CAP_SETNAME.
 * @param[in] cptr Client whose realname changed.
 */
void monitor_notify_setname(struct Client *cptr)
{
  struct MonitorNick *mn;
  struct SLink *lp;

  if (!cptr)
    return;
  mn = mon_find(cli_name(cptr));
  if (!mn)
    return;
  for (lp = mn->mn_watchers; lp; lp = lp->next) {
    if (!MyConnect(lp->value.cptr))
      continue;
    if (!HasCap(lp->value.cptr, CAP_EXTMONITOR))
      continue;
    if (!HasCap(lp->value.cptr, CAP_SETNAME))
      continue;
    sendcmdto_one(cptr, CMD_SETNAME, lp->value.cptr, ":%s",
                  cli_info(cptr));
  }
}

/** IRCv3 extended-monitor: notify MONITOR watchers of CHGHOST changes.
 * Only sent to watchers who have both CAP_EXTMONITOR and CAP_CHGHOST.
 * @param[in] cptr Client whose host changed.
 */
void monitor_notify_chghost(struct Client *cptr)
{
  struct MonitorNick *mn;
  struct SLink *lp;

  if (!cptr || !cli_user(cptr))
    return;
  mn = mon_find(cli_name(cptr));
  if (!mn)
    return;
  for (lp = mn->mn_watchers; lp; lp = lp->next) {
    if (!MyConnect(lp->value.cptr))
      continue;
    if (!HasCap(lp->value.cptr, CAP_EXTMONITOR))
      continue;
    if (!HasCap(lp->value.cptr, CAP_CHGHOST))
      continue;
    sendrawto_one(lp->value.cptr, ":%s!%s@%s CHGHOST %s %s",
                  cli_name(cptr), cli_user(cptr)->username,
                  cli_user(cptr)->host, cli_user(cptr)->username,
                  cli_user(cptr)->host);
  }
}
