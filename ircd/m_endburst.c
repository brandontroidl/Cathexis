/*
 * IRC - Internet Relay Chat, ircd/m_end_of_burst.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 *
 * $Id: m_endburst.c 1411 2005-05-30 13:14:54Z entrope $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "send.h"

#ifdef USE_SSL
#include "s2s_crypto.h"
#endif

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * ms_end_of_burst - server message handler
 * - Added Xorath 6-14-96, rewritten by Run 24-7-96
 * - and fixed by record and Kev 8/1/96
 * - and really fixed by Run 15/8/96 :p
 * This the last message in a net.burst.
 * It clears a flag for the server sending the burst.
 *
 * As of 10.11, to fix a bug in the way BURST is processed, it also
 * makes sure empty channels are deleted
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chan, *next_chan;

  assert(0 != cptr);
  assert(0 != sptr);

  sendto_opmask_butone(0, SNO_NETWORK, "Completed net.burst from %C.", 
  	sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST, cptr, "");
  ClearBurst(sptr);
  SetBurstAck(sptr);
  if (MyConnect(sptr))
    sendcmdto_one(&me, CMD_END_OF_BURST_ACK, sptr, "");

  /* Count through channels... */
  for (chan = GlobalChannelList; chan; chan = next_chan) {
    next_chan = chan->next;
    if (!chan->members && (chan->mode.mode & MODE_BURSTADDED)) {
      /* Newly empty channel, schedule it for removal. */
      chan->mode.mode &= ~MODE_BURSTADDED;
      sub1_from_channel(chan);
   } else
      chan->mode.mode &= ~MODE_BURSTADDED;
  }

#ifdef USE_SSL
  /* S2S_CSYNC (Cathexis 1.6.0+): after cleaning up BURSTADDED flags, emit
   * one CHASH line per populated channel so the originating peer can
   * compare against its own hash. This runs only on locally-connected
   * peers (MyConnect) so a chained burst through multiple hops doesn't
   * re-emit hashes at every forward. */
  if (MyConnect(sptr) && feature_bool(FEAT_S2S_CSYNC)) {
    char hexhash[129];
    int emitted = 0;
    int limit = feature_int(FEAT_S2S_CSYNC_MAX_PER_SECOND);
    if (limit <= 0) limit = 50;

    for (chan = GlobalChannelList; chan; chan = chan->next) {
      /* Skip empty channels — nothing to synchronize */
      if (!chan->members)
        continue;
      /* Skip local-only channels (& prefix) — they aren't network state */
      if (chan->chname[0] == '&')
        continue;
      if (emitted >= limit) {
        /* Defer remaining hashes to avoid overwhelming the peer. A
         * follow-on pass after the current second can pick them up; for
         * now this is a conservative circuit-breaker. */
        sendto_opmask_butone(0, SNO_NETWORK,
          "CHASH: emitted %d hashes to %C, deferring %s remaining channels (rate-limit)",
          emitted, sptr, chan->chname);
        break;
      }
      if (s2s_channel_hash(hexhash, chan) < 0)
        continue;
      sendcmdto_one(&me, CMD_CHASH, sptr, "%s %s", chan->chname, hexhash);
      emitted++;
    }

    if (emitted > 0) {
      Debug((DEBUG_DEBUG, "CHASH: sent %d channel hashes to %s",
             emitted, cli_name(sptr)));
    }
  }
#endif

  return 0;
}

/*
 * ms_end_of_burst_ack - server message handler
 *
 * This the acknowledge message of the `END_OF_BURST' message.
 * It clears a flag for the server receiving the burst.
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst_ack(struct Client *cptr, struct Client *sptr, int parc, char **parv)
{
  if (!IsServer(sptr))
    return 0;

  sendto_opmask_butone(0, SNO_NETWORK, "%C acknowledged end of net.burst.",
		       sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST_ACK, cptr, "");
  ClearBurstAck(sptr);

  return 0;
}
