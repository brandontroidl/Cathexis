/*
 * IRC - Internet Relay Chat, ircd/m_chash.c
 * Copyright (C) 2026 Cathexis Development Team
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
/** @file
 * @brief Handler for the CHASH post-EOB channel-state verification message.
 *
 * CHASH is a server-only command used to catch silent channel state
 * divergence after a netsplit/netjoin or during a normal BURST. Each
 * server computes s2s_channel_hash() over every channel it burst, and
 * after EOB emits one CHASH line per channel to its uplink:
 *
 *     :<sid> CH #channel <hexhash>
 *
 * The peer compares against its own hash. On mismatch it logs a WARN
 * and optionally requests a re-burst by sending CHASH back with an
 * empty hash argument:
 *
 *     :<sid> CH #channel :
 *
 * Rate limited via FEAT_S2S_CSYNC_MAX_PER_SECOND to prevent CHASH
 * storms after a widescale netsplit rejoin.
 */
#include "config.h"

#ifdef USE_SSL

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s2s_crypto.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

#include <string.h>
#include <time.h>

/** Rate-limit state for CHASH processing. Incremented on each CHASH we
 *  accept from any peer; reset each second. When we exceed
 *  FEAT_S2S_CSYNC_MAX_PER_SECOND, additional CHASH lines are dropped
 *  silently (the peer's own rate-limit should keep it sane). */
static struct {
  time_t         window_start;
  unsigned int   count;
} chash_ratelimit = { 0, 0 };

static int chash_allow(void)
{
  time_t now = CurrentTime;
  int limit;

  if (now != chash_ratelimit.window_start) {
    chash_ratelimit.window_start = now;
    chash_ratelimit.count = 0;
  }

  limit = feature_int(FEAT_S2S_CSYNC_MAX_PER_SECOND);
  if (limit <= 0) limit = 50;

  if (chash_ratelimit.count >= (unsigned)limit)
    return 0;

  chash_ratelimit.count++;
  return 1;
}

/** ms_chash - CHASH message handler for servers.
 *
 * parv[0] = sender prefix (propagated)
 * parv[1] = channel name
 * parv[2] = SHA3-512 hex hash of peer's channel state, or empty for resync
 *           request
 */
int ms_chash(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  char local_hash[129];
  const char *peer_hash;
  const char *chname;

  if (!feature_bool(FEAT_S2S_CSYNC))
    return 0;                     /* silently ignore when disabled */

  if (parc < 3)
    return need_more_params(sptr, "CHASH");

  chname    = parv[1];
  peer_hash = parv[2];

  if (!chash_allow()) {
    Debug((DEBUG_DEBUG, "CHASH rate-limit dropping %s from %s",
           chname, cli_name(sptr)));
    return 0;
  }

  chptr = FindChannel(chname);
  if (!chptr) {
    /* Peer has the channel, we don't — our side is missing it. Log and
     * drop. A full re-burst would fix this but we don't initiate one
     * from here; the peer's next message on this channel will create it. */
    log_write(LS_NETWORK, L_INFO, 0,
              "CHASH: peer %s reports channel %s but we don't have it "
              "(silent desync, may recover organically)",
              cli_name(sptr), chname);
    return 0;
  }

  /* Empty hash = explicit resync request from peer */
  if (EmptyString(peer_hash)) {
    log_write(LS_NETWORK, L_INFO, 0,
              "CHASH: peer %s requested re-burst of %s",
              cli_name(sptr), chname);
    /* Re-burst would be triggered here. Current implementation is
     * detection-only; explicit re-burst scheduling lands in a future
     * patch so we don't risk burst storms on partial deployments. */
    return 0;
  }

  if (s2s_channel_hash(local_hash, chptr) < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "CHASH: failed to hash local state of %s", chname);
    return 0;
  }

  if (s2s_channel_verify(chptr, peer_hash)) {
    Debug((DEBUG_DEBUG, "CHASH %s: OK (matches peer %s)",
           chname, cli_name(sptr)));
    return 0;
  }

  log_write(LS_NETWORK, L_WARNING, 0,
            "CHASH MISMATCH on %s from peer %s: local=%s peer=%s",
            chname, cli_name(sptr), local_hash, peer_hash);

  sendto_opmask_butone(0, SNO_NETWORK,
    "CHASH mismatch on %s from %s (local=%.16s... peer=%.16s...)",
    chname, cli_name(sptr), local_hash, peer_hash);

  /* Detection only. A future patch will optionally request a re-burst
   * here when FEAT_S2S_CSYNC_AUTO_RESYNC is TRUE. */
  return 0;
}

#else /* !USE_SSL */

/* Without OpenSSL the hash functions aren't available; CHASH becomes a no-op. */
int ms_chash(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  return 0;
}

#endif /* USE_SSL */
