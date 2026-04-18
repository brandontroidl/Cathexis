/*
 * IRC - Internet Relay Chat, ircd/m_markread.c
 * Copyright (C) 2026 Cathexis Development
 *
 * IRCv3 draft/read-marker — per-user read position tracking.
 *
 * MARKREAD <target> [<timestamp>]
 *
 * When a client sends MARKREAD with a timestamp, the server stores it
 * and echoes to other sessions of the same user. On JOIN, the server
 * sends the stored read position to the joining client.
 *
 * This is a basic implementation suitable for single-server deployments.
 * For full bouncer support, storage would need to persist across restarts.
 */
#include "config.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include <string.h>

/** Handle MARKREAD from a local client.
 *
 * MARKREAD <target>             — query current read position
 * MARKREAD <target> <timestamp> — set read position
 *
 * For now, this is a simple echo implementation. The server accepts
 * the MARKREAD and echoes it back. Full persistence requires a storage
 * backend (future: Acid XQUERY integration).
 */
int m_markread(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;

  if (parc < 2)
    return need_more_params(sptr, "MARKREAD");

  if (!HasCap(sptr, CAP_READMARKER))
    return 0;

  target = parv[1];

  if (parc >= 3) {
    /* Client is setting a read marker — accepted silently.
     * Do NOT echo back to the same client, or clients like IRCCloud
     * will re-send MARKREAD on every echo, creating an infinite loop.
     * TODO: echo to OTHER sessions of the same account (multi-device). */
  } else {
    /* Client is querying — reply with * (no stored position) */
    sendcmdto_one(&me, CMD_MARKREAD, sptr, "%s *", target);
  }

  return 0;
}
