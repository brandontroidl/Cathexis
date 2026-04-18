/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
 * Copyright (C) 2026 Cathexis Development
 *
 * IRCv3 client-to-server BATCH — handles draft/multiline batches.
 *
 * When a client sends BATCH +ref draft/multiline #target, the server
 * buffers subsequent PRIVMSGs until BATCH -ref, then delivers the
 * complete batch to recipients.
 *
 * Recipients with draft/multiline CAP receive a proper batch.
 * Recipients without receive concatenated text as a single PRIVMSG.
 */
#include "config.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_batch.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include <string.h>
#include <stdlib.h>

#define ML_MAX_LINES  100
#define ML_MAX_BYTES  4096

/** Per-client multiline batch state. */
struct MultiBatch {
  struct Client  *owner;
  struct MultiBatch *next;
  char            ref[16];
  char            target[CHANNELLEN + 1];
  char           *lines[ML_MAX_LINES];
  int             nlines;
  int             total_bytes;
  int             active;
};

static struct MultiBatch *ml_list = NULL;

static struct MultiBatch *ml_find(struct Client *cptr)
{
  struct MultiBatch *mb;
  for (mb = ml_list; mb; mb = mb->next)
    if (mb->owner == cptr && mb->active)
      return mb;
  return NULL;
}

static struct MultiBatch *ml_create(struct Client *cptr, const char *ref,
                                     const char *target)
{
  struct MultiBatch *mb = MyCalloc(1, sizeof(*mb));
  mb->owner = cptr;
  ircd_strncpy(mb->ref, ref, sizeof(mb->ref) - 1);
  ircd_strncpy(mb->target, target, sizeof(mb->target) - 1);
  mb->active = 1;
  mb->next = ml_list;
  ml_list = mb;
  return mb;
}

static void ml_destroy(struct MultiBatch *mb)
{
  struct MultiBatch **pp;
  int i;
  for (i = 0; i < mb->nlines; i++)
    MyFree(mb->lines[i]);
  for (pp = &ml_list; *pp; pp = &(*pp)->next) {
    if (*pp == mb) { *pp = mb->next; break; }
  }
  MyFree(mb);
}

/** Called when a client disconnects — clean up any active batch. */
void ml_client_exit(struct Client *cptr)
{
  struct MultiBatch *mb = ml_find(cptr);
  if (mb) ml_destroy(mb);
}

/** Add a line to the active batch. Returns 0 on success. */
int ml_add_line(struct Client *cptr, const char *text)
{
  struct MultiBatch *mb = ml_find(cptr);
  int len;

  if (!mb) return -1;
  if (mb->nlines >= ML_MAX_LINES) return -1;

  len = strlen(text);
  if (mb->total_bytes + len + 1 > ML_MAX_BYTES) return -1;

  DupString(mb->lines[mb->nlines], text);
  mb->nlines++;
  mb->total_bytes += len + 1; /* +1 for \n separator */
  return 0;
}

/** Deliver a completed multiline batch to the target. */
static void ml_deliver(struct Client *sptr, struct MultiBatch *mb)
{
  struct Channel *chptr;
  struct Client *acptr;
  struct Membership *member;
  int is_channel;

  is_channel = IsChannelName(mb->target);

  if (is_channel) {
    chptr = FindChannel(mb->target);
    if (!chptr) return;
    if (!find_member_link(chptr, sptr)) return;

    for (member = chptr->members; member; member = member->next_member) {
      acptr = member->user;
      if (acptr == sptr && !HasCap(sptr, CAP_ECHOMSG))
        continue;
      if (!MyConnect(acptr))
        continue;

      if (HasCap(acptr, CAP_MULTILINE) && HasCap(acptr, CAP_BATCH)) {
        /* Send as batch */
        char ref[BATCH_REFLEN + 1];
        int i;
        batch_generate_ref(ref, sizeof(ref));
        batch_start(acptr, ref, "draft/multiline", mb->target);
        for (i = 0; i < mb->nlines; i++) {
          sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                        ref, cli_name(sptr),
                        cli_user(sptr) ? cli_user(sptr)->username : "*",
                        cli_user(sptr) ? cli_user(sptr)->host : "*",
                        mb->target, mb->lines[i]);
        }
        batch_end(acptr, ref);
      } else {
        /* Concatenate and send as single PRIVMSG */
        char combined[ML_MAX_BYTES + 1];
        int i, pos = 0;
        for (i = 0; i < mb->nlines && pos < ML_MAX_BYTES; i++) {
          int len = strlen(mb->lines[i]);
          if (pos + len + 1 > ML_MAX_BYTES) break;
          if (pos > 0) combined[pos++] = ' ';
          memcpy(combined + pos, mb->lines[i], len);
          pos += len;
        }
        combined[pos] = '\0';
        sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s",
                      mb->target, combined);
      }
    }
  } else {
    /* DM multiline */
    acptr = FindUser(mb->target);
    if (!acptr || !MyConnect(acptr)) return;

    if (HasCap(acptr, CAP_MULTILINE) && HasCap(acptr, CAP_BATCH)) {
      char ref[BATCH_REFLEN + 1];
      int i;
      batch_generate_ref(ref, sizeof(ref));
      batch_start(acptr, ref, "draft/multiline", mb->target);
      for (i = 0; i < mb->nlines; i++) {
        sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                      ref, cli_name(sptr),
                      cli_user(sptr) ? cli_user(sptr)->username : "*",
                      cli_user(sptr) ? cli_user(sptr)->host : "*",
                      mb->target, mb->lines[i]);
      }
      batch_end(acptr, ref);
    } else {
      char combined[ML_MAX_BYTES + 1];
      int i, pos = 0;
      for (i = 0; i < mb->nlines && pos < ML_MAX_BYTES; i++) {
        int len = strlen(mb->lines[i]);
        if (pos + len + 1 > ML_MAX_BYTES) break;
        if (pos > 0) combined[pos++] = ' ';
        memcpy(combined + pos, mb->lines[i], len);
        pos += len;
      }
      combined[pos] = '\0';
      sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%s :%s",
                    mb->target, combined);
    }
  }
}

/** Handle BATCH command from a local client.
 *
 * BATCH +<ref> draft/multiline <target>   — start batch
 * BATCH -<ref>                            — end batch
 */
int m_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *refarg;

  if (parc < 2)
    return need_more_params(sptr, "BATCH");

  refarg = parv[1];

  if (*refarg == '+') {
    /* Start a new batch */
    const char *ref = refarg + 1;
    const char *btype;
    const char *target;
    struct MultiBatch *existing;

    if (parc < 4)
      return need_more_params(sptr, "BATCH");

    btype = parv[2];
    target = parv[3];

    if (!HasCap(sptr, CAP_MULTILINE))
      return 0; /* silently ignore if client doesn't have the CAP */

    if (ircd_strcmp(btype, "draft/multiline") != 0)
      return 0; /* only draft/multiline supported */

    /* Abort any existing batch from this client */
    if ((existing = ml_find(sptr)))
      ml_destroy(existing);

    ml_create(sptr, ref, target);
    return 0;

  } else if (*refarg == '-') {
    /* End the batch */
    const char *ref = refarg + 1;
    struct MultiBatch *mb = ml_find(sptr);

    if (!mb || ircd_strcmp(mb->ref, ref) != 0)
      return 0; /* no matching batch */

    ml_deliver(sptr, mb);
    ml_destroy(mb);
    return 0;
  }

  return 0;
}
