/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * ircd/ircd_tags.c — IRCv3 message tag infrastructure implementation.
 */

#include "ircd_tags.h"
#include "ircd_msgid.h"
#include "ircd_string.h"
#include "client.h"
#include "struct.h"
#include "capab.h"
#include "s_user.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/*
 * Core API
 */

void msgtags_init(struct MsgTags *mt)
{
  memset(mt, 0, sizeof(*mt));
}

int msgtags_parse(struct MsgTags *mt, const char *tagstr)
{
  char buf[MAXTAGLEN];
  char *p, *pair, *eq;

  if (!mt || !tagstr || !*tagstr)
    return -1;

  msgtags_init(mt);

  /* Copy to mutable buffer */
  ircd_strncpy(buf, tagstr, sizeof(buf));

  p = buf;
  while (p && *p && mt->count < MAXTAGS) {
    /* Split on semicolons */
    pair = p;
    p = strchr(p, ';');
    if (p)
      *p++ = '\0';

    if (!*pair)
      continue;

    /* Split key=value */
    eq = strchr(pair, '=');
    if (eq) {
      *eq++ = '\0';
      ircd_strncpy(mt->tags[mt->count].key, pair, MAXTAGKEYLEN);
      msgtags_unescape_value(eq, mt->tags[mt->count].value, MAXTAGVALLEN);
    } else {
      /* Boolean tag (no value) */
      ircd_strncpy(mt->tags[mt->count].key, pair, MAXTAGKEYLEN);
      mt->tags[mt->count].value[0] = '\0';
    }

    mt->tags[mt->count].client_only = (pair[0] == '+') ? 1 : 0;
    mt->count++;
  }

  return 0;
}

int msgtags_serialize(const struct MsgTags *mt, char *buf, size_t buflen,
                      int filter_client_only, int filter_server)
{
  char escaped[MAXTAGVALLEN * 2];
  size_t pos = 0;
  int i, first = 1;

  if (!mt || !buf || buflen == 0) {
    if (buf && buflen > 0)
      buf[0] = '\0';
    return 0;
  }

  buf[0] = '\0';

  for (i = 0; i < mt->count; i++) {
    /* Apply filters */
    if (filter_client_only && mt->tags[i].client_only)
      continue;
    if (filter_server && !mt->tags[i].client_only)
      continue;

    if (!first) {
      if (pos + 1 >= buflen) break;
      buf[pos++] = ';';
    }
    first = 0;

    /* Key */
    size_t klen = strlen(mt->tags[i].key);
    if (pos + klen >= buflen) break;
    memcpy(buf + pos, mt->tags[i].key, klen);
    pos += klen;

    /* Value (if non-empty) */
    if (mt->tags[i].value[0]) {
      if (pos + 1 >= buflen) break;
      buf[pos++] = '=';

      int elen = msgtags_escape_value(mt->tags[i].value, escaped, sizeof(escaped));
      if (pos + (size_t)elen >= buflen) break;
      memcpy(buf + pos, escaped, elen);
      pos += elen;
    }
  }

  buf[pos] = '\0';
  return (int)pos;
}

int msgtags_prefix(const struct MsgTags *mt, char *buf, size_t buflen,
                   int include_client_only)
{
  char tagstr[MAXTAGLEN];
  int len;

  if (!mt || mt->count == 0 || !buf || buflen < 3) {
    if (buf && buflen > 0)
      buf[0] = '\0';
    return 0;
  }

  len = msgtags_serialize(mt, tagstr, sizeof(tagstr),
                          include_client_only ? 0 : 1, 0);
  if (len == 0) {
    buf[0] = '\0';
    return 0;
  }

  /* @tagstr<space> */
  int written = snprintf(buf, buflen, "@%s ", tagstr);
  if (written < 0 || (size_t)written >= buflen) {
    buf[0] = '\0';
    return 0;
  }
  return written;
}

/*
 * Tag manipulation
 */

int msgtags_set(struct MsgTags *mt, const char *key, const char *value)
{
  int i;

  if (!mt || !key || !*key)
    return -1;

  /* Overwrite if exists */
  for (i = 0; i < mt->count; i++) {
    if (strcmp(mt->tags[i].key, key) == 0) {
      if (value)
        ircd_strncpy(mt->tags[i].value, value, MAXTAGVALLEN);
      else
        mt->tags[i].value[0] = '\0';
      return 0;
    }
  }

  /* Add new */
  if (mt->count >= MAXTAGS)
    return -1;

  ircd_strncpy(mt->tags[mt->count].key, key, MAXTAGKEYLEN);
  if (value)
    ircd_strncpy(mt->tags[mt->count].value, value, MAXTAGVALLEN);
  else
    mt->tags[mt->count].value[0] = '\0';
  mt->tags[mt->count].client_only = (key[0] == '+') ? 1 : 0;
  mt->count++;

  return 0;
}

const char *msgtags_get(const struct MsgTags *mt, const char *key)
{
  int i;
  if (!mt || !key)
    return NULL;
  for (i = 0; i < mt->count; i++) {
    if (strcmp(mt->tags[i].key, key) == 0)
      return mt->tags[i].value;
  }
  return NULL;
}

int msgtags_remove(struct MsgTags *mt, const char *key)
{
  int i;
  if (!mt || !key)
    return 0;
  for (i = 0; i < mt->count; i++) {
    if (strcmp(mt->tags[i].key, key) == 0) {
      /* Shift remaining tags down */
      if (i < mt->count - 1)
        memmove(&mt->tags[i], &mt->tags[i + 1],
                (mt->count - i - 1) * sizeof(struct TagEntry));
      mt->count--;
      return 1;
    }
  }
  return 0;
}

int msgtags_has(const struct MsgTags *mt, const char *key)
{
  return msgtags_get(mt, key) != NULL;
}

void msgtags_merge(struct MsgTags *dst, const struct MsgTags *src)
{
  int i;
  if (!dst || !src)
    return;
  for (i = 0; i < src->count; i++)
    msgtags_set(dst, src->tags[i].key, src->tags[i].value);
}

void msgtags_merge_server(struct MsgTags *dst, const struct MsgTags *src)
{
  int i;
  if (!dst || !src)
    return;
  for (i = 0; i < src->count; i++) {
    if (!src->tags[i].client_only)
      msgtags_set(dst, src->tags[i].key, src->tags[i].value);
  }
}

void msgtags_merge_client(struct MsgTags *dst, const struct MsgTags *src)
{
  int i;
  if (!dst || !src)
    return;
  for (i = 0; i < src->count; i++) {
    if (src->tags[i].client_only)
      msgtags_set(dst, src->tags[i].key, src->tags[i].value);
  }
}

/*
 * Standard tag injection
 */

void msgtags_inject_time(struct MsgTags *mt)
{
  char timebuf[64];
  struct timespec ts;
  struct tm tm;

  if (!mt || msgtags_has(mt, "time"))
    return;

  clock_gettime(CLOCK_REALTIME, &ts);
  gmtime_r(&ts.tv_sec, &tm);
  snprintf(timebuf, sizeof(timebuf),
           "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           ts.tv_nsec / 1000000);

  msgtags_set(mt, "time", timebuf);
}

void msgtags_inject_time_ts(struct MsgTags *mt, time_t timestamp)
{
  char timebuf[64];
  struct tm tm;

  if (!mt || msgtags_has(mt, "time"))
    return;

  gmtime_r(&timestamp, &tm);
  snprintf(timebuf, sizeof(timebuf),
           "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec);

  msgtags_set(mt, "time", timebuf);
}

void msgtags_inject_msgid(struct MsgTags *mt)
{
  char msgid[MSGID_LEN + 1];

  if (!mt || msgtags_has(mt, "msgid"))
    return;

  ircd_msgid_generate(msgid, sizeof(msgid));
  msgtags_set(mt, "msgid", msgid);
}

void msgtags_inject_account(struct MsgTags *mt, const char *account)
{
  if (!mt || !account || !*account)
    return;
  if (strcmp(account, "*") == 0)
    return; /* not logged in */
  msgtags_set(mt, "account", account);
}

void msgtags_inject_bot(struct MsgTags *mt)
{
  if (!mt)
    return;
  msgtags_set(mt, "draft/bot", NULL);
}

void msgtags_inject_batch(struct MsgTags *mt, const char *refid)
{
  if (!mt || !refid || !*refid)
    return;
  msgtags_set(mt, "batch", refid);
}

void msgtags_inject_label(struct MsgTags *mt, const char *label)
{
  if (!mt || !label || !*label)
    return;
  msgtags_set(mt, "label", label);
}

void msgtags_inject_standard(struct MsgTags *mt)
{
  if (!mt)
    return;
  msgtags_inject_time(mt);
  msgtags_inject_msgid(mt);
}

void msgtags_inject_for_source(struct MsgTags *mt, struct Client *source)
{
  if (!mt || !source)
    return;

  msgtags_inject_standard(mt);

  /* Inject account tag if user is logged in */
  if (IsAccount(source))
    msgtags_inject_account(mt, cli_user(source)->account);

  /* Inject bot tag if user has +B mode */
  if (HasFlag(source, FLAG_BOT))
    msgtags_inject_bot(mt);
}

/*
 * Tag escaping per IRCv3 message-tags spec
 *
 * Escape sequences:
 *   \: → ;  (semicolon)
 *   \s → ' ' (space)
 *   \\ → \  (backslash)
 *   \r → CR
 *   \n → LF
 */

int msgtags_escape_value(const char *src, char *dst, size_t dstlen)
{
  size_t si = 0, di = 0;

  if (!src || !dst || dstlen == 0) {
    if (dst && dstlen > 0)
      dst[0] = '\0';
    return 0;
  }

  while (src[si] && di + 2 < dstlen) {
    switch (src[si]) {
    case ';':
      dst[di++] = '\\'; dst[di++] = ':'; break;
    case ' ':
      dst[di++] = '\\'; dst[di++] = 's'; break;
    case '\\':
      dst[di++] = '\\'; dst[di++] = '\\'; break;
    case '\r':
      dst[di++] = '\\'; dst[di++] = 'r'; break;
    case '\n':
      dst[di++] = '\\'; dst[di++] = 'n'; break;
    default:
      dst[di++] = src[si]; break;
    }
    si++;
  }

  dst[di] = '\0';
  return (int)di;
}

int msgtags_unescape_value(const char *src, char *dst, size_t dstlen)
{
  size_t si = 0, di = 0;

  if (!src || !dst || dstlen == 0) {
    if (dst && dstlen > 0)
      dst[0] = '\0';
    return 0;
  }

  while (src[si] && di + 1 < dstlen) {
    if (src[si] == '\\' && src[si + 1]) {
      switch (src[si + 1]) {
      case ':': dst[di++] = ';';  si += 2; break;
      case 's': dst[di++] = ' ';  si += 2; break;
      case '\\': dst[di++] = '\\'; si += 2; break;
      case 'r': dst[di++] = '\r'; si += 2; break;
      case 'n': dst[di++] = '\n'; si += 2; break;
      default:
        /* Unknown escape: drop backslash per spec */
        dst[di++] = src[si + 1]; si += 2; break;
      }
    } else {
      dst[di++] = src[si++];
    }
  }

  dst[di] = '\0';
  return (int)di;
}

/*
 * Filtering for send path
 */

int msgtags_for_client(const struct MsgTags *mt, struct Client *client,
                       char *buf, size_t buflen)
{
  struct MsgTags filtered;
  int i;

  if (!mt || !client || !buf || buflen < 2) {
    if (buf && buflen > 0)
      buf[0] = '\0';
    return 0;
  }

  msgtags_init(&filtered);

  /* Check what this client supports */
  int has_message_tags = HasCap(client, CAP_MSGTAGS);
  int has_server_time  = HasCap(client, CAP_SERVERTIME);
  int has_account_tag  = HasCap(client, CAP_ACCOUNTTAG);

  for (i = 0; i < mt->count; i++) {
    const struct TagEntry *te = &mt->tags[i];

    if (te->client_only) {
      /* Client-only tags: only relay if client has message-tags */
      if (has_message_tags)
        msgtags_set(&filtered, te->key, te->value);
      continue;
    }

    /* Server tags: check specific CAPs */
    if (strcmp(te->key, "time") == 0) {
      if (has_server_time || has_message_tags)
        msgtags_set(&filtered, te->key, te->value);
    } else if (strcmp(te->key, "account") == 0) {
      if (has_account_tag || has_message_tags)
        msgtags_set(&filtered, te->key, te->value);
    } else if (strcmp(te->key, "msgid") == 0 ||
               strcmp(te->key, "batch") == 0 ||
               strcmp(te->key, "label") == 0 ||
               strncmp(te->key, "draft/", 6) == 0) {
      /* These require message-tags CAP */
      if (has_message_tags)
        msgtags_set(&filtered, te->key, te->value);
    } else {
      /* Unknown server tag: require message-tags */
      if (has_message_tags)
        msgtags_set(&filtered, te->key, te->value);
    }
  }

  if (filtered.count == 0) {
    buf[0] = '\0';
    return 0;
  }

  return msgtags_prefix(&filtered, buf, buflen, 1);
}

int msgtags_for_server(const struct MsgTags *mt, char *buf, size_t buflen)
{
  /* P10 server links get all tags unconditionally */
  if (!mt || mt->count == 0 || !buf || buflen < 2) {
    if (buf && buflen > 0)
      buf[0] = '\0';
    return 0;
  }
  return msgtags_prefix(mt, buf, buflen, 1);
}
