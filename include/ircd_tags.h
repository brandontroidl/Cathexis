/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * include/ircd_tags.h — IRCv3 message tag infrastructure.
 *
 * MsgTags is the core struct that carries IRCv3 tags through the
 * entire send path. Every sendcmdto_* function in send.c takes an
 * optional MsgTags pointer. If non-NULL, tags are prepended to the
 * outgoing line for clients that have negotiated message-tags CAP.
 *
 * Tag lifecycle:
 *   1. Incoming line → parse.c extracts tags into MsgTags
 *   2. Handler adds/modifies tags (msgid, time, account, etc.)
 *   3. sendcmdto_* checks each recipient's CAPs
 *   4. For clients with message-tags: prepend @tags prefix
 *   5. For clients without: send bare line (no tags)
 *   6. For P10 server links: always include tags
 */

#ifndef INCLUDED_ircd_tags_h
#define INCLUDED_ircd_tags_h

#include <time.h>

/** Maximum number of tags per message */
#define MAXTAGS 32

/** Maximum total tag string length (spec allows 8191, we cap at 4096) */
#define MAXTAGLEN 4096

/** Maximum single tag key length */
#define MAXTAGKEYLEN 256

/** Maximum single tag value length (after unescaping) */
#define MAXTAGVALLEN 512

/** A single IRCv3 message tag (key=value pair). */
struct TagEntry {
  char key[MAXTAGKEYLEN];   /**< Tag key (e.g., "time", "msgid", "+typing") */
  char value[MAXTAGVALLEN]; /**< Tag value (unescaped) */
  int  client_only;         /**< 1 if key starts with '+' */
};

/** Collection of IRCv3 message tags attached to a message. */
struct MsgTags {
  struct TagEntry tags[MAXTAGS]; /**< Tag array */
  int count;                     /**< Number of tags in array */
};

/*
 * Core API
 */

/** Initialize a MsgTags struct (zero all fields). */
void msgtags_init(struct MsgTags *mt);

/** Parse an IRCv3 tag string (without leading '@') into a MsgTags struct.
 *  Returns 0 on success, -1 on parse error. */
int msgtags_parse(struct MsgTags *mt, const char *tagstr);

/** Serialize a MsgTags struct to an IRCv3 tag string (without leading '@').
 *  Writes to buf, returns number of bytes written.
 *  If filter_client_only is 1, client-only tags (+prefix) are excluded.
 *  If filter_server is 1, server tags (no + prefix) are excluded. */
int msgtags_serialize(const struct MsgTags *mt, char *buf, size_t buflen,
                      int filter_client_only, int filter_server);

/** Build the full @tags prefix for a P10 or client line.
 *  Writes "@key=val;key2=val2 " to buf (with trailing space).
 *  Returns bytes written, or 0 if no tags. */
int msgtags_prefix(const struct MsgTags *mt, char *buf, size_t buflen,
                   int include_client_only);

/*
 * Tag manipulation
 */

/** Set a tag (overwrites if key already exists). Returns 0 on success. */
int msgtags_set(struct MsgTags *mt, const char *key, const char *value);

/** Get a tag value by key. Returns NULL if not found. */
const char *msgtags_get(const struct MsgTags *mt, const char *key);

/** Remove a tag by key. Returns 1 if removed, 0 if not found. */
int msgtags_remove(struct MsgTags *mt, const char *key);

/** Check if a tag exists. */
int msgtags_has(const struct MsgTags *mt, const char *key);

/** Copy all tags from src to dst (appends, does not clear dst first). */
void msgtags_merge(struct MsgTags *dst, const struct MsgTags *src);

/** Copy only server tags (non '+' prefix) from src to dst. */
void msgtags_merge_server(struct MsgTags *dst, const struct MsgTags *src);

/** Copy only client-only tags ('+' prefix) from src to dst. */
void msgtags_merge_client(struct MsgTags *dst, const struct MsgTags *src);

/*
 * Standard tag injection (call these before sending)
 */

/** Inject @time= tag with current UTC time if not already set. */
void msgtags_inject_time(struct MsgTags *mt);

/** Inject @time= tag with a specific timestamp. */
void msgtags_inject_time_ts(struct MsgTags *mt, time_t ts);

/** Inject @msgid= tag with a new unique ID if not already set.
 *  Uses ircd_msgid_generate() from ircd_msgid.h. */
void msgtags_inject_msgid(struct MsgTags *mt);

/** Inject @account= tag for the given account name. */
void msgtags_inject_account(struct MsgTags *mt, const char *account);

/** Inject draft/bot tag (boolean, no value). */
void msgtags_inject_bot(struct MsgTags *mt);

/** Inject @batch= tag with the given batch reference ID. */
void msgtags_inject_batch(struct MsgTags *mt, const char *refid);

/** Inject @label= tag. */
void msgtags_inject_label(struct MsgTags *mt, const char *label);

/** Inject all standard server tags (@time, @msgid) for an originating message. */
void msgtags_inject_standard(struct MsgTags *mt);

/** Inject all standard server tags plus @account for a specific source user. */
struct Client; /* forward declaration */
void msgtags_inject_for_source(struct MsgTags *mt, struct Client *source);

/*
 * Tag escaping (IRCv3 spec)
 */

/** Escape a tag value for wire format. Writes to dst. Returns bytes written. */
int msgtags_escape_value(const char *src, char *dst, size_t dstlen);

/** Unescape a tag value from wire format. Writes to dst. Returns bytes written. */
int msgtags_unescape_value(const char *src, char *dst, size_t dstlen);

/*
 * Filtering for send path
 */

/** Build tags for a specific client, respecting their negotiated CAPs.
 *  - If client has message-tags CAP: include server tags + client-only tags
 *  - If client has server-time only: include only @time
 *  - If client has no tag CAPs: return empty
 *  Writes the @prefix string to buf. Returns bytes written. */
int msgtags_for_client(const struct MsgTags *mt, struct Client *client,
                       char *buf, size_t buflen);

/** Build tags for a P10 server-to-server line. Always include all tags. */
int msgtags_for_server(const struct MsgTags *mt, char *buf, size_t buflen);

#endif /* INCLUDED_ircd_tags_h */
