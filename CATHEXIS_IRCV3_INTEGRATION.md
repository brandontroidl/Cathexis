# Cathexis IRCv3 Complete Integration Guide

Version 1.5.0 — Full IRCv3 compliance for Cathexis IRCd.

## New Files to Add

```
include/ircd_tags.h      — MsgTags struct and API
include/ircd_msgid.h     — Message ID generation API
include/ircd_botmode.h   — Bot-mode (+B) defines
ircd/ircd_tags.c         — Tag parse/serialize/inject/filter (380 lines)
ircd/ircd_msgid.c        — crypto/rand message ID generation (50 lines)
```

Add to `ircd/Makefile.in` IRCD_SRC and IRCD_OBJ:
```
ircd_tags.c → ircd_tags.o
ircd_msgid.c → ircd_msgid.o
```

---

## 1. FOUNDATION: send.c Tag Relay

This is the single change that unlocks message-tags, message-ids,
server-time, echo-message, TAGMSG, batch, and labeled-response.

### 1a. Add MsgTags parameter to ALL sendcmdto_* functions

Every function in send.c that sends messages to clients or servers
must accept an optional `struct MsgTags *` parameter.

**Functions to modify** (add `struct MsgTags *tags` as the LAST parameter):

```c
/* Client-targeted sends */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, struct MsgTags *tags, const char *pattern, ...);

void sendcmdto_channel(struct Client *from, const char *cmd, const char *tok,
                       struct Channel *to, struct Client *one,
                       unsigned int skip, struct MsgTags *tags,
                       const char *pattern, ...);

void sendcmdto_common_channels(struct Client *from, const char *cmd,
                               const char *tok, struct MsgTags *tags,
                               const char *pattern, ...);

void sendcmdto_match(struct Client *from, const char *cmd, const char *tok,
                     const char *to, struct Client *one,
                     unsigned int who, struct MsgTags *tags,
                     const char *pattern, ...);

void sendcmdto_flag_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           unsigned int flag, struct MsgTags *tags,
                           const char *pattern, ...);

/* Server-targeted sends (P10) */
void sendcmdto_serv(struct Client *from, const char *cmd, const char *tok,
                    struct MsgTags *tags, const char *pattern, ...);

/* Also: sendcmdto_prio_one, sendrawto_one, etc. */
```

### 1b. Inside each sendcmdto_* function: prepend tags

For **client** recipients, before writing the line:

```c
/* In the per-client send path (inside the channel member loop, etc.) */
if (tags && tags->count > 0) {
  char tagprefix[MAXTAGLEN + 4];
  int tlen = msgtags_for_client(tags, target_client, tagprefix, sizeof(tagprefix));
  if (tlen > 0) {
    /* Prepend tag prefix before the :source COMMAND ... line */
    msgq_append(&target_client->sendQ, tagprefix);
  }
}
```

For **P10 server** recipients:

```c
if (tags && tags->count > 0) {
  char tagprefix[MAXTAGLEN + 4];
  int tlen = msgtags_for_server(tags, tagprefix, sizeof(tagprefix));
  if (tlen > 0) {
    msgq_append(&server->sendQ, tagprefix);
  }
}
```

### 1c. Update ALL callers of sendcmdto_* functions

Every call site must pass tags (or NULL for no tags). Search the entire
source tree for `sendcmdto_` and add the tags parameter.

**Key callers that MUST pass tags:**

```c
/* m_privmsg.c — PRIVMSG/NOTICE relay */
struct MsgTags mt;
msgtags_init(&mt);
msgtags_inject_for_source(&mt, sptr);
/* Also merge any incoming tags from the source (client-only relay) */
if (incoming_tags)
  msgtags_merge_client(&mt, incoming_tags);
sendcmdto_channel(sptr, "PRIVMSG", "P", chptr, NULL, SKIP_DEAF, &mt,
                  "%H :%s", chptr, text);

/* m_topic.c — TOPIC change */
struct MsgTags mt;
msgtags_init(&mt);
msgtags_inject_for_source(&mt, sptr);
sendcmdto_channel(sptr, "TOPIC", "T", chptr, NULL, 0, &mt,
                  "%H :%s", chptr, topic);

/* m_join.c — JOIN notification */
/* m_part.c — PART notification */
/* m_quit.c — QUIT notification */
/* m_kick.c — KICK notification */
/* m_nick.c — NICK change notification */
/* m_mode.c — MODE change notification */
/* ... ALL message-generating commands */
```

For commands that don't originate user-visible messages (PING, PONG,
numeric replies, etc.), pass NULL for tags.

---

## 2. parse.c — Extract Tags from Incoming Lines

### 2a. Modify the message parser to extract tag prefix

In `parse.c`, the main `parse_client()` and `parse_server()` functions
read lines. Before extracting the source prefix, check for `@`:

```c
/* At the top of the parse function, before source extraction */
struct MsgTags incoming_tags;
msgtags_init(&incoming_tags);

if (*ch == '@') {
  /* Extract tag string */
  char *tagend = strchr(ch, ' ');
  if (tagend) {
    char tagbuf[MAXTAGLEN];
    size_t taglen = tagend - ch - 1; /* skip '@' */
    if (taglen > 0 && taglen < sizeof(tagbuf)) {
      memcpy(tagbuf, ch + 1, taglen);
      tagbuf[taglen] = '\0';
      msgtags_parse(&incoming_tags, tagbuf);
    }
    ch = tagend + 1;
    while (*ch == ' ') ch++; /* skip extra spaces */
  }
}

/* Store incoming_tags on the message struct so handlers can access them */
```

### 2b. Store tags on the parsed message

Add a `struct MsgTags *tags` field to the message/command context so
handlers can access incoming tags. The exact mechanism depends on how
Cathexis passes context — either:
- Add `struct MsgTags` to `struct Client` temporarily during parse
- Pass through the handler function signature
- Store on a thread-local or parse-context struct

---

## 3. m_cap.c — Fix CAP Advertisement

### 3a. Add missing CAPs to capab_list[]

```c
/* In m_cap.c, add to the capab_list[] array: */
{ "draft/bot-mode",     CAP_BOTMODE,     0, 0 },
{ "message-ids",        CAP_MESSAGEIDS,  0, 0 },
/* Ensure monitor is present: */
{ "monitor",            CAP_MONITOR,     0, 0 },
```

### 3b. Add new CAP flags to capab.h

```c
/* In include/capab.h, add to the CAP_ enum: */
#define CAP_MESSAGETAGS    (1 << X)  /* if not already defined */
#define CAP_MESSAGEIDS     (1 << Y)  /* message-ids */
#define CAP_BOTMODE        (1 << Z)  /* draft/bot-mode */
#define CAP_MONITOR        (1 << W)  /* monitor */
/* Also ensure these exist: */
#define CAP_SERVERTIME     /* ... */
#define CAP_ACCOUNTTAG     /* ... */
#define CAP_ECHOMESSAGE    /* ... */
#define CAP_BATCH          /* ... */
#define CAP_LABELEDRESPONSE /* ... */
```

If running out of bits in a single `unsigned int`, use `capab_ircv3_ext.h`
secondary bitmask.

---

## 4. m_tagmsg.c — Real TAGMSG Relay

Replace the current stub with actual relay logic:

```c
int m_tagmsg(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct MsgTags mt;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "TAGMSG");

  /* TAGMSG only makes sense if there are tags to relay */
  if (!sptr->tags || sptr->tags->count == 0)
    return 0;

  msgtags_init(&mt);
  /* Copy client-only tags from incoming */
  msgtags_merge_client(&mt, sptr->tags);
  /* Add standard server tags */
  msgtags_inject_for_source(&mt, sptr);

  if (IsChannelName(parv[1])) {
    chptr = FindChannel(parv[1]);
    if (!chptr)
      return send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);

    /* Relay to channel — only to members with message-tags CAP */
    sendcmdto_channel(sptr, "TAGMSG", "TG", chptr, sptr,
                      SKIP_NONMESSAGETAGS, &mt, "%H", chptr);
  } else {
    /* Relay to user */
    struct Client *target = FindUser(parv[1]);
    if (!target)
      return send_reply(sptr, ERR_NOSUCHNICK, parv[1]);

    if (HasCap(target, CAP_MESSAGETAGS))
      sendcmdto_one(sptr, "TAGMSG", "TG", target, &mt, "%C", target);
  }

  return 0;
}
```

Add `SKIP_NONMESSAGETAGS` constant to skip members without message-tags CAP.

---

## 5. echo-message

Echo-message requires tag relay (done in step 1). The only additional
change is: when a client has `CAP_ECHOMESSAGE` and sends PRIVMSG/NOTICE,
echo the message back to them with tags.

In `m_privmsg.c`, after the channel/user relay:

```c
/* Echo back to sender if they have echo-message CAP */
if (HasCap(sptr, CAP_ECHOMESSAGE)) {
  sendcmdto_one(sptr, cmd, tok, sptr, &mt, "%s :%s", target, text);
}
```

---

## 6. ircd_batch.c — Netsplit/Netjoin Batches

### 6a. Generate netsplit batch on SQUIT

In the SQUIT handler (or wherever netsplit QUITs are generated):

```c
/* Before sending QUIT messages for netsplit users */
char refid[16];
ircd_batch_generate_refid(refid, sizeof(refid));
sendcmdto_common_channels(NULL, "BATCH", NULL, NULL,
                          "+%s netsplit %s %s", refid, server1, server2);

/* For each QUIT in the netsplit, add @batch=refid tag */
struct MsgTags mt;
msgtags_init(&mt);
msgtags_inject_batch(&mt, refid);
msgtags_inject_time(&mt);
/* send QUIT with &mt */

/* After all QUITs */
sendcmdto_common_channels(NULL, "BATCH", NULL, NULL, "-%s", refid);
```

### 6b. Generate netjoin batch on server link

Same pattern for netjoin — wrap the re-introduction JOINs in a
`netjoin` batch.

---

## 7. Bot-Mode (+B)

### 7a. client.h — Add FLAG_BOT

```c
/* In the flag enum in client.h */
#define FLAG_BOT        /* next available flag number */
```

### 7b. s_user.c — Handle +B in mode processing

In `set_user_mode()`, add 'B' to the mode table:

```c
case 'B':
  if (what == MODE_ADD)
    SetFlag(sptr, FLAG_BOT);
  else
    ClrFlag(sptr, FLAG_BOT);
  break;
```

### 7c. whocmds.c — Show B in WHO flag field

In the WHO response builder, if `IsBotMode(target)`, add 'B' to
the flag string.

### 7d. Propagate +B on P10

When a user sets +B, propagate via MODE to other servers so the
network state stays consistent.

---

## 8. account-extban

In `channel.c`, in the ban matching function:

```c
/* Add $a:account extban type */
if (ban[0] == '$' && ban[1] == 'a' && ban[2] == ':') {
  const char *banacct = ban + 3;
  if (IsAccount(target)) {
    if (match(banacct, cli_user(target)->account) == 0)
      return 1; /* ban matches */
  }
  continue;
}
```

Also update ISUPPORT to advertise `EXTBAN=$,a`.

---

## 9. utf8-only

### 9a. Add ISUPPORT token

In `ircd_features.c` or ISUPPORT generation:
```c
/* Add UTF8ONLY to ISUPPORT (005) */
send_reply(sptr, RPL_ISUPPORT, "UTF8ONLY ...");
```

### 9b. Validate UTF-8 on user-visible messages

In `m_privmsg.c` (PRIVMSG/NOTICE handler), add UTF-8 validation:

```c
if (feature_bool(FEAT_UTF8ONLY)) {
  if (!is_valid_utf8(text)) {
    return send_reply(sptr, ERR_INVALIDTEXT, "Message must be valid UTF-8");
    /* Use FAIL standard-reply if client has message-tags */
  }
}
```

Also validate on TOPIC, PART reason, QUIT reason, KICK reason.

Add `is_valid_utf8()` utility function (scan bytes for valid UTF-8 sequences).

---

## 10. no-implicit-names

In `m_join.c`, after successful JOIN, before sending NAMES reply:

```c
/* Skip automatic NAMES if client has no-implicit-names CAP */
if (!HasCap(sptr, CAP_NOIMPLICITNAMES)) {
  /* Send NAMES reply as usual */
  do_names(sptr, chptr, NAMES_ALL);
}
```

Add `CAP_NOIMPLICITNAMES` to capab.h and "no-implicit-names" to capab_list[].

---

## 11. monitor — Add to CAP Advertisement

In `m_cap.c`, ensure monitor is in capab_list[]:
```c
{ "monitor", CAP_MONITOR, 0, 0 },
```

The m_monitor.c implementation is already complete — it just needs
the CAP entry.

---

## 12. WHOX Audit

In `whocmds.c`, verify the WHO response matches IRCv3 WHOX spec:
- %t token should return the query token
- %a should return account name (or "0" if not logged in)
- %f should return away + oper + channel membership flags
- %r should return realname

---

## 13. chathistory — Complete XQUERY Proxy

`m_chathistory.c` currently has a skeleton. Complete it:

```c
int m_chathistory(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  /* Parse subcommand and params */
  /* Build XQUERY and forward to services (Synaxis/Acid) */
  /* XQUERY format: <our-numeric> XQ <target-services-server> <routing> :CHATHISTORY <sub> <params> */

  /* Forward the label tag from the client if present */
  struct MsgTags mt;
  msgtags_init(&mt);
  if (sptr->tags && msgtags_has(sptr->tags, "label"))
    msgtags_inject_label(&mt, msgtags_get(sptr->tags, "label"));

  sendcmdto_serv(sptr, "XQUERY", "XQ", &mt,
                 "%s %s :CHATHISTORY %s",
                 services_server, routing_info, chathistory_args);
  return 0;
}
```

---

## 14. Draft/WIP Extensions (behind FEAT_ flags)

These should be behind `ircd_features.c` feature flags so they can
be enabled/disabled at runtime:

| Spec | Feature Flag | Status |
|------|-------------|--------|
| channel-rename | FEAT_CHANNELRENAME | New m_rename.c needed |
| account-registration | FEAT_ACCOUNTREG | New m_register.c, relay to services |
| extended-monitor | FEAT_EXTMONITOR | Extend m_monitor.c with account monitoring |
| read-marker | FEAT_READMARKER | New m_markread.c |
| pre-away | FEAT_PREAWAY | Extend m_away.c with batch support |
| multiline | FEAT_MULTILINE | New batch type + message concatenation |
| metadata | FEAT_METADATA | New m_metadata.c (complex, draft spec) |
| message-redaction | FEAT_REDACTION | New m_redact.c |
| extended-isupport | FEAT_EXTISUPPORT | Extend RPL_ISUPPORT |

Each of these is a significant feature. Implement behind flags so
the network can enable them progressively.

---

## 15. Build and Test

### 15a. Makefile changes

Add to `ircd/Makefile.in`:
```
IRCD_SRC += ircd_tags.c ircd_msgid.c
IRCD_OBJ += ircd_tags.o ircd_msgid.o
```

### 15b. Clean build

```bash
rm -f ircd/*.o && make clean && make distclean
./configure
make
```

### 15c. Test matrix

| Test | How to verify |
|------|---------------|
| Tags on PRIVMSG | Connect two clients with message-tags CAP, send PRIVMSG, verify @time;msgid;account on received line |
| Tags filtered | Connect client WITHOUT message-tags, verify no @ prefix on received messages |
| server-time only | Connect with only server-time CAP, verify only @time appears |
| TAGMSG relay | Send TAGMSG with +typing tag, verify relay to channel members with message-tags |
| echo-message | Enable echo-message CAP, send PRIVMSG, verify echoed back with tags |
| bot-mode | Set +B on a user, verify draft/bot tag appears on their messages |
| account-extban | Set ban $a:accountname, verify user with that account is banned |
| WHOIS +B | WHOIS a user with +B, verify it shows in modes |
| monitor CAP | CAP LS, verify "monitor" appears |
| batch netsplit | Force a netsplit, verify BATCH +refid netsplit wraps QUITs |
| labeled-response | Send command with @label=xyz, verify response has @label=xyz |
| chathistory | Send CHATHISTORY LATEST, verify XQUERY forwarded to services |
| no-implicit-names | Negotiate no-implicit-names, JOIN channel, verify no NAMES reply |
| utf8-only | Enable UTF8ONLY, send invalid UTF-8, verify rejection |
| P10 tags | Check that P10 server links carry @tags prefix on all lines |

---

## 16. IRCv3 Compliance Summary

After all changes:

| Spec | Status |
|------|--------|
| capability-negotiation (302) | DONE — audit m_cap.c |
| message-tags | DONE — ircd_tags.c + send.c integration |
| message-ids | DONE — ircd_msgid.c + msgtags_inject_msgid |
| server-time | DONE — msgtags_inject_time on all paths |
| batch | DONE — ircd_batch.c + netsplit/netjoin generation |
| labeled-response | DONE — label tag relay through send path |
| echo-message | DONE — echo in m_privmsg.c with tags |
| multi-prefix | DONE (existing) |
| userhost-in-names | DONE (existing) |
| extended-join | DONE (existing) |
| account-notify | DONE (existing) |
| account-tag | DONE — msgtags_inject_account |
| away-notify | DONE (existing) |
| chghost | DONE (existing) |
| setname | DONE (existing) |
| invite-notify | DONE (existing) |
| monitor | DONE — add CAP entry |
| standard-replies | DONE (existing) |
| sasl 3.1/3.2 | DONE (existing via iauthd-ts) |
| sts | DONE (existing) |
| cap-notify | DONE (existing) |
| bot-mode | DONE — ircd_botmode.h + FLAG_BOT |
| account-extban | DONE — channel.c $a: matching |
| webirc | DONE (existing) — audit against spec |
| WHOX | DONE — audit whocmds.c |
| utf8-only | DONE — validation + ISUPPORT |
| no-implicit-names | DONE — m_join.c CAP check |
| TAGMSG | DONE — m_tagmsg.c real relay |
| chathistory | DONE — m_chathistory.c XQUERY proxy |
| channel-rename | DRAFT — behind FEAT_CHANNELRENAME |
| account-registration | DRAFT — behind FEAT_ACCOUNTREG |
| extended-monitor | DRAFT — behind FEAT_EXTMONITOR |
| read-marker | DRAFT — behind FEAT_READMARKER |
| pre-away | DRAFT — behind FEAT_PREAWAY |
| multiline | DRAFT — behind FEAT_MULTILINE |
| metadata | DRAFT — behind FEAT_METADATA |
| message-redaction | DRAFT — behind FEAT_REDACTION |
| extended-isupport | DRAFT — behind FEAT_EXTISUPPORT |

**All ratified specs: COMPLETE.**
**All draft specs: Behind feature flags, implementable progressively.**

---

## 17. 36-Pass Audit Checklist

Per Cathexis standards, every change gets a 36-pass audit:

1. Buffer overflow check (ircd_strncpy, snprintf return)
2. NULL pointer check (cli_connect guard on all async paths)
3. Integer overflow check (no pointer arithmetic for range)
4. Use-after-free check
5. Double-free check
6. Memory leak check (OPENSSL_cleanse on key material)
7. Thread safety (tag operations during send)
8. Constant-time comparison (ircd_constcmp for secrets)
9. All crypto through ircd_crypto.h
10. OpenSSL version compatibility
11. CodeQL clean
12. No AI attribution in source
13. Copyright header on all new files
14. Error path coverage
15. Edge cases (empty tags, max tags, oversized values)
16. P10 protocol correctness
17. CAP negotiation correctness
18. Tag escaping roundtrip
19. Backward compatibility (clients without tags see no change)
20. Server-to-server tag propagation
21. Memory usage under load
22. Flood protection (tag size limits)
23. Injection prevention (tag values can't inject commands)
24. Cross-server state consistency
25. BURST sequence correctness with tags
26. Kill/reconnect pseudo-client behavior
27. Feature flag defaults
28. Configuration documentation
29. ISUPPORT accuracy
30. Numeric reply correctness
31. Channel type coverage (# & + !)
32. Mode parameter handling
33. Ban matching correctness (extban)
34. UTF-8 validation edge cases
35. Batch reference uniqueness
36. Full source tree scan line 1 to EOF
