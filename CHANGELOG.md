# Cathexis Changelog

## 1.0.0 — 2026-03-07

Initial Cathexis release. Security-hardened fork of Nefarious2 (u2.10.12.14).

### Security Hardening

#### Buffer Overflow Prevention (sprintf → ircd_snprintf)
- `ircd/ircd.c` — PID file write
- `ircd/send.c` — SSL write error formatting
- `ircd/os_generic.c` — All 7 resource usage sprintf calls
- `ircd/m_map.c` — Server lag display
- `ircd/opercmds.c` — Timestamp formatting (4 calls)
- `ircd/s_misc.c` — Date formatting
- `ircd/uping.c` — Ping time formatting (2 calls)
- `ircd/ircd_crypt_bcrypt.c` — Bcrypt salt generation (snprintf)
- `ircd/ircd_reslib.c` — DNS name encoding (5 calls, snprintf)

#### Buffer Overflow Prevention (strcpy → ircd_strncpy)
- `ircd/channel.c:3879,4064` — Ban propagation who field (2 sites)
- `ircd/m_nick.c:178` — Nick copy after truncation
- `ircd/m_svsnick.c:135` — SVS nick copy
- `ircd/m_check.c` — All 12 strcpy calls replaced
- `ircd/m_names.c` — All 11 strcpy calls replaced
- `ircd/m_burst.c:468` — Burst ban who literal
- `ircd/m_whois.c:223` — Channel name into buffer
- `ircd/list.c:230` — Default username
- `ircd/ircd_res.c:244` — Domain name append
- `ircd/s_user.c:744,859,867` — Nick to client name (3 sites)
- `ircd/s_bsd.c:604` — IP to sockhost copy
- `ircd/s_misc.c:464,467` — Netsplit comment strings

#### SSL/TLS Hardening
- `ircd/ssl.c` — Verify callback now logs unverified certificates with
  error codes when `FEAT_SSL_VERIFYCERT` is disabled, aiding production
  deployment auditing

#### Compiler Warning Fixes
- `ircd/ircd_reslib.c` — `const char *cp` for read-only pointer
- `ircd/ircd_string.c` — `const char *colon`, `const char *dot`
- `ircd/m_list.c` — Explicit `(char *)` cast for write-through pointers
- `ircd/m_sasl.c` — Explicit `(char *)` cast for write-through pointers
- `ircd/convert-conf.c` — Explicit `(char *)` cast for write-through pointer

### IRCv3 Modernization

#### New Capabilities (11)
Added to `include/capab.h`, `ircd/m_cap.c`, `include/ircd_features.h`,
and `ircd/ircd_features.c`:
- `cap-notify` (CAP_CAPNOTIFY)
- `server-time` (CAP_SERVERTIME)
- `account-tag` (CAP_ACCOUNTTAG)
- `message-tags` (CAP_MSGTAGS)
- `echo-message` (CAP_ECHOMSG)
- `invite-notify` (CAP_INVITENOTIFY)
- `chghost` (CAP_CHGHOST)
- `setname` (CAP_SETNAME)
- `batch` (CAP_BATCH)
- `labeled-response` (CAP_LABELEDRESP)
- `standard-replies` (CAP_STDREPLIES)

All capabilities are feature-gated and enabled by default.

#### New Command: SETNAME
- `ircd/m_setname.c` — New file implementing IRCv3 SETNAME
- `m_setname()` — Local client handler with capability gate, CR/LF
  filtering, length validation
- `ms_setname()` — Server handler (trusts peer, no error replies sent
  back across network)
- Registered in `ircd/parse.c` with `MFLG_SLOW` rate limiting
- Declared in `include/handlers.h`, tokens in `include/msg.h`
- Added to `ircd/Makefile.in` build

#### Protocol Parser
- `ircd/parse.c` — Added IRCv3 message tag (`@tags`) prefix skip in
  `parse_client()`, enabling modern IRC clients to send tagged messages

#### CAP 302 Infrastructure
- `include/client.h` — Added `con_capver` field to Connection struct
  with `cli_capver()` / `con_capver()` accessor macros

### Snomask Modernization

Replaced the legacy numeric snomask system with letter-based masks following
modern IRC daemon conventions (UnrealIRCd, InspIRCd, Charybdis).

- `ircd/s_user.c` — New snomask letter mapping table, rewritten
  `is_snomask()` and `umode_make_snomask()` to parse letter strings,
  new `snomask_to_str()` display function
- `ircd/s_err.c` — RPL_SNOMASK (008) now shows letter display
- `include/s_user.h` — Added `snomask_to_str()` declaration
- `doc/snomask.txt` — Complete rewrite with letter reference table

Users now use `/mode nick +s +nKg` instead of `/mode nick +s 1540`.
Legacy numeric masks are still accepted for backward compatibility.

### Files Modified (31 changed, 1 new)

**Headers:** capab.h, client.h, handlers.h, ircd_features.h, msg.h

**Core:** parse.c, send.c, ssl.c, ircd.c, m_cap.c, ircd_features.c

**Security:** channel.c, m_nick.c, m_svsnick.c, m_check.c, m_names.c,
m_burst.c, m_whois.c, m_map.c, list.c, ircd_res.c, s_user.c, s_bsd.c,
s_misc.c, os_generic.c, opercmds.c, uping.c, ircd_crypt_bcrypt.c,
ircd_reslib.c

**Warnings:** ircd_string.c, m_list.c, m_sasl.c, convert-conf.c

**New:** ircd/m_setname.c

**Docs:** README, AUDIT.md, CHANGELOG.md

**Build:** ircd/Makefile.in, include/patchlevel.h, ircd/version.c.SH

### Snomask Letter Consistency (additional changes)

- `ircd/ircd_parser.y` — Config parser snomask rules now accept letter
  strings (e.g. `snomask = "nKgDt"`) in addition to numeric values.
  Added `#include "s_user.h"` for `snomask_str_to_mask()`.
- `ircd/ircd_features.c` — Feature SET handler for integer features now
  detects letter-based input and converts via `snomask_str_to_mask()`.
  Feature GET and STATS report for SNOMASK_ features now display the
  letter equivalent alongside the numeric value.
- `ircd/m_oper.c` — MODE +s on OPER now sends letter-based snomask
  instead of numeric `+%d`.
- `ircd/s_user.c` — Added `snomask_str_to_mask()` conversion function.
- `include/s_user.h` — Exported `snomask_str_to_mask()`.

### Oper Level Hierarchy

Added +N (Network Administrator) user mode, matching UnrealIRCd conventions.

Oper hierarchy (highest to lowest):
  +k  Service (unchanged)
  +N  Network Administrator (NEW)
  +a  Server Administrator (renamed from "IRC Administrator")
  +o  Global IRC Operator (unchanged)
  +O  Local IRC Operator (unchanged)

Files changed:
- `include/client.h` — Added FLAG_NETADMIN, PRIV_NETADMIN, Is/Set/Clear macros
- `ircd/s_user.c` — Added 'N' case in umode parsing
- `ircd/m_oper.c` — Sets +N on OPER when PRIV_NETADMIN granted, updated mode string
- `ircd/m_whois.c` — Full hierarchy display: +N/+a/+o/+O with distinct labels
- `ircd/ircd_features.c` — Added FEAT_WHOIS_NETADMIN, FEAT_WHOIS_LOCOPER
- `include/ircd_features.h` — New feature enums
- `ircd/client.c` — Added P(NETADMIN) to privilege table, default off for global opers
- `ircd/ircd_parser.y` — Added TPRIV_NETADMIN token and parser rule
- Config keyword: `netadmin = yes/no;` in Operator/Class blocks

### Help System Rewrite

Rewrote all 104 command help strings to be descriptive and match modern
IRCd conventions. Each entry now shows syntax, parameters, and required
privileges. Empty strings remain only for internal server-only commands.

- `ircd/parse.c` — All msgtab help strings rewritten
- `ircd/m_help.c` — Changed branding to "Cathexis Help System"

### TAGMSG Command (IRCv3)

- `ircd/m_tagmsg.c` — New file. Accepts IRCv3 TAGMSG command to prevent
  ERR_UNKNOWNCOMMAND from modern clients (IRCCloud, The Lounge, gamja).
  Command is accepted and validated but tag relay is not yet implemented
  (requires ircd_tags infrastructure).
- `include/msg.h` — Added MSG_TAGMSG/TOK_TAGMSG/CMD_TAGMSG
- `include/handlers.h` — Added m_tagmsg declaration
- `ircd/parse.c` — Registered TAGMSG command
- `ircd/Makefile.in` — Added m_tagmsg.c to build

### Echo-Message (IRCv3)

- `ircd/ircd_relay.c` — Added echo-message support at 4 relay points:
  channel PRIVMSG, channel NOTICE, private PRIVMSG, private NOTICE.
  Clients negotiating the echo-message capability now receive a copy
  of their own messages back from the server, enabling proper message
  display in modern clients.

### Bug Fixes

- **echo-message cap disabled** — Cap was advertised but not implemented,
  causing clients (IRCCloud, The Lounge, etc.) that negotiated it to not
  display the user's own sent messages. Removed from active cap list in
  `ircd/m_cap.c`. Will be re-enabled when message relay infrastructure
  is added.
- **CONNEXIT_NOTICES default changed to TRUE** — Connection/exit notices
  now enabled by default (`ircd/ircd_features.c`). Opers with snomask
  +c will see client connects and quits.
- **client.h enum corruption fixed** — Restored proper enum structure
  for Flag and Priv enums that was broken by a deduplication error.
