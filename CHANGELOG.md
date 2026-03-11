# Cathexis Changelog

## 1.1.0 — 2026-03-11

Security hardening release. All vulnerabilities identified in the 10-pass
security audit have been remediated in-source. Zero compiler warnings.

### Security Fixes (CRITICAL)

- **ircd_cloaking.c** — Replaced all 9 `strcpy(res+16, KEY*)` calls with
  bounded `safe_key_copy()` helper. Prevents stack buffer overflow when
  cloaking keys exceed 496 bytes (MA-01). Also replaced `strcat()` in
  `hidehost_normalhost()` with `strncat()`.

- **channel.c** — `get_channel()` now enforces `CHANNELLEN` for ALL
  sources, not just local users. Previously a rogue server could
  introduce over-length channel names that overflow `CHANNELLEN+1`
  buffers in mode parsing (TF-01, Patch 4).

- **ircd_crypt.c** — Added constant-time `CRYPTO_memcmp()` fallback
  for non-SSL builds, preserving timing-safe password comparison.

### Security Fixes (HIGH)

- **client.c** — Rewrote all 4 privilege/mark accumulation functions
  (`client_check_privs`, `client_send_privs`, `client_sendtoserv_privs`,
  `client_check_marks`) to use position-tracked `memcpy` with explicit
  bounds checking instead of `strcat` chains (MA-03, Patch 6).

- **m_privs.c** — Replaced `strcat` loop in `ms_privs()` with bounded
  `memcpy` construction (MA-05, Patch 3).

- **m_watch.c** — Replaced `strcpy`/`strcat` with `ircd_strncpy` and
  bounded `memcpy` in watch list display (MA-02).

### Security Fixes (MEDIUM — strcat → strncat/bounded)

All remaining `strcat()` calls across the codebase replaced:

- **m_cap.c** — Capability list accumulation
- **m_check.c** — All 20+ `strcat` calls (status flags, eflags, mode
  buffers, channel text accumulation)
- **m_whois.c** — Mark display and channel list accumulation
- **ircd_features.c** — ISUPPORT MAXLIST/EXTBAN construction
- **s_user.c** — ISUPPORT MAXLIST/EXTBAN, user mode buffer
- **ircd_crypt_smd5.c** — Salt construction
- **crule.c** — Connection rule argument parsing
- **s_misc.c** — Netsplit comment construction

### Security Fixes (LOW — strcpy → ircd_strncpy)

Defense-in-depth replacements for `strcpy` of bounded values:

- **s_auth.c** — `cli_sockhost` copy
- **s_misc.c** — `ctime()` result copy
- **m_map.c** — Tree prompt literal
- **opercmds.c** — Timestamp literal
- **numnicks.c** — Numeric nick copy
- **uping.c** — Server name copy
- **whocmds.c** — "n/a" literal

### Compiler Warning Fixes

- **s_bsd.c** — Suppressed 4 `write()` return value warnings with
  proper `__attribute__((unused))` pattern.

### IRCv3 Compliance Fixes

- **m_whois.c** — WHOIS channel list now shows all applicable prefixes
  (`@%+`) when client has negotiated `multi-prefix`, matching the IRCv3
  multi-prefix specification requirement for NAMES, WHO, and WHOIS.

- **m_setname.c** — Error responses changed from `ERR_NEEDMOREPARAMS` to
  IRCv3 standard-replies `FAIL SETNAME INVALID_REALNAME` format per the
  setname specification.

- **s_user.c** — Added `NAMELEN` token to RPL_ISUPPORT (005) as required
  by the IRCv3 setname specification.

### Build

- Zero compiler errors
- Zero compiler warnings
- `./configure && make && make install` verified clean
- 22 source files modified from 1.0.0

### Files Changed (22)

**Security (critical):** ircd_cloaking.c, channel.c, ircd_crypt.c

**Security (buffer hardening):** client.c, m_privs.c, m_watch.c,
m_cap.c, m_check.c, m_whois.c, ircd_features.c, s_user.c,
ircd_crypt_smd5.c, crule.c, s_misc.c

**Security (defense-in-depth):** s_auth.c, m_map.c, opercmds.c,
numnicks.c, uping.c, whocmds.c

**IRCv3 compliance:** m_whois.c, m_setname.c, s_user.c

**Compiler warnings:** s_bsd.c

**Version/docs:** patchlevel.h, CHANGELOG.md, AUDIT.md, MEMORY_AUDIT.md,
PATCH_DIFFS.md, PRIVILEGE_ANALYSIS.md, EXPLOIT_ANALYSIS.md,
TAINT_ANALYSIS.md, DESYNC_ANALYSIS.md, CATHEXIS_SECURITY_AUDIT.md,
example.conf

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

### SVS* Commands — Network Administrator Access

All SVS commands now have `mo_*` oper handlers requiring `PRIV_NETADMIN`.
Network Administrators can use these directly without raw server lines:

  /SVSJOIN <nick> <#channel>          Force a user to join a channel
  /SVSPART <nick> <#channel> [:msg]   Force a user to part a channel
  /SVSNICK <nick> <newnick>           Force a nickname change
  /SVSMODE <nick> <modes>             Force user mode changes
  /SVSQUIT <nick> [:reason]           Force a user to disconnect
  /SVSIDENT <nick> <newident>         Change a user's ident
  /SVSINFO <nick> :<newrealname>      Change a user's realname
  /SVSNOOP <server> <+/->             Enable/disable NOOP on a server
  /SWHOIS <nick> [:<text>]            Set/clear custom WHOIS line

All commands log to SNO_OLDSNO for audit trail.
Server-to-server handlers (ms_*) remain for services compatibility.

Files changed: m_svsjoin.c, m_svspart.c, m_svsnick.c, m_svsmode.c,
m_svsquit.c, m_svsident.c, m_svsinfo.c, m_svsnoop.c, m_swhois.c,
handlers.h, parse.c

### IRCv3 CAP LS 302 Support

- `ircd/m_cap.c` — cap_ls() now parses the version parameter from
  `CAP LS 302`. Version is stored in `con_capver`. Clients requesting
  302 automatically get cap-notify enabled (per IRCv3 spec).

### SA* Commands — Direct Oper Interface (replaces SVS* for opers)

Added 7 SA* (Server Admin) commands as the oper-facing interface,
matching UnrealIRCd/InspIRCd conventions:

  /SAJOIN <nick> <#channel>      Force join (no services needed)
  /SAPART <nick> <#channel>      Force part
  /SANICK <nick> <newnick>       Force nick change
  /SAMODE <target> <modes>       Force mode change (users and channels)
  /SAQUIT <nick> [:reason]       Force disconnect
  /SATOPIC <#channel> :<topic>   Force topic change
  /SAWHOIS <nick> [:<text>]      Set/clear custom WHOIS line

All require PRIV_NETADMIN (+N). All log actions to SNO_OLDSNO.
Remote targets propagate via SVS* S2S protocol automatically.
Non-opers see "Permission Denied". Non-netadmins see "No privileges".

SVS* commands remain as server-to-server protocol for services
compatibility (X3, Atheme, anope, etc.).

New files: ircd/m_sa.c, include/msg.h (SA defines)
Changed: parse.c, handlers.h, Makefile.in

### Help System Rewrite

Completely rewritten /HELP with categories and multi-line help:

  /HELP              Categorized command index
  /HELP <command>    Detailed multi-line help for any command
  /HELP USERMODES    User mode reference table
  /HELP CHANMODES    Channel mode reference table
  /HELP SNOMASK      Server notice mask letter reference
  /HELP OPERLEVELS   Oper hierarchy reference

Extended help entries for all SA* commands with usage, examples,
and privilege requirements. Falls back to msgtab one-liners for
commands without extended entries.

New file: ircd/m_help.c (complete rewrite)

### SA* Commands — Network Administrator Access

SA commands require PRIV_NETADMIN (+N, `netadmin = yes` in oper block).
Opers with the netadmin privilege get +N on /OPER and gain access to
all SA commands (SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, SATOPIC, SAWHOIS).

The oper hierarchy for SA* access:
  netadmin = yes  →  +N mode set on /OPER  →  SA* commands enabled

### SA* Commands — Network Administrator Only (final)

SA commands require PRIV_NETADMIN (+N, `netadmin = yes`).
No services needed to use them. Oper block example:

    Operator {
      name = "admin";
      netadmin = yes;    # Grants +N and SA* access
    };
