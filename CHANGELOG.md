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
