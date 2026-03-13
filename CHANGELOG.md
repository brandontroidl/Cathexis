# Changelog

All notable changes to Cathexis IRCd, relative to upstream Nefarious2 (u2.10.12.14).

## [1.1.0] — 2026-03-13

### Added

**DNSBL (DNS Blacklist) System**
- Built-in DNSBL checking during client registration in `s_auth.c`
- Queries up to 3 DNSBL zones in parallel alongside DNS/ident lookups
- IPv4 reversed-octet and IPv6 reversed-nibble query format
- Two modes: reject listed IPs or mark them for oper review
- Timeout handling — clients treated as clean if DNSBL query doesn't respond
- Oper notices via SNO_CONNEXIT showing listed IP, zone, and result
- Preconfigured with dnsbl.dronebl.org, rbl.efnetrbl.org, torexit.dan.me.uk
- 7 new features: DNSBL, DNSBL_HOST, DNSBL_HOST2, DNSBL_HOST3, DNSBL_REJECT, DNSBL_REASON, DNSBL_MARK

**Channel Prefix Hierarchy (+q/+a)**
- Channel owner mode +q (~ prefix) — highest privilege tier
- Channel protect mode +a (& prefix) — above operator
- Full privilege enforcement: +q can set +q/+a/+o/+h/+v, +a can set +a/+o/+h/+v
- Kick protection: +q can only be kicked by +q, +a cannot be kicked by +o/+h
- OWNERPROTECT feature toggle — when FALSE, +a reverts to admin-only channel flag
- ISUPPORT PREFIX= adapts to all 4 combinations of OWNERPROTECT/HALFOPS
- +q/+a display in NAMES, WHO, WHOIS (multi-prefix aware)
- +q/+a in BURST for network synchronization
- Servers without OWNERPROTECT silently strip +q/+a from BURST/mode messages

**SA\* Commands (Network Administration)**
- 10 commands consolidated from 9 SVS* source files into single `m_sa.c`
- SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, SATOPIC, SAWHOIS, SAIDENT, SAINFO, SANOOP
- All require PRIV_NETADMIN (+N)
- All generate SNO_OLDSNO notices with full parameters (who, target, details)
- SAMODE calls mode_parse directly with MODE_PARSE_FORCE — no OPMODE dependency
- Wire tokens preserved from SVS* for rolling upgrade compatibility
- Both mo_ (oper) and ms_ (server S2S) handlers for each command
- ALLOWMODES_SVSMODE renamed to ALLOWMODES_SAMODE

**Help System**
- Complete rewrite of `m_help.c`
- Categorized index: User Commands, Oper Commands, Network Admin Commands, Reference Topics
- Verbose help for all 10 SA* commands with usage, examples, and privilege requirements
- Reference topics: USERMODES, CHANMODES, CHANPREFIXES, SNOMASK, OPERLEVELS, FEATURES

**Production Configuration**
- `ircd.conf` with 242 explicit feature settings covering the full daemon
- Oper block with complete privilege set including WHO visibility (show_invis, show_all_invis, whox, see_chan, etc.)
- CONFIG_OPERCMDS enabled
- DNSBL zones preconfigured
- All HIS privacy settings, IRCv3 caps, cloaking, extended modes, extended bans
- DIEPASS/RESTARTPASS placeholders
- Clone detection thresholds (IPCHECK_CLONE_LIMIT/PERIOD/DELAY)
- `doc/example.conf` updated with all new features and dead-zone warnings

**systemd Integration**
- `cathexis.service` unit file with NoNewPrivileges, ProtectSystem=strict, PrivateTmp
- `setup.sh` one-command installer (user creation, build, key generation, service install)

### Changed

**Security Hardening — Critical**
- `ircd_cloaking.c`: All 9 `strcpy(res+16, KEY*)` replaced with bounded `safe_key_copy()` helper
- `channel.c`: `get_channel()` enforces CHANNELLEN for all sources, not just local users
- `ircd_features.c`: DNSBL_HOST2/HOST3 declared with FEAT_NULL to prevent feature_init() crash

**Security Hardening — High**
- `client.c`: 4 privilege/mark accumulation functions — strcat chains replaced with position-tracked memcpy
- `m_privs.c`: strcat loop replaced with bounded memcpy
- `m_watch.c`: strcpy/strcat replaced with ircd_strncpy + bounded memcpy
- `os_generic.c`: Added missing `#include "ircd_snprintf.h"` (fixes -pedantic build)
- `ircd_snprintf.h`: Added `#ifndef va_copy` guard (fixes gcc 14 redefinition warnings)
- `channel.c`: 4 locations in modebuf pipeline updated to include MODE_OWNER/MODE_PROTECT in bitmasks

**Security Hardening — Medium**
- strcat replaced with bounded alternatives in: m_cap.c, m_check.c, m_whois.c, ircd_features.c, s_user.c, ircd_crypt_smd5.c, crule.c, s_misc.c
- `ircd_crypt.c`: Constant-time password comparison via CRYPTO_memcmp() with fallback
- `m_mode.c`: Operator gate updated to recognize +q/+a as having channel operator privileges
- `m_kick.c`: Kick permissions updated with full +q/+a hierarchy enforcement

**Security Hardening — Low**
- strcpy replaced with ircd_strncpy in: s_auth.c, m_map.c, opercmds.c, numnicks.c, uping.c, whocmds.c

**IRCv3 Compliance**
- `m_whois.c`: WHOIS shows all prefixes when multi-prefix negotiated (was missing, spec requires NAMES+WHO+WHOIS)
- `m_setname.c`: Error responses use FAIL SETNAME INVALID_REALNAME standard replies
- `s_user.c`: NAMELEN added to RPL_ISUPPORT (required by setname spec)

**Mode Handling**
- `m_mode.c`: +q/+a users recognized as channel operators for mode changes
- `m_kick.c`: +q/+a users recognized for kick permissions with hierarchy enforcement
- `channel.c`: `is_chan_op()` recognizes +q/+a as having operator status

**Documentation**
- `doc/features.txt`: Appended Cathexis 1.1.0 section (DNSBL, +q/+a, SA* commands)
- `doc/modes.txt`: Updated +a dual role, added +q channel owner
- `doc/snomask.txt`: Updated snomask o and c descriptions

### Removed

- 9 SVS* source files: m_svsjoin.c, m_svspart.c, m_svsnick.c, m_svsmode.c, m_svsquit.c, m_svsident.c, m_svsinfo.c, m_svsnoop.c, m_swhois.c (all consolidated into m_sa.c)
- All strcat() calls from the codebase (0 remaining)

### Fixed

- SAMODE channel modes now display nick parameters correctly (was showing `*` instead of target nick)
- All 10 SA* commands properly registered in parse.c message table (7 were missing after SVS* cleanup)
- Feature init crash when DNSBL_HOST2/HOST3 are empty (FEAT_NULL flag)
- Build error with -pedantic flag (missing include in os_generic.c)
- va_copy redefinition warnings with gcc 14+ (guard in ircd_snprintf.h)
- +q/+a member status bits actually stored on membership (mode_process_clients bitmask fix)
- Orphaned dependency lines in Makefile.in after SVS* file removal (39 lines)
- engine_epoll.c crash with `_syscall1` fallback on modern Linux when `-pg`/`-pedantic` causes configure's epoll link test to fail (removed ancient fallback, uses proper glibc epoll functions)

## [1.0.0] — 2026-03-11

### Added

- Initial security hardening of Nefarious2 codebase
- All sprintf() in runtime code replaced with ircd_snprintf()
- SETNAME CR/LF injection filtering
- Separate client/server SETNAME handlers
- SSL certificate verification logging

### Changed

- Version scheme: major.minor.patch
- Patchlevel string: `+Cathexis(1.0.0)`
