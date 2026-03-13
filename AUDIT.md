# Cathexis Security Audit

**Codebase:** Nefarious2 (Cathexis fork), ~88,000 lines of C, 268 files
**Audit Date:** March 2026
**Version:** Cathexis 1.1.0
**Scope:** Full source review — 177 .c files, 89 .h files
**Status:** All identified findings fixed and applied to source

---

## Executive Summary

The Nefarious2 codebase is a mature, production-grade IRC daemon with sound architectural fundamentals. The core buffer handling in `packet.c` and `parse.c` is correct by construction. No remote code execution vulnerabilities were identified.

The primary findings were systematic use of unsafe C string functions (`sprintf`, `strcpy`, `strcat`) that, while individually bounded by context in most cases, represented a fragile defense posture. All instances have been remediated. Additional work includes a DNSBL system, channel prefix hierarchy (+q/+a/+o/+h/+v), SVS*-to-SA* command consolidation, and comprehensive configuration hardening.

---

## Risk Summary

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 3     | 3     | 0         |
| High     | 5     | 5     | 0         |
| Medium   | 12    | 12    | 0         |
| Low      | 14    | 14    | 0         |
| Info     | 3     | —     | 3 (P10 protocol design) |

---

## CRITICAL Findings

### C1 — Stack Buffer Overflow in ircd_cloaking.c (FIXED)

9 calls to `strcpy(res+16, KEY*)` in `ircd_cloaking.c` where `KEY1/KEY2/KEY3` are operator-configurable strings with no length limit. If a cloaking key exceeds 496 bytes, these overflow the 512-byte stack buffer.

**Fix:** Replaced all 9 calls with `safe_key_copy()` helper that enforces bounded copy.

### C2 — Channel Length Bypass via Server Source (FIXED)

`get_channel()` in `channel.c` only enforced `CHANNELLEN` for local users. A rogue or compromised server could send channel names exceeding the buffer size, overflowing fixed-size arrays throughout the codebase.

**Fix:** CHANNELLEN enforcement applied to all sources (local and server).

### C3 — Feature Init Crash on NULL String Defaults (FIXED)

`DNSBL_HOST2` and `DNSBL_HOST3` features declared as string type with NULL defaults but without the `FEAT_NULL` flag. `feature_init()` asserts non-NULL defaults for string features, causing `ircd -k` and normal startup to abort.

**Fix:** Added `FEAT_NULL` flag to both feature declarations.

---

## HIGH Findings

### H1 — strcat Accumulation Chains in client.c (FIXED)

Four privilege/mark accumulation functions in `client.c` used unbounded `strcat` chains to build output strings. While individually unlikely to overflow, the pattern is fragile and a single new privilege could trigger it.

**Fix:** All 4 functions converted to position-tracked `memcpy` with explicit bounds checking.

### H2 — strcat Loop in m_privs.c (FIXED)

`strcat` loop building privilege string in `m_privs.c` with no bounds tracking.

**Fix:** Replaced with bounded `memcpy` with position tracking.

### H3 — strcpy/strcat in m_watch.c (FIXED)

`strcpy` and `strcat` used to build WATCH response strings.

**Fix:** Replaced with `ircd_strncpy` and bounded `memcpy`.

### H4 — Missing Includes for Pedantic Builds (FIXED)

`os_generic.c` called `ircd_snprintf()` without including `ircd_snprintf.h`. This compiled under default flags (implicit function declaration is a warning) but failed under `-pedantic` (implicit declarations are errors), and the `memcpy`-based `va_copy` fallback produced incorrect code on x86_64.

**Fix:** Added missing `#include "ircd_snprintf.h"`. Also added `#ifndef va_copy` guard in `ircd_snprintf.h` to prevent redefinition warnings with gcc 14+ which provides `va_copy` as a builtin.

### H5 — modebuf Pipeline Missing +q/+a Support (FIXED)

Four locations in the `modebuf` pipeline in `channel.c` only knew about `MODE_CHANOP | MODE_HALFOP | MODE_VOICE`. When +q or +a modes were set, the mode letters appeared in output but nick parameters were replaced with `*`, and the actual member status bits were never stored.

**Fix:** All four locations updated to include `MODE_OWNER | MODE_PROTECT` in their bitmasks.

---

## MEDIUM Findings (All Fixed)

| ID | File | Issue | Fix |
|----|------|-------|-----|
| M1 | m_cap.c | strcat building CAP response | strncat with bounds |
| M2 | m_check.c | strcat in CHECK output | strncat with bounds |
| M3 | m_whois.c | strcat building WHOIS channels | strncat with bounds |
| M4 | ircd_features.c | strcat in feature dump | strncat with bounds |
| M5 | s_user.c | strcat building ISUPPORT | strncat with bounds |
| M6 | ircd_crypt_smd5.c | strcat in salt generation | strncat with bounds |
| M7 | crule.c | strcat in rule error messages | strncat with bounds |
| M8 | s_misc.c | strcat in server info | strncat with bounds |
| M9 | m_mode.c | Missing +q/+a in operator gate | Added IsOwner/IsProtect checks |
| M10 | m_kick.c | Missing +q/+a in kick permission | Added hierarchy enforcement |
| M11 | m_kick.c | Missing +q/+a in S2S bounce check | Added IsOwner/IsProtect |
| M12 | ircd_crypt.c | Non-constant-time password compare | CRYPTO_memcmp with fallback |

---

## LOW Findings (All Fixed)

Replaced `strcpy` with `ircd_strncpy` in these files where the copy was exact-fit or nearly so but lacked explicit bounds:

s_auth.c, m_map.c, opercmds.c, numnicks.c, uping.c, whocmds.c, m_setname.c (CR/LF filter added), s_user.c, m_burst.c, m_names.c, m_whois.c (multi-prefix WHOIS), parse.c (SA* command registration), m_help.c (help system rewrite), ircd_features.c (DNSBL features)

---

## Remaining (Info — P10 Protocol Design)

These cannot be fixed without a protocol redesign:

1. **S2S message authentication** — P10 uses trust-based server authentication. Messages from servers are accepted without per-message verification.
2. **Desync scenarios** — Split-brain conditions during netsplits can cause channel state divergence. This is inherent to the P10 BURST mechanism.
3. **SVS* source restriction** — The protocol trusts that SVS/SA commands originate from authorized services. There is no cryptographic verification of the source.

---

## Files Changed

### Security Hardening (1.0.0 + 1.1.0)

| File | Changes |
|------|---------|
| ircd/ircd_cloaking.c | `safe_key_copy()` for all 9 KEY copies |
| ircd/channel.c | CHANNELLEN enforcement, +q/+a modebuf support, is_chan_op +q/+a awareness, mode_process_clients +q/+a member status |
| ircd/client.c | 4 strcat chains → bounded memcpy |
| ircd/m_privs.c | strcat loop → bounded memcpy |
| ircd/m_watch.c | strcpy/strcat → ircd_strncpy + bounded memcpy |
| ircd/m_cap.c | strcat → strncat |
| ircd/m_check.c | strcat → strncat |
| ircd/m_whois.c | strcat → strncat, multi-prefix WHOIS |
| ircd/ircd_features.c | strcat → strncat, DNSBL features, OWNERPROTECT feature, FEAT_NULL fix |
| ircd/s_user.c | strcat → strncat, NAMELEN in ISUPPORT |
| ircd/ircd_crypt_smd5.c | strcat → strncat |
| ircd/crule.c | strcat → strncat |
| ircd/s_misc.c | strcat → strncat |
| ircd/s_auth.c | strcpy → ircd_strncpy, DNSBL system |
| ircd/m_mode.c | +q/+a operator gate |
| ircd/m_kick.c | +q/+a kick hierarchy |
| ircd/m_setname.c | CR/LF filter, FAIL standard replies |
| ircd/ircd_crypt.c | Constant-time password compare |
| ircd/os_generic.c | Missing include fix |
| include/ircd_snprintf.h | va_copy guard for gcc 14+ |
| include/channel.h | CHFL_OWNER, CHFL_PROTECT, MODE_OWNER, MODE_PROTECT |
| include/ircd_features.h | FEAT_OWNERPROTECT, FEAT_DNSBL_* |

### Feature Additions

| File | Feature |
|------|---------|
| ircd/m_sa.c | All 10 SA* commands (consolidated from 9 SVS* files) |
| ircd/m_help.c | Complete /HELP system rewrite |
| ircd/s_auth.c | DNSBL lookup system |
| ircd/channel.c | +q (owner) and +a (protect) prefix modes |
| ircd/m_names.c | +q/+a prefix display |
| ircd/whocmds.c | +q/+a prefix in WHO |
| ircd/m_whois.c | +q/+a prefix in WHOIS |
| ircd/m_burst.c | +q/+a in BURST |
| ircd/parse.c | All 10 SA* command registration |
| include/msg.h | MSG/TOK/CMD for all SA* commands |
| include/handlers.h | Handler declarations for all SA* commands |

### Configuration

| File | Description |
|------|-------------|
| ircd.conf | Production config, 242 features, full oper privileges |
| doc/ircd.conf | Copy of production config |
| doc/example.conf | Upstream reference with DNSBL, WHOIS labels, all new features |
| cathexis.service | systemd unit with security hardening |
| setup.sh | One-command install script |

---

## Build Verification

The codebase compiles with 0 errors and 0 warnings under:
- Default flags: `gcc -g -O2`
- Strict flags: `gcc -Wall -pedantic -g -O2` with `--enable-debug --enable-warnings --enable-pedantic`

Tested with gcc 14 on x86_64 Linux.
