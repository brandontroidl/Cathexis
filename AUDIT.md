# Cathexis Security Audit

**Codebase:** Nefarious2 (Cathexis fork), ~88,000 lines of C, 268 files
**Audit Date:** March 2026
**Version:** Cathexis 1.2.0
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
| Critical | 4     | 4     | 0         |
| High     | 7     | 7     | 0         |
| Medium   | 15    | 15    | 0         |
| Low      | 14    | 14    | 0         |
| Info     | 4     | —     | 4 (design notes) |

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

### C4 — Empty-Token Mechanism Dispatch Matches All Passwords (FIXED)

The `ircd_crypt()` mechanism dispatch loop calls `ircd_strncmp(token, salt, token_size)`. When `token_size == 0` (bcrypt, sha256, sha512 use empty tokens), `strncmp("", anything, 0)` always returns 0, matching every password hash to the first empty-token mechanism (bcrypt). Bcrypt's handler receives a `$6$` hash it doesn't recognize, generates a new bcrypt hash, and the comparison with the stored `$6$` hash fails. **This caused all SHA-256/SHA-512 passwords to produce "Password mismatch".**

**Fix:** Added `crypt_token_size == 0` skip in the dispatch loop. SHA/bcrypt are detected only by their dedicated `$5$`/`$6$`/`$2y$` prefix checks after the loop.

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

### H6 — Timing-Vulnerable Password Comparisons Across Codebase (FIXED)

Six files used `strcmp()` to compare passwords, channel keys, or hashed credentials. `strcmp()` exits on first mismatch, leaking information about how many leading characters match through execution time. An attacker with precise network timing could progressively recover secrets character by character.

| File | Comparison | Risk |
|------|-----------|------|
| `m_server.c:619` | Server link password | Server-to-server auth bypass |
| `s_conf.c:877` | WebIRC password | WebIRC spoofing |
| `s_conf.c:969` | SHost password | Host spoof bypass |
| `s_auth.c:570` | Client connection password | Auth block bypass |
| `m_join.c:176-178` | APASS/UPASS channel keys | Channel takeover |
| `m_join.c:191-193` | Channel mode +k key | Key recovery |

**Fix:** Created `include/ircd_crypto.h` with portable `ircd_constcmp()` (constant-time string comparison using `CRYPTO_memcmp` or volatile fallback) and `ircd_clearsecret()` (secure memory clearing). All six files updated. Password buffers cleared before `MyFree()`.

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
| M13 | m_oper.c | Credential enumeration via different error codes | Uniform ERR_NOOPERHOST for both paths |
| M14 | m_oper.c | No OPER brute force protection | 10-second cli_since penalty per failure |
| M15 | ircd.c | Default cloaking keys are public | Startup warning if keys match defaults or empty |
| M16 | ircd_defs.h | Client PASSWDLEN truncation at 20 chars | Increased to 128 |

---

## LOW Findings (All Fixed)

Replaced `strcpy` with `ircd_strncpy` in these files where the copy was exact-fit or nearly so but lacked explicit bounds:

s_auth.c, m_map.c, opercmds.c, numnicks.c, uping.c, whocmds.c, m_setname.c (CR/LF filter added), s_user.c, m_burst.c, m_names.c, m_whois.c (multi-prefix WHOIS), parse.c (SA* command registration), m_help.c (help system rewrite, array size 30→40), ircd_features.c (DNSBL features)

Additional low-severity fixes:
- `umkpasswd.c`: Three `abort()` calls replaced with `show_help(); exit(1);` — missing `-m` flag or conflicting options no longer produce a core dump

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

## Cryptography Modernization (1.2.0)

### Password Hashing

| Mechanism | Tag | Algorithm | Status |
|-----------|-----|-----------|--------|
| SHA-512 | `$6$` | crypt() `$6$`, 1M rounds | **Recommended** |
| SHA-256 | `$5$` | crypt() `$5$`, 1.2M rounds | Strong |
| bcrypt | `$2y$` | crypt() `$2y$`, cost 13 | Strong |
| native | `$CRYPT$` | System crypt() (varies) | Acceptable |
| Salted MD5 | `$SMD5$` | Custom MD5 + salt | **Rejected by default** |
| Plain | `$PLAIN$` | No hashing | **Rejected by default** |
| Plain | `$PLAIN$` | No hashing | **Deprecated** — logs warning |

Salt generation for all mechanisms uses `/dev/urandom` (16 bytes for SHA, bcrypt custom base64).

### bcrypt sizeof Fix

`generate_bcrypt_salt()` used `sizeof(salt)` where `salt` is a `char *` parameter. On x86_64, `sizeof(char *)` is 8, but the buffer is 30 bytes. The `snprintf` only wrote 8 bytes of the `$2y$XX$` prefix, producing a truncated salt. Fixed to use explicit size `30`.

### PRNG Replacement

| | Old (MD5-based) | New (/dev/urandom) |
|--|---|---|
| Entropy source | `gettimeofday()` microseconds | `/dev/urandom` kernel CSPRNG |
| Hash function | Custom MD5 | None needed (OS provides randomness) |
| OpenSSL integration | None | `RAND_bytes()` when available |
| Predictability | Attackable with timing info | Computationally infeasible |

### Host Cloaking

| | Legacy (MD5) | HMAC-SHA512 (default) |
|--|---|---|
| Hash function | Double MD5 (custom impl) | HMAC-SHA512 (OpenSSL) |
| Segment size | 24 bits (6 hex chars) | 64 bits (16 hex chars) |
| Classical brute-force | ~16M attempts/segment | ~18.4 quintillion/segment |
| Post-quantum (Grover) | ~4K attempts/segment | ~4.3 billion/segment |
| Feature toggle | `HOST_HIDING_HMAC = FALSE` | `HOST_HIDING_HMAC = TRUE` (default) |

**Migration note:** Changing `HOST_HIDING_HMAC` will change all cloaked hostnames on the network. All servers must use the same setting. Plan a coordinated switch during a maintenance window.

### Weak Password Gates

| Feature | Default | Effect |
|---------|---------|--------|
| `CRYPT_ALLOW_PLAIN` | FALSE | `$PLAIN$` passwords rejected at OPER time |
| `CRYPT_ALLOW_SMD5` | FALSE | `$SMD5$` passwords rejected at OPER time |

When the gate is FALSE, the server sends an `SNO_OLDSNO` notice saying "REJECTED" and refuses authentication. When TRUE, the password is accepted but a deprecation warning is still sent.

### TLS Cipher Hardening

| Setting | Default Value |
|---------|---------------|
| `SSL_CIPHERS` (TLS 1.2) | `ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES:!SEED:!IDEA` |
| `SSL_CIPHERSUITES` (TLS 1.3) | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` |
| `SSL_NOTLSV1` | TRUE |
| `SSL_NOTLSV1_1` | TRUE |

The cipher defaults prioritize 256-bit symmetric keys (AES-256-GCM first) which provide 128-bit post-quantum security under Grover's algorithm. ECDHE provides forward secrecy. When OpenSSL 3.5+ adds ML-KEM (Kyber) support, hybrid post-quantum key exchange will activate automatically through TLS 1.3 negotiation with no code changes required.

### Crypto Files Changed

| File | Change |
|------|--------|
| `ircd/ircd_crypt_sha.c` | New — SHA-256 (1.2M rounds) / SHA-512 (1M rounds) password mechanisms |
| `include/ircd_crypt_sha.h` | New — SHA mechanism declarations |
| `ircd/ircd_crypt_bcrypt.c` | Fixed sizeof(salt) bug, cost bumped to 13 |
| `ircd/random.c` | Rewritten — /dev/urandom + RAND_bytes CSPRNG |
| `ircd/ircd_cloaking.c` | Added HMAC-SHA512 cloaking (64-bit segments) |
| `include/ircd_cloaking.h` | Added HMAC cloaking declarations |
| `ircd/ircd_crypt.c` | Registered SHA, weak password gates, deprecation warnings |
| `ircd/umkpasswd.c` | Registered SHA mechanisms, crash fix (abort → exit) |
| `ircd/s_user.c` | HMAC-SHA512 cloaking dispatch |
| `include/ircd_features.h` | FEAT_HOST_HIDING_HMAC, FEAT_CRYPT_ALLOW_PLAIN/SMD5 |
| `ircd/ircd_features.c` | Feature entries, quantum-ready TLS cipher defaults |
| `include/ircd_crypto.h` | New — portable `ircd_constcmp()`, `ircd_clearsecret()` |
| `ircd/m_server.c` | Constant-time server link password comparison |
| `ircd/s_conf.c` | Constant-time WebIRC/SHost password comparison + secret clearing |
| `ircd/s_auth.c` | Constant-time client connection password comparison |
| `ircd/m_join.c` | Constant-time APASS/UPASS/channel key comparisons |
| `ircd/Makefile.in` | Added ircd_crypt_sha.c to build |
| `ircd/m_oper.c` | OPER brute force penalty, credential enumeration fix |
| `ircd/ircd.c` | Cloaking key startup safety check |
| `include/ircd_defs.h` | PASSWDLEN increased from 20 to 128 |
| `ircd/m_help.c` | HelpEntry array increased from 30 to 40 |

---

## Build Verification

The codebase compiles with 0 errors and 0 warnings under:
- Default flags: `gcc -g -O2`
- Strict flags: `gcc -Wall -pedantic -g -O2` with `--enable-debug --enable-warnings --enable-pedantic`
- Hardened flags: `gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wformat -Wformat-security`

Tested with gcc 14 on x86_64 Linux.
