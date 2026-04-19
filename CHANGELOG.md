# Cathexis IRCd Changelog

## 1.6.0 (2026-04-19) — Post-quantum cryptography + S2S_CSYNC + CAP_sts + HOST_HIDING_HMAC

Major release. Introduces NIST-standardized post-quantum authentication on server-to-server links, wires up the three features that were documented but unimplemented in prior versions, and upgrades all s2s symmetric primitives to SHA3-512.

### Build requirements (BREAKING)
- **OpenSSL >= 3.5.0** required (for native ML-KEM hybrid TLS key exchange and ML-DSA signatures). Hard-requirement in `configure.in` + `configure`.
- **liboqs (Open Quantum Safe)** required (for ML-DSA-87 + SLH-DSA-SHAKE-256f dual signatures in the s2s layer). Install `liboqs-dev` on Debian/Ubuntu, or build from <https://github.com/open-quantum-safe/liboqs> with `-DOQS_ENABLE_SIG_ML_DSA_87=ON -DOQS_ENABLE_SIG_SPHINCS=ON`.
- Existing OpenSSL 3.0.x / 1.1.x deployments will fail configure with a clear error message directing them to upgrade.

### Post-quantum cryptography
- New module `pq_crypto.c` / `include/pq_crypto.h` (~480 LOC). Implements:
  - **Dual-signature keypair** — ML-DSA-87 (FIPS 204 Category 5, lattice-based) as primary + SLH-DSA-SHAKE-256f (FIPS 205 Category 5, hash-based) as secondary. Both must verify; a break in either family leaves the other protecting the link.
  - **`PQKeypair` struct** + generate / load / save / free lifecycle via liboqs
  - **`pq_sign_dual` / `pq_verify_dual`** with little-endian wire format: `[alg:2][siglen:4][sig:N]` repeated for both signatures
  - **Keyfile format** — text, labeled base64 blocks, mode-0600 enforced on load (refuses group/other readable)
  - **HMAC-SHA3-512** via `EVP_MAC` (OpenSSL 3.5+)
  - **HKDF-SHA3-512** via `EVP_KDF`
  - **`pq_derive_s2s_mac_key`** — derives 64-byte s2s MAC key with label `"cathexis-s2s-hmac-sha3-v2"`

- `s2s_crypto.c` upgrades:
  - `S2SKey` struct grown: `hmac_key[64]`, `sacert_key[64]`, `peer_pqfp[32]`, `pq_active`, `pq_required` fields
  - `compute_link_mac()` abstraction: HMAC-SHA3-512 on USE_PQ, HMAC-SHA256 on fallback
  - `s2s_derive_keys()` uses HKDF-SHA3-512 with `v2` labels when PQ is compiled in — **breaking change**: pre-1.6.0 `v1` HMAC-SHA256 derivations will NOT interoperate with 1.6.0 peers, so link both ends at the same time
  - All sign/verify paths use dynamic MAC width (64 or 32 bytes) via `s2s_mac_len()` / `s2s_mac_hexlen()`
  - `s2s_channel_hash()` uses SHA3-512 (128 hex chars) on USE_PQ
  - New PQ link-auth helpers: `s2s_pq_sign_challenge`, `s2s_pq_verify_challenge`, `s2s_pq_fingerprint` (SHA3-256 of concatenated public keys)
  - New `S2S_PQSIG_TAG "@pqsig="` constant for future per-command PQ signatures

- **TLS hybrid key exchange** default changed to `X25519MLKEM768:X25519:P-256` in `FEAT_SSL_GROUPS`. Hybrid ML-KEM-768 + X25519 is preferred; X25519 and P-256 provide classical fallback. Client context (outgoing s2s TLS) now also applies the same group list, cipher list, and TLS 1.3 ciphersuites as the server context — fixing a pre-1.6.0 bug where s2s-outbound used whatever OpenSSL's defaults happened to be.

### New features (via `ircd_features.c`)
- `FEAT_PQ_POSTURE` (int, default 1=PREFERRED) — 0=DISABLED, 1=PREFERRED, 2=REQUIRED
- `FEAT_PQ_KEYFILE` (string, default `"pq_keys.cathexis"`)
- `FEAT_PQ_PEER_KEYDIR` (string, default `"pq_peers"`)
- `FEAT_HOST_HIDING_HMAC` (bool, default TRUE) — forces `HOST_HIDING_STYLE` to 2 (HMAC cloaking). New helper `feature_effective_host_hiding_style()` honors this override; all 33 call sites across 7 files (`channel.c`, `m_account.c`, `m_oper.c`, `m_sasl.c`, `m_userip.c`, `m_webirc.c`, `s_user.c`) migrated from `feature_int(FEAT_HOST_HIDING_STYLE)` to the helper
- `FEAT_S2S_CSYNC` (bool, default TRUE)
- `FEAT_S2S_CSYNC_MAX_PER_SECOND` (int, default 50)
- `FEAT_CAP_STS_ENABLED` (bool, default TRUE)
- `FEAT_CAP_STS_DURATION` (int, default 2592000 = 30 days)
- `FEAT_CAP_STS_PORT` (int, default 6697)
- `FEAT_CAP_STS_PRELOAD` (bool, default FALSE)

### S2S_CSYNC — channel state verification (implemented)
- New command `CHASH` / token `CH` (server-only, `MSG_CHASH`/`TOK_CHASH` in `include/msg.h`)
- New handler `ms_chash` in `ircd/m_chash.c` (~180 LOC). Accepts `:sid CH #channel <hexhash>` from peers, runs `s2s_channel_verify()`, and logs + emits SNO_NETWORK on mismatch. Empty hash argument is reserved for future re-burst requests.
- Rate-limited via `FEAT_S2S_CSYNC_MAX_PER_SECOND` (default 50/sec)
- Emission wired into `ms_end_of_burst` in `ircd/m_endburst.c`: after clearing BURSTADDED flags, iterates `GlobalChannelList` and emits one CHASH per populated non-local (`#` not `&`) channel. Rate-limit circuit breaker stops emission and emits an SNO_NETWORK notice if the per-second cap is hit.
- Detection-only in 1.6.0 — explicit re-burst on mismatch left as a deliberate follow-on so operators can observe real-world mismatch rates before auto-remediation is enabled.

### CAP_STS — IRCv3 STS capability (implemented)
- STS was pre-wired in `m_cap.c` as `_CAP(STS, CAPFL_PROHIBIT, "sts", 0)` but never enabled because the referenced features (`FEAT_STS_PORT` / `FEAT_STS_DURATION`) were never registered. 1.6.0 fixes this: removed `CAPFL_PROHIBIT`, tied visibility to `FEAT_CAP_STS_ENABLED`, and corrected the feature names to `FEAT_CAP_STS_PORT` / `FEAT_CAP_STS_DURATION` / `FEAT_CAP_STS_PRELOAD`.
- Dynamic cap value: `sts=port=6697,duration=2592000` (plus `,preload` when `FEAT_CAP_STS_PRELOAD` is TRUE)
- Only advertised on CAP LS 302+ per IRCv3 spec; legacy CAP LS clients don't see it.

### HOST_HIDING_HMAC (implemented)
- Was documented but unimplemented in prior versions (`doc/example.ircd.conf` referenced `"HOST_HIDING_HMAC" = "TRUE"` but rehash logged "Unknown feature HOST_HIDING_HMAC"). Now registered as a real feature that forces the cloaking style to 2 (HMAC-SHA3-512 as of 1.6.0) when TRUE. Default is TRUE.

### DNSBL mark format extension (carryover from 1.5.6 draft)
- `s_auth.c` tracks all matching zones (up to 3, matching the config cap), not just the first
- Extended mark format: `"DNSBL|zone1|zone2|zone3"` (pipe-separated). Legacy plain `"DNSBL"` still works for services that don't parse zones.
- Downstream consumer: Noesis Sentinel uses the zone list for weighted multi-zone scoring (see noesis-1.1.0).

### Documentation
- `doc/features.txt` rewritten to truthfully describe all implemented features; pre-1.6.0 "known issue: documented but not registered" items for HOST_HIDING_HMAC / S2S_CSYNC / CAP_sts are now gone because the implementations landed.
- `doc/example.ircd.conf` config blocks referencing the new features no longer produce "Unknown feature" warnings on rehash.
- New doc entry for the PQ feature triad + dual-signature rationale.

### Migration notes
- If running in a mixed-version network (some nodes on 1.5.x, some on 1.6.0), `FEAT_PQ_POSTURE=1` (PREFERRED, default) lets you stagger upgrades. Set `PQ_POSTURE=2` (REQUIRED) only after all nodes are on 1.6.0+.
- The s2s HMAC-SHA256 → HMAC-SHA3-512 switch at v1→v2 label is **not interoperable** between 1.5.x and 1.6.0 for signed links. Either upgrade link pairs simultaneously, or temporarily set the Connect block's `hmac = no` on both ends to bypass signing during the staggered upgrade window.
- Oper, NickServ, and ChanServ password hashes (Argon2id) are unchanged — already quantum-safe.

## 1.5.5 (2026-04-19)

### Removed — orphan headers and dead utf8 module
Deleted four header files and one source file that had zero callers anywhere in the tree — dead code shipping in `include/` and `ircd/`. All removals verified by a full build with the pruned tree (`./configure && make`) which produced a working `ircd` binary.

- `include/capab_ircv3_ext.h` — defined `CAP_CHATHISTORY`, `CAP_READMARKER`, `CAP_PREAWAY` macros that were never referenced outside the header itself. The real CAP bits are in `m_cap.c`.
- `include/ircd_botmode.h` — header with a comment block listing "integration points" (`client.h`, `s_user.c`, `whocmds.c`, `s_misc.c`, `m_cap.c`, `send.c`) that were never actually integrated. Zero external callers.
- `include/oper_levels.h` — defined `OPER_LEVEL_*` constants (0-5) and `CanUseSACommands` macro. No code referenced the symbols. Oper hierarchy is handled via the existing `FLAG_*` macros in `client.h`.
- `include/ircd_utf8.h` + `ircd/ircd_utf8.c` — exported `ircd_is_valid_utf8()` which had exactly zero callers. The UTF-8 validation never got wired into message processing; the function was a self-contained orphan.

### Rationale
These files were stub work that got written but never integrated. Shipping them in the tree misleads anyone auditing the build because `#include "ircd_botmode.h"` and `#include "ircd_utf8.h"` imply those features exist when they don't. Cleaner to remove them than to leave broken scaffolding.

## 1.5.4 (2026-04-19)

### Docs / Config
- **Stale `--with-geoip` mentions purged** — Cathexis dropped legacy libGeoIP support in 1.4.0 (MMDB-only since), but the `ircd.conf`, `doc/ircd.conf`, and `config.h.in` still referenced the old flag/paths. Updated the three breadcrumbs so nobody reading the shipped docs expects a `--with-geoip` option that no longer exists. No code or build behavior change.

## 1.5.3 (2026-04-19)

### Build
- **`--with-leak-detect` against modern libgc (`ircd/memdebug.c`)** — The leak-detector path was written against a patched Boehm GC 6.0 from 2001 (documented in the source comment) whose `GC_set_leak_handler()` symbol does not exist in modern libgc 7.x/8.x. Any build with `--with-leak-detect` (or `-DMDEBUG`) failed to link `umkpasswd` with `undefined reference to GC_set_leak_handler`. Changed the forward declaration to be elided and the single call site to use a function-local `__attribute__((weak))` reference, so modern libgc links cleanly (handler not installed, `GC_find_leak = 1` alone still produces leak reports) and the historical patched gc6.0 path still works if present.
- **Test binary link with `-DMDEBUG` (`ircd/test/Makefile.in`)** — When `--with-leak-detect` is active, global `CFLAGS` picks up `-DMDEBUG`, so `numnicks.o` (linked into `ircd_in_addr_t`) references `dbg_malloc_zero` from `memdebug.o`. The test Makefile didn't link `memdebug.o`, causing `undefined reference to dbg_malloc_zero`. Added `../memdebug.o` to `IRCD_IN_ADDR_T_OBJS` and forwarded the top-level `CFLAGS`, `LDFLAGS`, and `LIBS` to the test binaries so they link against `-lgc` when needed.

## 1.5.2 (2026-04-19)

### Security
- **WHO mark output buffer overflow (`ircd/whocmds.c`)** — Stack buffer overflow in the marks-output path of the WHO reply. The truncation arithmetic was wrong: `strncpy` was bounded by the *remaining* space after the current mark, while the destination pointer advanced by the mark's *full* length, writing past `markbuf[128]` when cumulative marks neared the buffer size. Rewrote the loop to check `p2 + marklen + 2 > pend` before each copy, use `memcpy` with the source length, and use `ircd_strncpy` for the `*ManyMarks*` overflow fallback (previously a raw `strncpy` with no guaranteed NUL termination). Reachable by any user with `+M` who accumulates marks long enough.

### Crypto
- **S2S HMAC key zeroization (`ircd/s_serv.c`)** — Replaced `memset(&tmpkey, 0, sizeof(tmpkey))` on the stack-scoped `struct S2SKey` with `OPENSSL_cleanse(&tmpkey, sizeof(tmpkey))`. The memset was subject to dead-store elimination because `tmpkey` goes out of scope immediately after; HMAC key material could remain on the stack after link establishment. Matches the pattern already used in `ircd/ircd_cloaking.c`.

## 1.5.1 (2026-04-12)

### IRCv3
- **TAGMSG relay** — Full implementation replacing the previous stub. Raw client tags (`+react`, `+typing`, `+reply`) preserved during parsing via `parse_get_raw_tags()`, relayed to channel members with `message-tags` CAP enabled. Echo-message support. Server-time and msgid tags added to outgoing messages. Enables reactions and typing indicators in Lexis/IRCCloud.
- **MARKREAD silent accept** — No longer echoes back to sender, preventing infinite 2-second loop with IRCCloud/Lexis. Unregistered client handler changed from `m_unregistered` to `m_ignore` to prevent 451 flood during CAP negotiation.

### Build
- **ircd_msgid.c** — Added to `Makefile.in` source list (was missing, caused linker error). Fixed includes: uses direct `RAND_bytes`/`OPENSSL_cleanse` with `#ifdef USE_SSL` guards instead of non-existent `ircd_random_bytes()`.

### Bug Fixes
- **parse.c** — Raw client tags preserved in static buffer during parsing, accessible via `parse_get_raw_tags()` for TAGMSG relay.
- **send.h** — Added `extern const char *parse_get_raw_tags(void)` declaration.

## 1.5.0 (2026-04-09)

### Security
- **Per-link S2S HMAC authentication** — HMAC-SHA256 per-message signing/verification on server-to-server links. Each Connect block can independently enable HMAC with `hmac = yes`. Requires `S2S_HMAC = TRUE` globally. Key derived from link password using `HMAC-SHA256(password, "cathexis-s2s-hmac-v1")`.
- **CONF_HMAC flag collision fixed** — `CONF_HMAC` was 0x0100, same as `CONF_NOIDENTTILDE`. Changed to 0x0200.
- **SASL numeric table fixed** — 9 missing `{ 0 }` placeholder entries at positions 750-760 in `s_err.c` shifted all SASL numerics (903-908), causing ERR_SASLFAIL (904) to abort the server on SASL timeout. Fixed.
- **Non-fatal error numeric lookups** — `get_error_numeric()` and `rpl_str()` now return generic fallbacks instead of calling `assert(abort)` on missing numerics. The server will never crash from a missing error string.

### Build System
- **Pre-generated parser files** — `y.tab.c`, `y.tab.h`, `lex.yy.c` are now tracked in git and included in distribution tarballs. Building no longer requires bison/flex unless modifying the parser.
- **`make clean` preserves parser files** — only `make maintainer-clean` deletes generated parser files. Standard autotools practice.
- **Better error messages** — if parser regeneration is needed but bison/flex are missing, clear instructions are printed.
- **`ircd/.gitignore` updated** — parser files no longer excluded from version control.

### Configuration
- **Per-link HMAC in Connect blocks** — new `hmac = yes/no` option controls HMAC enforcement per link. Allows mixed networks where some servers support HMAC and others don't.
- **`doc/example.ircd.conf`** — comprehensive generic example config for distribution.

### Cleanup
- Removed all `.cvsignore` files (legacy CVS artifacts)
- Updated `.gitignore`, `.dockerignore`, `.mailmap`
- Updated `doc/features.txt` with S2S HMAC documentation

## 1.4.1 (2026-03)
- Initial Cathexis-specific release
- HMAC-SHA256 host cloaking
- Modern OpenSSL (TLS 1.2+ minimum)
- IRCv3 capabilities (SASL, account-notify, server-time, etc.)
- MaxMindDB GeoIP
- Argon2id operator passwords
