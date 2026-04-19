# Cathexis IRCd Changelog

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
