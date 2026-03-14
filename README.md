# Cathexis IRCd

Security-hardened fork of Nefarious2 with modern IRC features.

|  |  |
|--|--|
| **Version** | 1.2.0 |
| **Base** | Nefarious2 (u2.10.12.14) |
| **Protocol** | P10 |
| **License** | GNU General Public License v1+ |

## Quick Start

```bash
./configure --prefix=$HOME/ircd
make && make install
cp doc/ircd.conf $HOME/ircd/lib/ircd.conf
# Edit ircd.conf: server name, admin info, oper password, cloaking keys
$HOME/ircd/bin/ircd
```

Generate cloaking keys with `openssl rand -hex 32`. All three `HOST_HIDING_KEY` values must be unique and must match across all servers on the network. The daemon warns at startup if keys are still set to the compiled-in defaults.

## Build Options

```bash
# Full build with all optional features
./configure --prefix=$HOME/ircd --with-maxcon=512 \
  --with-openssl \
  --with-geoip=/usr --with-geoip-includes=/usr/include \
  --with-geoip-libs=/usr/lib/x86_64-linux-gnu \
  --with-mmdb=/usr --with-mmdb-includes=/usr/include/x86_64-linux-gnu \
  --with-mmdb-libs=/usr/lib/x86_64-linux-gnu

# Debug build (asserts enabled, profiling, pedantic warnings)
./configure ... --enable-debug --enable-warnings --enable-pedantic \
  --enable-profile --with-leak-detect
```

Validate configuration without starting the server:

```bash
$HOME/ircd/bin/ircd -k
```

## Features

### Channel Prefix Hierarchy

Five-tier channel membership with full privilege enforcement:

| Prefix | Mode | Role | Can set | Who can set |
|--------|------|------|---------|-------------|
| `~` | +q | Owner | +q +a +o +h +v | +q / Services / SAMODE |
| `&` | +a | Protect | +a +o +h +v | +q +a / Services / SAMODE |
| `@` | +o | Operator | +o +h +v | +q +a +o |
| `%` | +h | Halfop | +v | +q +a +o |
| `+` | +v | Voice | — | +q +a +o +h |

Kick protection enforces hierarchy — a +a user cannot be kicked by +o, a +q user cannot be kicked except by another +q. Enable/disable with `OWNERPROTECT` and `HALFOPS` features. ISUPPORT `PREFIX=` adapts automatically.

### SA* Commands (Network Administration)

Ten server admin commands, all requiring `PRIV_NETADMIN` (+N). Every use generates an `SNO_OLDSNO` (snomask `o`) notice visible to all opers showing who did what, to whom, with full parameters.

| Command | Purpose |
|---------|---------|
| SAJOIN | Force user into channel(s) |
| SAPART | Force user from channel(s) |
| SANICK | Force nickname change |
| SAMODE | Force mode change (user or channel) |
| SAQUIT | Force disconnect |
| SATOPIC | Force topic change |
| SAWHOIS | Set/clear custom WHOIS line |
| SAIDENT | Force ident change |
| SAINFO | Force realname change |
| SANOOP | Toggle NOOP on a server |

### DNSBL (DNS Blacklist)

Built-in DNS blacklist checking during client registration. Queries up to 3 DNSBL zones in parallel alongside DNS/ident lookups — no extra delay for clean IPs.

Preconfigured zones (all verified active):

| Zone | Coverage |
|------|----------|
| `dnsbl.dronebl.org` | Open proxies, botnets, compromised hosts |
| `rbl.efnetrbl.org` | Proxies, spam, trojans, Tor, drones (EFnet) |
| `torexit.dan.me.uk` | Tor exit nodes only |

Two modes: `DNSBL_REJECT=TRUE` disconnects listed IPs; `DNSBL_REJECT=FALSE` marks them for oper review via `/CHECK`. Configure in ircd.conf Features block.

### IRCv3 Compliance

| Specification | Status |
|---------------|--------|
| CAP negotiation 3.2 (LS 302, NEW/DEL) | Full |
| multi-prefix (NAMES + WHO + WHOIS) | Full |
| setname (FAIL standard replies, NAMELEN) | Full |
| SASL 3.2 | Full |
| WEBIRC | Full |
| message-tags | Accept/strip |
| server-time, account-tag, batch | Full |
| away-notify, account-notify, chghost | Full |
| cap-notify, invite-notify | Full |
| labeled-response, standard-replies | Full |
| echo-message | Available (default off) |

### Security Hardening

All fixes applied to source — no patches or external dependencies.

**Password hashing:** Six mechanisms available. SHA-512, SHA-256, and bcrypt are recommended. Salted MD5 and plaintext are deprecated — the server logs warnings when they're used. Generate passwords with `umkpasswd -m sha512 <password>`.

**PRNG:** Replaced the MD5 + `gettimeofday()` PRNG with `/dev/urandom` direct reads and OpenSSL `RAND_bytes()` when available. Affects PING cookies, nonces, and all security-critical randomness.

**Host cloaking:** HMAC-SHA512 cloaking is the default (`HOST_HIDING_HMAC = TRUE`). Replaces the legacy double-MD5 algorithm with 64-bit segments providing 256-bit post-quantum security. Requires OpenSSL. All servers must match. Set to FALSE for legacy MD5 cloaking.

**Weak password rejection:** `$PLAIN$` and `$SMD5$` passwords are rejected by default. Set `CRYPT_ALLOW_PLAIN` or `CRYPT_ALLOW_SMD5` to TRUE only during migration from legacy configs.

**TLS hardening:** Default cipher lists prioritize 256-bit symmetric keys (AES-256-GCM, ChaCha20) with ECDHE forward secrecy. TLS 1.0/1.1 disabled by default. Post-quantum ML-KEM key exchange activates automatically when OpenSSL 3.5+ is available.

**S2S authentication:** Optional per-message HMAC-SHA256 on server links (`S2S_HMAC = TRUE`). Keys derived from link passwords. Prevents message injection and tampering. Channel state hashing (`S2S_CSYNC`) detects desync after netsplits. SA* commands restricted to authorized services hub (`SERVICES_HUB_NUMERIC`).

**Memory safety:** Zero `strcat()` calls remain in the codebase. All `sprintf()` replaced with bounded `ircd_snprintf()`. All dangerous `strcpy()` replaced with `ircd_strncpy()` across 20+ files. Cloaking key copy uses bounded `safe_key_copy()` helper.

**Input validation:** `get_channel()` enforces CHANNELLEN for all sources (local + server). SETNAME filters CR/LF injection. Channel name length validated on BURST.

**Cryptographic:** Constant-time comparison (`ircd_constcmp()` from `ircd_crypto.h`) on all passwords, channel keys, and server link credentials. Secure memory clearing (`ircd_clearsecret()`) before freeing credential buffers.

**OPER hardening:** Failed OPER attempts incur a 10-second flood penalty, preventing brute force. Error responses are uniform (`ERR_NOOPERHOST`) for both missing operator and wrong password, preventing credential enumeration.

See `AUDIT.md` for the complete security audit with findings and remediation details.

### Configuration

The shipped `ircd.conf` has 242 explicitly set features covering the full daemon. The `doc/example.conf` is the upstream reference. Both files document every feature with comments.

Production config includes: connection classes, oper block with full privilege set (including WHO visibility), DNSBL zones, all HIS privacy settings, IRCv3 caps, cloaking, extended channel modes, extended bans, CTCP versioning, GeoIP, SASL, and Login-on-Connect.

## File Layout

```
ircd.conf              Production configuration (242 features)
AUDIT.md               Security audit report
CHANGELOG.md           Version history and all changes
LICENSE.md             License summary (GPL v1+)
README.md              This file
doc/example.conf       Upstream reference configuration
doc/ircd.conf          Copy of production config
include/               Header files
ircd/                  Source files
  m_sa.c               All 10 SA* commands
  m_help.c             /HELP system with categorized index
  s_auth.c             Auth system with DNSBL integration
  channel.c            Channel modes including +q/+a/+h hierarchy
  ircd_features.c      Feature toggle system (272 features)
```

## systemd

A `cathexis.service` unit file and `setup.sh` installer are included. The service runs as user `ircd` with `NoNewPrivileges`, `ProtectSystem=strict`, and `PrivateTmp` security hardening.

## Compatibility

Cathexis is wire-compatible with Nefarious2 and the P10 protocol. SA* commands use the same wire tokens as the original SVS* commands for rolling upgrade compatibility. Servers without `OWNERPROTECT` silently strip +q/+a from BURST/mode messages.

## P10 Protocol Extensions

Cathexis 1.2.0 addresses three structural weaknesses in the P10 protocol with optional extensions. These are disabled by default for backward compatibility.

**S2S message authentication** (`S2S_HMAC = TRUE`) — Every server-to-server message is HMAC-SHA256 signed using keys derived from the link password. Messages with invalid or missing signatures are silently dropped. Breaks compatibility with non-Cathexis servers.

**Desync detection** (`S2S_CSYNC = TRUE`) — Servers exchange SHA-256 hashes of channel state after BURST/EOB. Mismatches trigger re-synchronization requests, ensuring state divergence from netsplits is detected rather than silently accepted.

**SA\* source restriction** (`SERVICES_HUB_NUMERIC = "AB"`) — Only the server with the configured P10 numeric can send SA\* commands. All 9 server-side SA\* handlers verify source authorization. Unauthorized commands are rejected and logged. Falls back to legacy trust when unset.
