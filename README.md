# Cathexis — Security-Hardened Nefarious2 IRC Daemon

Cathexis is a security-hardened fork of the Nefarious2 IRC daemon (based on ircu/IRCu2). It retains full compatibility with the P10 server protocol and existing Nefarious2 networks while adding modern IRCv3 capabilities, systematic memory safety improvements, and comprehensive security hardening.

|  |  |
|--|--|
| **Version** | 1.1.0 |
| **Base** | Nefarious2 (u2.10.12.14) |
| **Protocol** | P10 |
| **License** | GNU General Public License v1+ |
| **Version scheme** | `major.minor.patch` — major: protocol breaks, minor: features/security, patch: bugfixes |

## Quick Start

```bash
./configure --prefix=/home/ircd
make
make install
cp doc/example.conf /home/ircd/lib/ircd.conf
# Edit ircd.conf — at minimum set General { name, description, numeric }
/home/ircd/bin/ircd
```

For SSL/TLS support, add `--with-openssl` to configure. See [Installation](#installation) below.

## What Cathexis Adds

### Security Hardening (1.0.0)

- All `sprintf()` calls in runtime code replaced with `ircd_snprintf()` for bounds-checked formatting
- All dangerous `strcpy()` calls replaced with `ircd_strncpy()` for bounded string copying across 20+ files
- SSL certificate verification callback logs unverified connections for deployment auditing
- SETNAME command includes CR/LF injection filtering
- Separate client/server handler pattern for SETNAME to prevent error reply leakage across server links

### Security Hardening (1.1.0)

- **CRITICAL:** All 9 `strcpy(res+16, KEY*)` calls in `ircd_cloaking.c` replaced with bounded `safe_key_copy()` — prevents stack buffer overflow when cloaking keys exceed 496 bytes
- **CRITICAL:** `get_channel()` now enforces `CHANNELLEN` for all sources, not just local users — prevents over-length channel names from rogue servers overflowing fixed-size buffers
- **HIGH:** All `strcat()` accumulation patterns across the entire codebase (55+ call sites in 15 files) replaced with bounded alternatives (`strncat`, position-tracked `memcpy`)
- **HIGH:** Constant-time `CRYPTO_memcmp()` fallback added for non-SSL builds, preserving timing-safe password comparison
- **LOW:** Defense-in-depth `strcpy` → `ircd_strncpy` replacements for bounded values in 7 additional files
- Zero `strcat()` calls remain in the codebase
- Zero compiler warnings across the full build

### IRCv3 Capabilities

Cathexis supports the following IRCv3 capabilities. Clients negotiate them via `CAP LS`/`CAP REQ` during connection registration. Non-IRCv3 clients connect normally without any capability negotiation.

| Capability | Status | Description |
|-----------|--------|-------------|
| `multi-prefix` | Full | All user prefixes in NAMES, WHO, and WHOIS |
| `userhost-in-names` | Full | `nick!user@host` format in NAMES replies |
| `extended-join` | Full | Account and realname in JOIN messages |
| `away-notify` | Full | AWAY status changes to common channels |
| `account-notify` | Full | ACCOUNT login changes to common channels |
| `sasl` | Full | SASL authentication (PLAIN, EXTERNAL) |
| `tls` | Full | STARTTLS connection upgrade (requires SSL build) |
| `cap-notify` | Full | CAP NEW/DEL change notifications (implicit with CAP 302) |
| `setname` | Full | SETNAME command with FAIL standard replies, NAMELEN ISUPPORT |
| `message-tags` | Accept | Client tags parsed and stripped; tag relay infrastructure pending |
| `server-time` | Framework | Advertised; tag attachment pending |
| `account-tag` | Framework | Advertised; tag attachment pending |
| `batch` | Framework | Advertised; batching infrastructure pending |
| `labeled-response` | Framework | Advertised; label tracking pending |
| `standard-replies` | Framework | FAIL/WARN/NOTE format (used by SETNAME) |
| `invite-notify` | Framework | Advertised; relay pending |
| `chghost` | Framework | Advertised; relay pending |

Capabilities marked "Framework" are negotiated and advertised but their full server-side relay behavior requires tag infrastructure not yet present. Clients degrade gracefully — they negotiate the capability but simply don't receive the corresponding tags on messages.

### New Commands

| Command | Privilege | Description |
|---------|-----------|-------------|
| `SETNAME` | cap-gated | Change realname (GECOS) on an active connection |
| `TAGMSG` | cap-gated | Send tag-only messages (accepted, relay pending) |
| `SAJOIN` | +N netadmin | Force user to join channel(s) |
| `SAPART` | +N netadmin | Force user to part channel(s) |
| `SANICK` | +N netadmin | Force nickname change |
| `SAMODE` | +N netadmin | Force mode change on user or channel |
| `SAQUIT` | +N netadmin | Force user disconnect |
| `SATOPIC` | +N netadmin | Force topic change, bypassing +t |
| `SAWHOIS` | +N netadmin | Set/clear custom WHOIS line |

All SA\* commands require `netadmin = yes` in the oper block. SVS\* commands remain as S2S protocol for X3/Atheme/Anope services compatibility.

### Oper Hierarchy

| Mode | Level | Access |
|------|-------|--------|
| `+N` | Network Administrator | SA\* commands, full network control |
| `+a` | Server Administrator | Server administration |
| `+o` | Global IRC Operator | Network-wide operator |
| `+O` | Local IRC Operator | Local server operator |

### Snomask Letters

Users set server notice masks with `/mode nick +s +<letters>`. Legacy numeric masks are still accepted for backward compatibility.

| Letter | Notices |
|--------|---------|
| `c` | Client connections/disconnections |
| `k` | Kill notices |
| `n` | Nickname changes |
| `g` | G-line activations |
| `j` | Connection rejections |
| `f` | Flood notices |
| `D` | Debug messages |
| `K` | K-line matches |
| `t` | Target change notices |

## Existing Nefarious2 Features

- Asynchronous event engines: epoll (Linux), kqueue (FreeBSD), /dev/poll (Solaris), poll() fallback
- F: (feature) lines with runtime GET/SET configuration
- P10 account persistence across netsplits
- Full SASL support (PLAIN, EXTERNAL)
- SSL/TLS for client and server links
- Extended ban types (`~a`, `~c`, `~j`, `~n`, `~q`, `~r`, `~m`, `~M`)
- WEBIRC support for web-based clients (options: secure, local-port, remote-port, certfp, account)
- G-line, Shun, Z-line network ban management
- Host cloaking (MD5-based with configurable keys)
- GeoIP / MaxMindDB integration (optional)

## Installation

### Requirements

- C compiler (gcc or clang)
- make
- flex and bison (for config parser generation)
- OpenSSL development headers (optional, for SSL/TLS)
- GeoIP or MaxMindDB libraries (optional)

### Basic Build

```bash
./configure --prefix=/home/ircd
make
make install
```

### Build with SSL

```bash
./configure --prefix=/home/ircd \
  --with-openssl-includes=/usr/include \
  --with-openssl-libs=/usr/lib/x86_64-linux-gnu
make
make install
```

### Build without SSL

```bash
./configure --prefix=/home/ircd --disable-ssl
make
make install
```

### Installed Files

| Path | Description |
|------|-------------|
| `<prefix>/bin/ircd` | IRC daemon binary |
| `<prefix>/bin/umkpasswd` | Password hashing utility |
| `<prefix>/bin/convert-conf` | Config format converter |
| `<prefix>/lib/ircd.conf` | Server configuration (you must create this) |
| `<prefix>/lib/example.conf` | Example configuration with full documentation |
| `<prefix>/lib/ircd.pem` | SSL certificate (generated on install if SSL enabled) |

## Configuration

Copy `example.conf` to `ircd.conf` and edit. At minimum, configure:

```
General {
    name = "irc.example.com";
    description = "My IRC Server";
    numeric = 1;     # Unique per server on the network (1-4095)
};
```

### Feature Toggles

All IRCv3 capabilities are enabled by default and can be toggled via Features blocks or the `/SET` command:

```
Features {
    "CAP_server_time" = "FALSE";      # disable server-time
    "CAP_message_tags" = "FALSE";     # disable message-tags
    "CAP_setname" = "FALSE";          # disable setname
};
```

### Cloaking Keys

Host cloaking requires three unique random keys. Generate them with:

```bash
openssl rand -hex 32
```

Keys must be under 256 characters. All servers on the network must use identical keys.

```
Features {
    "HOST_HIDING" = "TRUE";
    "HOST_HIDING_KEY1" = "<random key 1>";
    "HOST_HIDING_KEY2" = "<random key 2>";
    "HOST_HIDING_KEY3" = "<random key 3>";
};
```

### SSL Recommendations

For production deployments, enable certificate verification on server links:

```
Features {
    "SSL_VERIFYCERT" = "TRUE";
    "SSL_NOSELFSIGNED" = "TRUE";
};
```

Without these, server-to-server TLS accepts any certificate (logged but not rejected for backward compatibility).

## Compatibility

Cathexis is fully compatible with:

- **P10 protocol servers** — Nefarious2, ircu2 (server-to-server links work with unmodified peers)
- **IRCv3 clients** — HexChat, WeeChat, irssi, The Lounge, IRCCloud, gamja, Srain, Halloy, Goguma, Textual, mIRC, AdiIRC, KVIrc, Quassel
- **Legacy clients** — All RFC 1459/2812 clients connect normally without capability negotiation
- **Services** — X3, Atheme, Anope (via SVS\* S2S protocol)
- **Existing configs** — Nefarious2 `ircd.conf` files work without modification

## Performance Hints

- Use an OS with async event engines (Linux epoll, FreeBSD kqueue)
- Tune kernel file descriptor limits: `ulimit -n 16384`
- Run local caching DNS for fast resolver lookups
- Synchronize clocks via NTP across all network servers
- For Linux, configure via `/etc/security/limits.conf`
- For FreeBSD, set `kern.maxfiles` and `kern.maxfilesperproc`

## Project Documentation

| File | Description |
|------|-------------|
| `CHANGELOG.md` | Version history with all changes per release |
| `AUDIT.md` | Security audit findings and remediation status |
| `CATHEXIS_SECURITY_AUDIT.md` | Independent 10-pass security audit |
| `MEMORY_AUDIT.md` | Memory safety deep audit (Pass 5) |
| `TAINT_ANALYSIS.md` | Taint tracking analysis (Pass 4) |
| `PRIVILEGE_ANALYSIS.md` | Privilege escalation analysis (Pass 7) |
| `EXPLOIT_ANALYSIS.md` | Exploit development analysis (Pass 9) |
| `DESYNC_ANALYSIS.md` | Protocol desynchronization analysis (Pass 6) |
| `PATCH_DIFFS.md` | Secure refactor details (Pass 10) |
| `SYSTEM_ARCHITECTURE.md` | Architecture reconstruction (Pass 1) |
| `ATTACK_SURFACE.md` | Attack surface enumeration (Pass 2) |
| `PARSER_STATE_MACHINE.md` | Protocol parser analysis (Pass 3) |
| `FUZZ_TEST_PLAN.md` | Fuzzing strategy (Pass 8) |
| `doc/example.conf` | Fully documented example configuration |
| `doc/readme.*` | Feature-specific documentation |

## Credits

Cathexis security hardening and IRCv3 modernization:
Brandon Troidl

Nefarious 2.0:
Jobe (Matthew Beeching), Rubin (Alex Schumann), Obnoxious, Andromeda

Original ircu2:
Run (Carlo Wood), Bleep (Thomas Helvey), Isomer (Perry Lorier), Kev (Kevin Mitchell)

Original IRC:
Wiz (Jarkko Oikarinen)

For a full list of contributors, see `doc/Authors`.
