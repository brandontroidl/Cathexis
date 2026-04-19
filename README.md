# Cathexis IRCd

**Version 1.5.4** — A modern IRC daemon based on the ircu/P10 protocol family.

Copyright (c) Cathexis Development

## Features

- **P10 Protocol** with full ircu compatibility
- **Modern TLS** — OpenSSL 3.x, TLS 1.2+ minimum, configurable cipher suites
- **HMAC-SHA256 Host Cloaking** — cryptographically secure host hiding
- **S2S HMAC Authentication** — per-message HMAC-SHA256 signing on server links with per-link control
- **IRCv3 — 32/32 CAPs** — multi-prefix, userhost-in-names, extended-join, away-notify, account-notify, sasl (PLAIN/EXTERNAL), tls, cap-notify, server-time, account-tag, message-tags, echo-message, invite-notify, chghost, setname, batch, labeled-response, standard-replies, sts, message-ids, monitor, bot-mode, typing, no-implicit-names, pre-away, extended-monitor, channel-rename, message-redaction, read-marker, multiline, account-registration, chathistory
- **Channel Modes** — owner (+q), admin/protect (+a), halfop (+h), ban exceptions (+e)
- **Argon2id** operator and die/restart passwords
- **MaxMindDB** GeoIP lookups
- **DNSBL** support (DroneBL, EFnet RBL, custom zones)
- **Login-on-Connect** and SASL PLAIN/EXTERNAL

## Building

```bash
./configure --prefix=$HOME/ircd
make
make install
```

The distribution includes pre-generated parser files (`y.tab.c`, `y.tab.h`, `lex.yy.c`). Bison and flex are only needed if you modify `ircd_parser.y` or `ircd_lexer.l`.

## Configuration

Copy `doc/example.ircd.conf` to your install directory and edit it. At minimum, set:

1. `General { name, description, numeric }`
2. `Admin { Location, Contact }`
3. `Operator { name, password }` — generate with `umkpasswd -m sha512`
4. `Features { HOST_HIDING_KEY1/2/3 }` — generate with `openssl rand -hex 32`
5. `Connect` blocks for services

### S2S HMAC

Enable globally with `S2S_HMAC = TRUE` in Features, then add `hmac = yes` to individual Connect blocks. Links without `hmac = yes` operate in legacy mode.

## License

GNU General Public License v3+
