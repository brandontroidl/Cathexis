# Contributing to Cathexis IRCd

Cathexis IRCd is maintained by Cathexis Development. Contributions are welcome — whether that's bug reports, security disclosures, patches, documentation improvements, or feature proposals.

## Getting Started

### Build Environment

```bash
# Ubuntu 24.04 / Debian 12+
sudo apt install build-essential bison flex libssl-dev libmaxminddb-dev libargon2-dev

# Clone and build
git clone <repo-url> Cathexis
cd Cathexis
./configure --prefix=$HOME/ircd \
  --with-maxcon=512 \
  --enable-warnings \
  --with-mmdb-includes=/usr/include/x86_64-linux-gnu \
  --with-mmdb-libs=/usr/lib/x86_64-linux-gnu
make && make install
```

### Required Libraries

| Library | Package | Purpose |
|---------|---------|---------|
| OpenSSL 1.1.1+ | `libssl-dev` | TLS, HMAC-SHA256, X25519, CSPRNG |
| libmaxminddb | `libmaxminddb-dev` | GeoIP2 city/country lookups |
| libargon2 | `libargon2-dev` | Argon2id password hashing |

OpenSSL 1.1.1 is the minimum. OpenSSL 3.x is fully supported (EVP_MAC used automatically on 3.0+).

### After Struct Changes

Any modification to `client.h`, `channel.h`, or `ircd_features.h` (struct layouts or feature enums) requires a clean rebuild:

```bash
rm -f ircd/*.o && make clean && make distclean
./configure [flags]
make && make install
```

## Code Standards

### Language

- C99. No C++ or GNU extensions unless guarded by `#ifdef`.
- All new code must compile cleanly with `-Wall -pedantic`.

### Formatting

- 2-space indentation for new Cathexis code.
- Heritage code (ircu2/Nefarious2) retains its original style — do not reformat.
- Opening braces on the same line for functions and control flow.
- No trailing whitespace.

### Naming Conventions


### Security Requirements

All contributions touching security-sensitive code must follow these rules:

- **No MD5 or SHA-1** for any security purpose. HMAC-SHA256 minimum.
- **No direct `HMAC()` calls** — use `ircd_hmac_sha256()` from `ircd_crypto.h` (portable across OpenSSL 1.1.x and 3.0+).
- **No deprecated OpenSSL API** — no `SSL_library_init()`, `SSLv23_method()`, `SSLeay_version()`, etc.
- **TLS 1.2 is the hard minimum.** Do not add `SSL_OP_NO_*` feature toggles.
- **Buffer safety** — use `ircd_snprintf()` or `ircd_strncpy()`. No `sprintf()` or unbounded `strcpy()` in new code.
- **Secret cleanup** — call `OPENSSL_cleanse()` on key material and intermediate crypto buffers before they go out of scope.
- **NULL guards** — any async callback touching `cli_connect()` must check for NULL (DNSBL, auth callbacks).
- **`ircd_strncpy(dst, src, n)`** copies `n-1` chars. Callers pass full buffer size, not `size - 1`.

### Commit Messages

```
component: short description (50 chars max)

Detailed explanation of what changed and why.
Reference any relevant numerics, RFCs, or IRCv3 specs.

Fixes: #issue (if applicable)
```


## Architecture Overview

### Source Tree

```
include/          — Header files (85 .h files)
ircd/             — Server source (182 .c files)
ircd/test/        — Unit tests
doc/              — Example configs, protocol docs
```

### Key Files

| File | Purpose |
|------|---------|
| `ircd/ssl.c` | TLS context, cipher config, certificate handling |
| `ircd/ircd_cloaking.c` | HMAC-SHA256 host cloaking |
| `ircd/ircd_geoip.c` | MaxMindDB city/country/continent lookups |
| `ircd/ircd_crypt.c` | Password verification dispatch |
| `ircd/ircd_crypt_argon2.c` | Argon2id password hashing |
| `ircd/s2s_crypto.c` | Server-to-server HMAC authentication |
| `ircd/ircd_relay.c` | PRIVMSG/NOTICE relay (silence, color, mode enforcement) |
| `ircd/channel.c` | Channel modes, JOIN enforcement, mode parser |
| `ircd/s_user.c` | User modes, registration, cloaking dispatch |
| `ircd/m_help.c` | Help system (222+ entries) |
| `include/ircd_crypto.h` | Portable HMAC-SHA256 wrapper, constant-time compare |
| `include/client.h` | Client struct, flags, macros |
| `include/channel.h` | Channel struct, mode definitions |

### Crypto Architecture

```
ircd_crypto.h          — Portable wrappers (HMAC, cleanse, constcmp)
    ↓
ssl.c                  — TLS 1.2+ context (server + client)
ircd_cloaking.c        — Host cloaking (HMAC-SHA256)
s2s_crypto.c           — S2S authentication (HMAC-SHA256)
ircd_crypt_argon2.c    — Password hashing (Argon2id)
random.c               — CSPRNG (RAND_bytes)
```

All OpenSSL includes are centralized. Do not add `#include <openssl/...>` to new files — use `ircd_crypto.h` or the appropriate module header.



## Adding New Features

### New Channel Mode

1. Add `EXMODE_*` define to `include/channel.h`
2. Add `case 'X':` to mode parser in `ircd/channel.c` (4 tables + `channel_modes()` display)
3. Add JOIN enforcement in `channel.c` if needed
4. Update `infochanmodes` in `include/channel.h`
5. Update `CHANMODES` ISUPPORT string builder in `ircd/s_user.c`
6. Update help in `ircd/m_help.c`
7. Update `README.md` and `CHANGELOG.md`

### New User Mode

1. Add `FLAG_*` define to `include/client.h`
2. Add `{ FLAG_*, 'x' }` to userModeList in `ircd/s_user.c`
3. Add enforcement logic in appropriate handler
4. Update `infousermodes` in `include/client.h`
5. Update help in `ircd/m_help.c`
6. Update `README.md` and `CHANGELOG.md`

### New SNO Mask

1. Add `SNO_*` define to `include/client.h`
2. Update `SNO_ALL` (both oper and non-oper variants)
3. Add `{ SNO_*, 'x', "description" }` to table in `ircd/s_user.c`
4. Add SNO letter to WHOIS display in `ircd/m_whois.c`
5. Update help in `ircd/m_help.c`

### New Password Mechanism

1. Create `ircd/ircd_crypt_name.c` + `include/ircd_crypt_name.h`
2. Implement the crypt mechanism struct with `shortname`, `description`, `prefix`, `crypt_function`
3. Add `ircd_register_crypt_name()` to `ircd/ircd_crypt.c` and `ircd/umkpasswd.c`
4. Add verification path in `ircd_crypt()` if the hash format differs from standard crypt
5. Add configure detection if external library required
6. Add to `ircd/Makefile.in`
7. Update `MKPASSWD` in `ircd/m_mkpasswd.c` and help

## Testing

### Manual Testing

```bash
# Connect via SSL
openssl s_client -connect localhost:6697

/quote CAP LS 302

# Verify WHOIS (as oper)
/whois <nick>

```

### Unit Tests

```bash
cd ircd/test
make
./ircd_chattr_t && ./ircd_in_addr_t && ./ircd_match_t && ./ircd_string_t
```

## Reporting Bugs

Open an issue with:

1. Cathexis version (`/version` output)
2. Operating system and OpenSSL version
3. Steps to reproduce
4. Expected vs actual behavior
5. Relevant log output (sanitize IPs/hostnames)

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

See `SECURITY.md` for responsible disclosure procedures. Contact the maintainer directly with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

## License

Cathexis IRCd is licensed under the GNU General Public License v3.0 or later. All contributions must be compatible with GPL v3+. Heritage files from ircu2/Nefarious2 retain their original GPL v1+ headers.

Do not include any AI/LLM attribution in code or commit messages. Do not include "Dexterous Network LLC" in copyright headers — use "Cathexis Development" for new files.
