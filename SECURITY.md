# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x | ✅ Current release |
| 1.4.x | ⚠️ Security fixes only |
| < 1.4 | ❌ Unsupported |

## Reporting Vulnerabilities

Report security issues to: **admin@dexterousnetworkllc.org**

Include:
- Affected version(s)
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (if known)

Do NOT open public GitHub issues for security vulnerabilities.

## Security Architecture

### Threat Model

Cathexis is designed for hostile deployment where:
- All network inputs (client connections, S2S links) are controlled by adversaries
- Clients may send arbitrary protocol data
- DNS responses may be forged
- TLS connections may be intercepted at the network level

### Defense Layers

1. **Input Validation** — All command handlers validate parameter count before access. No `parv[]` dereference without bounds check.

2. **Memory Safety** — All `sprintf`/`strcpy`/`strcat` in network-facing code replaced with bounded variants (`ircd_snprintf`, `ircd_strncpy`, position-tracked `memcpy`).

3. **Cryptographic Security** — Constant-time credential comparison (`ircd_constcmp`), Argon2id/bcrypt/SHA-512 password hashing, HMAC-SHA256 host cloaking, S2S HMAC-SHA256 message signing.

4. **TLS Hardening** — TLS 1.2 minimum enforced, modern cipher suites, no renegotiation, server cipher preference, compression disabled.

5. **Rate Limiting** — KNOCK uses `check_target_limit()`, MONITOR requires `MyConnect()` + `IsRegistered()`, OPER failures incur 10-second flood penalty.

6. **Async Safety** — NULL guards on `cli_connect()` in `ssl_send()` and `parse_client()` for callbacks that fire after client disconnection.

### Known Limitations

- **S2S Trust** — The P10 protocol inherently trusts linked servers. A compromised server can send arbitrary protocol. S2S HMAC signing provides authentication but not defense against a server with valid credentials.

- **Struct Layout Sensitivity** — Changes to `struct Connection` or `struct Client` in `client.h` require a clean rebuild (`rm -f ircd/*.o`). The Makefile does not fully track header dependencies.

## Audit History

See [AUDIT.md](AUDIT.md) for the complete security audit report covering all findings from 1.0.0 through 1.4.0.

See [SECURITY_LIFECYCLE.h](SECURITY_LIFECYCLE.h) for the blue team / red team / purple team analysis performed on the 1.4.0 release.
