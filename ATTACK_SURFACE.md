# ATTACK_SURFACE.md — Pass 2: Attack Surface Enumeration
## Cathexis / Nefarious IRCd

---

## Entry Point Inventory

### EP-01 — IRC Client Protocol (TCP)

| Attribute | Detail |
|-----------|--------|
| **Port** | Configurable (default 6667 plain, 6697 SSL) |
| **Format** | RFC 1459 / IRCv3 lines, max 512 bytes, terminated by `\r\n` or `\n` |
| **Parser** | `parse_client()` in `parse.c` |
| **Downstream** | All `m_*.c` handlers accessible to CLIENT/UNREG/OPER roles |
| **IRCv3 tags** | `@key=value;key2=value2 CMD params` — tags are skipped without deep validation |
| **Pre-auth commands** | NICK, USER, PASS, PONG, ERROR, SERVER, CAP, AUTHENTICATE, WEBIRC, STARTTLS, NOTICE, QUIT, ADMIN, VERSION, PING |

**Risk surface:** Any unregistered TCP client can exercise all MFLG_UNREG handlers. Parameter values up to ~500 bytes each enter handler functions with varying length checks.

---

### EP-02 — Server-to-Server Link (P10 Protocol)

| Attribute | Detail |
|-----------|--------|
| **Format** | P10 numeric prefix (1–5 chars) or `:name` prefix, then token or long command, then params |
| **Parser** | `parse_server()` in `parse.c` |
| **Downstream** | All `ms_*` handlers; all server-protocol commands (BURST, CREATE, NICK, SVSIDENT, SVSMODE, SVSNICK, FAKE, MARK, PRIVS…) |
| **Trust model** | Any successfully linked server is fully trusted; no per-message signing |
| **Auth** | Password comparison in `mr_server` (`m_server.c:619`); single shared plaintext secret per link |

**Risk surface:** A compromised or rogue linked server can inject arbitrary P10 messages. All `ms_*` handlers treat the source server as authoritative.

---

### EP-03 — IRC Operator Commands

| Attribute | Detail |
|-----------|--------|
| **Commands** | OPER, KILL, GLINE, ZLINE, SHUN, OPMODE, CLEARMODE, JUPE, REHASH, RESTART, DIE, SET, RESET, CONNECT, SA* family |
| **Entry** | After `OPER` authentication; `cli_handler` set to `OPER_HANDLER` |
| **Auth** | Password hashed (bcrypt/smd5/crypt) compared in `m_oper.c`; host mask check |

**Risk surface:** Oper password brute-force; host mask bypass via WEBIRC; privilege escalation via misconfigured oper blocks or compromised SET feature values.

---

### EP-04 — Configuration Files

| Attribute | Detail |
|-----------|--------|
| **Files** | `ircd.conf`, included sub-files (`local.conf`, `linesync.conf`) |
| **Format** | Block-based (`General {}`, `Class {}`, `Oper {}`, `Features {}`, etc.) |
| **Parser** | Lex/yacc-style parser in `s_conf.c` |
| **Runtime reload** | `REHASH` command re-parses config without restart |
| **Feature strings** | `F:` (feature) lines set runtime parameters including cloaking keys (`HOST_HIDING_KEY1/2/3`) |

**Risk surface:** Malicious config entries (e.g., rogue O: lines, oversized feature string values) can trigger memory safety issues at runtime. No length validation on feature string values.

---

### EP-05 — Docker Environment Variables

| Attribute | Detail |
|-----------|--------|
| **File** | `tools/docker/dockerentrypoint.sh` |
| **Mechanism** | `grep -oE '%[A-Za-z_]...' base.conf-dist` → `sed -i "s\|${placeholder}\|${escaped_value}\|g"` |
| **Variables** | `IRCD_GENERAL_NAME`, `IRCD_GENERAL_DESCRIPTION`, `IRCD_GENERAL_NUMERIC`, `IRCD_ADMIN_LOCATION`, `IRCD_ADMIN_CONTACT` |
| **Sanitization** | Only `/`, `\`, `&` are escaped via `printf '%s\n' \| sed -e 's/[\\/&]/\\\\&/g'` |

**Risk surface:**
- `|` character in any env var breaks the outer `sed -i "s|...|...|g"` delimiter, resulting in malformed substitution or shell error.
- Newlines (`\n`) in env var values can inject additional config directives if they appear in the value substituted into the config file (e.g., `IRCD_GENERAL_DESCRIPTION` with embedded newlines could close a block and open a new `Oper {}` block).
- `IRCD_GENERAL_NUMERIC` is substituted without quoting: `numeric = %IRCD_GENERAL_NUMERIC%;`. Value `1; Oper { name = "backdoor"; password = "x"; host = "*"; class = "Opers"; }` would inject an oper block.

---

### EP-06 — Environment Variables (Runtime)

| Attribute | Detail |
|-----------|--------|
| **PATH / library loading** | Standard UNIX; ircd binary runs as dedicated user (UID 1234 in Docker) |
| **`IRCD_*` env vars** | Only read during Docker startup; not accessed at runtime by the daemon itself |

**Risk surface:** Low; no direct env var reads in the daemon process.

---

### EP-07 — File Reads

| Attribute | Detail |
|-----------|--------|
| **`ircd.conf`** | Read at start and on REHASH |
| **MOTD, RULES, OPERMOTD** | Read via `fileio.c` / `motd.c` on client demand |
| **SSL certificate** (`ircd.pem`) | Read by OpenSSL during TLS handshake |
| **iAuth pipe** | Unix socket to `iauthd.pl`; response parsed in `s_auth.c` |

**Risk surface:** If MOTD or RULES files are writable by an untrusted user, content injection into replies. iAuth pipe: malformed responses could confuse auth state machine (unvalidated field lengths in ident reply parsing).

---

### EP-08 — DNS Resolver Responses

| Attribute | Detail |
|-----------|--------|
| **Implementation** | `ircd_res.c`, `ircd_reslib.c` — custom async resolver |
| **Flow** | `gethost_byaddr(ip, callback)` → UDP DNS response → `auth_dns_callback` → `ircd_strncpy(cli_sockhost, hoststr, HOSTLEN+1)` |
| **Validation** | `auth_verify_hostname()` checks character set and length |

**Risk surface:** DNS cache poisoning could inject a crafted hostname. `auth_verify_hostname` does validate allowed chars but relies on the DNS library's length framing.

---

### EP-09 — IAuth External Daemon

| Attribute | Detail |
|-----------|--------|
| **File** | `tools/iauthd.pl` (Perl), communicates over Unix socket |
| **Protocol** | Custom text protocol; fields include username override, forced username, host override, account name |
| **Parsing** | `s_auth.c`, field extraction at token positions |

**Risk surface:** If `iauthd.pl` is compromised or returns malformed data, usernames or hostnames longer than `USERLEN`/`HOSTLEN` could reach `ircd_strncpy` calls. The daemon runs as the same user as ircd; compromise of the Perl script is equivalent to code execution.

---

### EP-10 — Network Sockets (Outbound)

| Attribute | Detail |
|-----------|--------|
| **Server connections** | `connect_server()` → `connect_inet()` → non-blocking `connect()` |
| **uPing** | UDP pings via `uping.c` |
| **DNS queries** | UDP to configured resolvers |

**Risk surface:** Source routing is explicitly disabled (`os_disable_options(fd)`). Server link targets are config-validated. UDP response parsing for DNS is the main external data plane.

---

### EP-11 — Plugin / Module Interface

No dynamic module loading is implemented. All command handlers are compiled in. `register_mapping()` allows pseudo-commands to be added for service bot routing, but this is triggered only by config at load time.

---

## Summary Table

| EP | Source | Trust Level | Parser | Critical Paths |
|----|--------|-------------|--------|----------------|
| EP-01 | IRC Client | Untrusted | `parse_client` | All `m_*` handlers |
| EP-02 | S2S Link | Trusted after auth | `parse_server` | All `ms_*` handlers, BURST, SVS* |
| EP-03 | IRC Oper | Elevated | `parse_client` | DIE, RESTART, SET, KILL, GLINE |
| EP-04 | Config file | Admin | `s_conf.c` | Feature strings, O:/C: blocks |
| EP-05 | Docker env | Deployment-time | `sed` substitution | ircd.conf injection |
| EP-07 | Filesystem | OS user | `fileio.c` | MOTD/RULES content |
| EP-08 | DNS | Network | `ircd_reslib.c` | Hostname assignment |
| EP-09 | iAuth pipe | Local | `s_auth.c` | Username/host override |
