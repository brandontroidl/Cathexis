# Cathexis IRC Daemon — 10-Pass Security Audit

**Target:** Cathexis IRCd (Nefarious/ircu2 derivative)
**Codebase:** ~87,000 lines of C across 268 source/header files
**Date:** March 2026
**Auditor:** Static analysis, manual code review

---

## PASS 1 — System Architecture Reconstruction

### Subsystem Inventory

**Protocol Parser** (`ircd/parse.c`): Uses a trie-based command lookup (MessageTree) for O(n) dispatch. Two entry points: `parse_client()` for users and `parse_server()` for S2S. The trie maps both long-form commands (`PRIVMSG`) and short tokens (`P`) to `struct Message` handler arrays.

**Networking Layer** (`ircd/s_bsd.c`, `ircd/os_generic.c`): Multi-engine I/O: epoll (`engine_epoll.c`), kqueue (`engine_kqueue.c`), poll (`engine_poll.c`), select (`engine_select.c`), devpoll (`engine_devpoll.c`). Connections managed via `struct Socket` with a `struct Client` per connection.

**Event Loop** (`ircd/ircd_events.c`, `ircd/ircd.c`): Timer-based event system with socket events, timers, and signal handlers. Main loop in `ircd.c` dispatches via the selected engine.

**Authentication System** (`ircd/s_auth.c`): Registration pipeline: DNS lookup → ident query → optional IAuth external daemon → PONG cookie → NICK/USER completion. WEBIRC gateway support (`m_webirc.c`). SASL via external services (`m_sasl.c`, `m_authenticate.c`). Operator authentication in `m_oper.c` with password hashing (bcrypt, SMD5, crypt, plain).

**Channel State Management** (`ircd/channel.c`): 5,088-line monolith handling: joins, parts, modes, bans, excepts, extended bans (`~a`, `~c`, `~j`, `~n`, `~q`, `~r`, `~m`, `~M`), APASS/UPASS channel ownership, mode parsing state machine, and ModeBuf batching.

**Operator Command Handlers** (`ircd/m_oper.c`, `ircd/m_sa.c`): Privilege levels: local oper (+O), global oper (+o), admin (+a), netadmin (+N). SA* commands (SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, SATOPIC, SAWHOIS) require PRIV_NETADMIN.

**Server-to-Server Link Logic** (`ircd/m_server.c`, `ircd/m_burst.c`, `ircd/s_serv.c`): P10 protocol. Server introduction with numeric collision detection, timestamp-based conflict resolution. BURST synchronization for channel state.

**Configuration Loading** (`ircd/s_conf.c`, `ircd/ircd_features.c`): Runtime features via `F:` lines. ConfItem-based server/oper/client blocks. REHASH support for live reloads.

**Logging** (`ircd/ircd_log.c`): Subsystem-based logging (LS_OPER, LS_SYSTEM, etc.) with configurable facilities.

### Core Data Structures

| Structure | Location | Role |
|-----------|----------|------|
| `struct Client` | `include/client.h` (1136 lines) | Users, servers, and unregistered connections. Contains cli_buffer[BUFSIZE] for message accumulation |
| `struct Channel` | `include/channel.h` | Channel with flexible-length name (`chname[1]` struct hack), mode state, ban/except lists, topic |
| `struct User` | `include/struct.h` | Per-user data: username, host, realhost, account, swhois[BUFSIZE+1], away |
| `struct Server` | `include/struct.h` | Per-server link data: uplink, burst state, lag |
| `struct ConfItem` | `include/s_conf.h` | Configuration entries with privilege masks |
| `struct AuthRequest` | `ircd/s_auth.c` | Registration state machine per connecting client |
| `struct Membership` | `include/channel.h` | User↔Channel link with mode flags |
| `struct Ban` | `include/channel.h` | Ban/except entries with mask, who-set, and timestamp |

### Message Flow: Socket → Handler

1. I/O engine signals readable socket
2. `read_packet()` in `s_bsd.c` reads raw bytes
3. `client_dopacket()` / `server_dopacket()` / `connect_dopacket()` in `packet.c` accumulates bytes into `cli_buffer`, splitting on CR/LF
4. `parse_client()` or `parse_server()` in `parse.c`:
   - Strips IRCv3 `@tags` prefix (client only)
   - Extracts or ignores sender prefix
   - Tokenizes command via trie lookup in `msg_tree` / `tok_tree`
   - Splits parameters (respecting `:` trailing)
   - Looks up handler by `cli_handler(cptr)` (UNREG/CLIENT/SERVER/OPER/SERVICE)
   - Dispatches to handler function

### Elevated Privilege Components

- IAuth daemon (`s_auth.c`): runs as external process, communicates over pipes
- OPER authentication (`m_oper.c`): grants flags and privileges
- SA* commands (`m_sa.c`): network administrator actions on any user
- SVS* protocol (`m_svsmode.c`, `m_svsjoin.c`, etc.): trusted S2S commands
- OPMODE/CLEARMODE (`m_opmode.c`, `m_clearmode.c`): oper channel override
- DIE/RESTART (`m_die.c`, `m_restart.c`): server shutdown/restart

### Security-Critical State Variables

- `cli_handler(cptr)`: determines which handler array slot is used — if set incorrectly, an unregistered client could access server handlers
- `cli_flags(cptr)`: privilege flags (FLAG_OPER, FLAG_LOCOP, etc.)
- `cli_from(from)`: used for direction checking — must match `cptr` or message is rejected as "fake direction"
- `cli_ip(cptr)`: client IP, rewritten by WEBIRC
- `cli_user(cptr)->account`: account name, trusted for host hiding

---

## PASS 2 — Attack Surface Enumeration

### Entry Point 1: IRC Client Protocol Messages

- **Format:** `[@tags] [:prefix] COMMAND param1 param2 :trailing\r\n`
- **Parser:** `parse_client()` in `parse.c`
- **Max size:** 512 bytes (`BUFSIZE`) enforced in `packet.c` by truncation
- **Downstream:** All `m_*` handler functions (100+ handlers)

### Entry Point 2: Server-to-Server Protocol (P10)

- **Format:** `<numeric> <TOKEN> params` or `:name COMMAND params`
- **Parser:** `parse_server()` in `parse.c`
- **Trust model:** Any linked server is fully trusted. No per-command authorization.
- **Critical handlers:** `ms_nick`, `ms_burst`, `ms_server`, `ms_kill`, `ms_account`, `ms_svsmode`, `ms_svsjoin`, `ms_svsnick`, `ms_svsident`, `ms_svsinfo`, `ms_fake`, `ms_mark`

### Entry Point 3: Operator Commands

- **Authentication:** `can_oper()` in `m_oper.c` matches name + password + optional SSL fingerprint
- **Remote OPER:** password sent in cleartext over S2S if `FEAT_REMOTE_OPER` enabled
- **SA* commands:** Require `PRIV_NETADMIN` but operate network-wide

### Entry Point 4: Configuration Files

- **Parsed by:** `s_conf.c`, `ircd_features.c`
- **Contents:** Oper passwords, server link passwords, WEBIRC passwords, cloaking keys
- **REHASH:** Live reload via oper command — configuration errors could downgrade security

### Entry Point 5: WEBIRC Gateway

- **Handler:** `m_webirc()` in `m_webirc.c`
- **Effect:** Completely replaces client IP, hostname, and SSL state
- **Trust:** Password-authenticated but the password is static and shared

### Entry Point 6: IAuth External Daemon

- **Communication:** Pipes to external process
- **Can set:** Forced username, IP override, connection acceptance/rejection
- **Risk:** If IAuth process is compromised, it can authorize arbitrary connections

### Entry Point 7: SASL Authentication

- **Handler:** `m_authenticate()`, `ms_sasl()`
- **Flow:** Client → local server → services server → response path
- **Trust:** Account names set via `ms_account()` are trusted for host-hiding

---

## PASS 3 — Protocol Parser State Machine

### Client Parser States (`parse_client`)

```
START → eat leading spaces
  → '@' → SKIP_TAGS → eat spaces → NEXT
  → ':' → SKIP_PREFIX → eat spaces → NEXT
  → other → NEXT

NEXT:
  → '\0' → ERROR (empty message)
  → EXTRACT_COMMAND (terminated by ' ' or '\0')
  → TRIE_LOOKUP(msg_tree)
    → found → PARSE_PARAMS
    → not found → ERR_UNKNOWNCOMMAND

PARSE_PARAMS:
  → eat spaces (null-terminating each)
  → ':' → rest is single trailing param → DONE
  → token → para[++i] = s
  → i >= paramcount → rest lumped into last param → DONE
  → '\0' → DONE

DONE → dispatch to handler via cli_handler(cptr)
```

### Server Parser States (`parse_server`)

```
START:
  → ':' → EXTRACT_PREFIX_NAME → FindClient(prefix) → validate cli_from
  → digit/letter → EXTRACT_NUMERIC_PREFIX (1-2 chars = server, 3-5 chars = user)
    → FindNServer or findNUser → validate cli_from
  → eat spaces → EXTRACT_COMMAND

EXTRACT_COMMAND:
  → 3-digit numeric → NUMERIC_DISPATCH
  → token lookup in tok_tree, fallback to msg_tree
  → PARSE_PARAMS (same as client)
  → dispatch to handler[cli_handler(cptr)]
```

### Parser Edge Cases and Risks

1. **Tag skipping is simplistic:** `parse_client` skips `@tags` by scanning to the next space. A malformed tag block with no trailing space would consume the entire message silently.

2. **Prefix from clients is silently ignored:** The prefix from client messages is skipped but not validated. This is correct behavior but worth noting — clients cannot forge prefixes.

3. **Numeric prefix parsing trusts format:** In `parse_server`, the numeric prefix length determines if it's a server or user lookup. A malformed 4-character prefix falls through to `findNUser` which may return NULL, causing the message to be silently dropped.

4. **SQUIT exception in prefix handling:** When a prefix is unknown, the server still allows `SQ` (SQUIT) and certain other commands through by reassigning `from = cptr`. This is necessary for protocol correctness but creates a path where commands execute with an unexpected sender identity.

5. **Parameter count overflow:** `paramcount` is capped at `MAXPARA` (15) in the parsing loop. The `para` array is sized `MAXPARA + 2` (17 entries). With `MFLG_EXTRA` adding an extra parameter at index 1, the effective limit is still safe.

---

## PASS 4 — Taint Tracking Analysis

### Taint Sources

| Source | Entry Function | First Buffer |
|--------|---------------|-------------|
| Client TCP data | `read_packet()` | `cli_buffer(cptr)` [512 bytes] |
| Server TCP data | `read_packet()` | `cli_buffer(cptr)` [512 bytes] |
| Config file | `s_conf.c` parsing | Stack/heap strings |
| Environment | `getenv()` calls | Process environment |
| IAuth pipe | `iauth_read()` | `i_buffer` [513 bytes] |
| WEBIRC params | `m_webirc()` | `parv[]` array |

### Critical Taint Flows

**Flow 1: Client message → channel name → strcpy**
```
Client sends: JOIN #<long_name>
→ parse_client() extracts para[1] = channel name
→ m_join() → get_channel()
→ For non-MyUser (remote), no CHANNELLEN truncation
→ len = strlen(chname) [unbounded for remote]
→ MyMalloc(sizeof(Channel) + len) → strcpy(chptr->chname, chname)
```
The strcpy is safe because allocation matches, but the uncapped name length for remote servers is a trust assumption.

**Flow 2: Client message → cloaking keys → strcpy into MD5 buffer**
```
IP address → hidehost_ipv4() / hidehost_ipv6()
→ ircd_snprintf into buf[512]
→ DoMD5(res, buf, strlen(buf))
→ strcpy(res+16, KEY1)  ← KEY is config-controlled
```
If cloaking keys (KEY1/KEY2/KEY3) exceed 496 characters, `strcpy(res+16, KEY)` overflows `res[512]`. These are admin-configured but there is no length validation at config load time.

**Flow 3: Server protocol → SVS* commands → user state modification**
```
Linked server sends: SVSIDENT <numeric> <newident>
→ ms_svsident() trusts the server completely
→ ircd_strncpy(cli_user(acptr)->username, newident, USERLEN + 1)
```
A compromised server can change any user's ident, hostname, modes, channels, or nick via SVS* commands.

**Flow 4: WEBIRC → IP replacement → privilege decisions**
```
WEBIRC <pass> <user> <host> <ip>
→ m_webirc() validates password against WebIRC block
→ memcpy(&cli_ip(sptr), &addr, ...) replaces real IP
→ All subsequent IP-based decisions (G-lines, Z-lines, IPcheck, connection limits) use the spoofed IP
```

**Flow 5: Oper password → S2S cleartext transmission**
```
Client sends: OPER <server> <name> <password>
→ m_oper() with parc > 3 and FEAT_REMOTE_OPER
→ sendcmdto_one(sptr, CMD_OPER, srv, "%C %s %s", srv, parv[2], parv[3])
→ Password sent in cleartext across S2S links
```

### Taint Reaching Dangerous Operations

| Tainted Data | Dangerous Operation | Location |
|-------------|---------------------|----------|
| Channel name | `strcpy()` | `channel.c:1830` |
| Cloaking key | `strcpy()` into MD5 buffer | `ircd_cloaking.c:108-217` |
| Privilege names | `strcat()` into static buffer | `client.c:328-384` |
| Watch nicknames | `strcpy()` and `strcat()` | `m_watch.c:157-169` |
| Away message | `strcpy()` | `m_away.c:138` |
| WEBIRC IP | `memcpy()` replacing real IP | `m_webirc.c` |
| Config marks | `strcpy()` into allocated buffer | `s_conf.c:1630` |
| Error numeric format | `strcpy()` into fixed buffer | `s_err.c:2015-2020` |

---

## PASS 5 — Memory Corruption Deep Audit

### Finding MEM-01: strcpy in cloaking with config-controlled key length
**File:** `ircd/ircd_cloaking.c` lines 108, 116, 124, 132, 175, 183, 191, 199, 217
**Pattern:**
```c
static char res[512];
DoMD5((unsigned char *)&res, ...);
strcpy(res+16, KEY1); // KEY1 from config, no length check
```
**Root cause:** The cloaking keys (KEY1, KEY2, KEY3) are loaded from configuration without length validation. If any key exceeds 496 bytes, `strcpy(res+16, KEY)` overflows the 512-byte `res` buffer on the stack.
**Exploitability:** Requires admin config access. Low remote risk but could be triggered by a malicious configuration file.

### Finding MEM-02: strcat accumulation in client.c privilege printing
**File:** `ircd/client.c` lines 328-329, 356-357, 383-384
**Pattern:**
```c
static char privbufp[BUFSIZE] = "";
for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
        strcat(privbufp, privtab[i].name);
        strcat(privbufp, " ");
    }
}
```
**Root cause:** `client_check_privs()` checks `strlen(privbufp) + strlen(name) + 2 > 70` to flush, but the boundary is 70 — well within BUFSIZE (512). However, `client_send_privs()` and `client_sendtoserv_privs()` check against `BUFSIZE - mlen` which is safer. The `client_check_privs()` function resets at 70, not at BUFSIZE, so it is safe but uses a confusing threshold.
**Exploitability:** Low — the privilege table is compile-time fixed.

### Finding MEM-03: strcpy in m_away.c without explicit length check
**File:** `ircd/m_away.c` line 138
**Pattern:**
```c
strcpy(away, message);
```
**Context needed:** Must verify `away` allocation size vs. message length. The `message` comes from `parv[parc-1]` which is bounded by BUFSIZE (512) from the parser. The `away` field is `MyMalloc`'d to `strlen(message) + 1`, so this is safe by construction but fragile — any change to allocation logic could introduce a vulnerability.

### Finding MEM-04: Unbounded strcat in ircd_cloaking.c hostname construction
**File:** `ircd/ircd_cloaking.c` lines 238, 244
**Pattern:**
```c
static char result[HOSTLEN+1]; // HOSTLEN = 75
ircd_snprintf(0, result, HOSTLEN, "%s-%X.", PREFIX, alpha);
len = strlen(result) + strlen(p);
if (len <= HOSTLEN)
    strcat(result, p);
else {
    c = p + (len - HOSTLEN);
    strcat(result, c);
}
```
**Root cause:** The `else` branch computes `c` to shorten the concatenation to fit HOSTLEN, but uses `strcat` without a final bounds check. If `c` points to a string exactly `HOSTLEN - strlen(result)` long plus null terminator, it writes exactly to the limit. The logic appears correct but is fragile and should use `strncat`.

### Finding MEM-05: strcat chains in m_check.c
**File:** `ircd/m_check.c` lines 219-248, 363-369, 511-518, 585, 855
**Pattern:** Multiple `strcat()` calls building status strings into fixed buffers.
**Root cause:** These strings are built from short, known-length flag names. The buffer sizes (e.g., `outbuf[BUFSIZE]`) are large enough for all possible flag combinations. Safe in practice but unmaintainable — adding new flags without updating buffer math could overflow.

### Finding MEM-06: strcpy in m_watch.c with unbounded input
**File:** `ircd/m_watch.c` lines 157, 168-169
**Pattern:**
```c
strcpy(line, lp->value.wptr->wt_nick);
// ... later:
strcat(line, " ");
strcat(line, lp->value.wptr->wt_nick);
```
**Context:** `wt_nick` is bounded by NICKLEN (30). Multiple nicknames are accumulated. If `line` is stack-allocated with insufficient size, accumulating many watch entries could overflow.

### Finding MEM-07: strcpy in s_err.c for numeric format strings
**File:** `ircd/s_err.c` lines 2015, 2020
**Pattern:**
```c
strcpy(numbuff, ":%s 000 %s ");
strcpy(numbuff + 11, p->format);
```
**Root cause:** `p->format` comes from the compile-time error table. The `numbuff` buffer must be large enough for the prefix plus the longest format string. If any format string exceeds the buffer, overflow occurs. Safe as long as the error table is not modified to contain overly long formats.

### Finding MEM-08: strcat chains in ircd_features.c
**File:** `ircd/ircd_features.c` lines 319-400
**Pattern:** Building the ISUPPORT `MAXLIST` string with repeated `strcat()` calls appending mode letters and numeric values.
**Root cause:** The `imaxlist` buffer is stack-allocated. The accumulated content is short (mode letters + small integers + delimiters) and well within typical buffer sizes, but no explicit overflow check exists.

### Dangerous Function Census

| Function | Occurrences (ircd/*.c) | Assessment |
|----------|----------------------|------------|
| `strcpy` | ~20 | Several with config/runtime-length sources |
| `strcat` | ~55 | Primarily accumulation patterns, most with implicit bounds |
| `sprintf` | 0 (uses `ircd_snprintf`) | Safe — all format printing uses bounded variant |
| `gets` | 0 | Not present |
| `memcpy` | ~15 | Used with explicit sizes, appears safe |
| `ircd_strncpy` | ~60 | Always null-terminates, safe wrapper |
| `ircd_snprintf` | ~200+ | Bounded format printing, safe |

---

## PASS 6 — Protocol Desynchronization Analysis

### Scenario 1: Nick Collision During Netsplit

**Mechanism:** During a netsplit, two users on different sides register the same nickname. On rejoin, both servers send `NICK` introductions with different timestamps.

**Resolution logic** (in `ms_nick`): The server compares `lastnick` timestamps. The older nickname survives; the newer one is killed. If timestamps are equal, the user with the "lesser" user@host survives.

**Desync risk:** If network latency causes the KILL for the losing nick to not propagate to all servers before additional state changes (mode changes, channel joins), different servers may briefly disagree about which user holds the nick.

### Scenario 2: Channel Timestamp Manipulation

**Mechanism:** The BURST message includes a channel creation timestamp. A server introducing a channel with an older timestamp can override the existing channel's modes.

**Attack vector:** A compromised or rogue server sends a BURST with `creationtime` = 0 (or very old), causing all existing modes, bans, and operator status to be wiped in favor of the "older" channel state.

**Impact:** Complete channel takeover: the attacker's server can set arbitrary modes, operators, and bans.

### Scenario 3: Fake Server Introduction

**Mechanism:** `ms_server()` introduces new servers. If an attacker controls a linked server, they can introduce fake servers with arbitrary numerics.

**Detection:** `check_loop_and_lh()` validates against hub/leaf restrictions and numeric collisions. However, if the hub mask is permissive (e.g., `*`), any server name can be introduced.

**Impact:** A fake server can then introduce fake users via NICK, set ACCOUNT states via ms_account, and issue SVS* commands.

### Scenario 4: SVS* Abuse from Compromised Server

**Mechanism:** All SVS* commands (SVSMODE, SVSJOIN, SVSNICK, SVSIDENT, SVSINFO, SVSPART, SVSQUIT, SVSNOOP) are server-only but have NO sender verification beyond `IsServer(cptr)`.

**Impact:** Any linked server can:
- Change any user's ident (`SVSIDENT`)
- Change any user's modes including +o oper (`SVSMODE`)
- Force any user into or out of channels (`SVSJOIN`/`SVSPART`)
- Force nick changes (`SVSNICK`)
- Kill any user (`SVSQUIT`)

There is no "services server" or "U-line" restriction on which servers can issue these commands.

### Scenario 5: ACCOUNT Spoofing

**Mechanism:** `ms_account()` sets a user's account name and can trigger host-hiding. Any linked server can issue this.

**Impact:** An attacker controlling a linked server can set `+r` (registered) and an arbitrary account name on any user, bypassing services authentication. This account name is then trusted for extended bans (`~a:account`), channel access, and host hiding.

### Scenario 6: MARK Metadata Injection

**Mechanism:** `ms_mark()` sets arbitrary metadata marks on clients. These marks can influence WEBIRC processing, connection classification, and operational visibility.

**Impact:** A compromised server can inject marks that alter how the target server classifies connections.

---

## PASS 7 — Privilege Escalation Analysis

### Finding PRIV-01: Remote OPER Sends Password in Cleartext

**Location:** `m_oper.c` line 248-254
**Mechanism:** When `FEAT_REMOTE_OPER` is enabled and a user specifies a remote server, the OPER command (including the plaintext password) is forwarded via S2S protocol.
**Impact:** Any server on the path between the client's server and the target server can intercept oper credentials.
**Severity:** HIGH if remote OPER is enabled.

### Finding PRIV-02: No Source Restriction on SVS* Commands

**Location:** `m_svsmode.c`, `m_svsjoin.c`, `m_svsnick.c`, `m_svsident.c`, `m_svspart.c`, `m_svsquit.c`, `m_svsnoop.c`, `m_svsinfo.c`
**Mechanism:** These commands are restricted to the SERVER handler (`ms_*`) but any linked server can issue them. There is no U-line or services-only check.
**Impact:** A single compromised leaf server can escalate to full network control by issuing SVSMODE to grant oper on arbitrary users, then using those opers.
**Severity:** CRITICAL in multi-server networks.

### Finding PRIV-03: OPMODE/CLEARMODE Without Full Logging

**Location:** `m_opmode.c`, `m_clearmode.c`
**Mechanism:** These commands allow opers with PRIV_OPMODE to override channel modes. While server notices are sent, the source oper information may not reach all servers.
**Impact:** An oper can take over any channel. The logging is present but could be evaded if the oper has SNO_OLDSNO disabled on target servers.

### Finding PRIV-04: SA* Commands Bypass All Channel Restrictions

**Location:** `m_sa.c`
**Mechanism:** SAJOIN bypasses: +i (invite only), +k (key), +l (limit), +b (bans), +r (registered only), +S (SSL only), and all extended bans. No channel-side validation occurs.
**Impact:** A netadmin can force any user into any channel regardless of protections.
**Severity:** By design, but the lack of any audit trail on the target channel is notable.

### Finding PRIV-05: WEBIRC Password Comparison

**Location:** `m_webirc.c` → `find_webirc_conf()`
**Mechanism:** WEBIRC authentication uses a static shared password. If this password leaks (e.g., from a compromised web gateway), any connection can spoof arbitrary IPs.
**Impact:** Complete IP-based security bypass (G-lines, Z-lines, connection limits, ident lookups).

### Finding PRIV-06: IAuth Can Override All Connection Checks

**Location:** `s_auth.c`
**Mechanism:** IAuth flags include `IAUTH_REQUIRED` (connection fails without IAuth approval), `IAUTH_UNDERNET` (Undernet extensions for IP/class override). IAuth can set forced usernames, override IP addresses, and set connection classes.
**Impact:** A compromised IAuth process has root-equivalent access to the server.

### Finding PRIV-07: Handler Index Determines Privilege Level

**Location:** `parse.c` dispatch via `cli_handler(cptr)`
**Mechanism:** The handler index (0=UNREG, 1=CLIENT, 2=SERVER, 3=OPER, 4=SERVICE) determines which function processes the command. This is set in `s_user.c` during registration and in `m_oper.c` upon OPER.
**Risk:** If `cli_handler` were corrupted (e.g., by a memory safety bug), a client could be dispatched to server handlers, bypassing all client-side restrictions.

---

## PASS 8 — Fuzz Test Generation Plan

### Target 1: Protocol Parser (parse_client)
```
# Oversized messages (exceed 512 bytes)
python -c "print('A' * 600)" | nc target 6667

# Malformed prefix
printf ':%.500s PRIVMSG #test :hello\r\n' "$(python -c "print('A'*500)")"

# Empty command with prefix
printf ':\x01\x02\x03 \r\n'

# Null bytes in command
printf 'PRIVMSG\x00 #test :hello\r\n'

# Maximum parameters
printf 'PRIVMSG p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p13 p14 p15 p16\r\n'

# Tags abuse
printf '@%.1000s PRIVMSG #test :hello\r\n' "$(python -c "print('a=b;'*250)")"
```

### Target 2: Nick Registration
```
# Oversized nick
printf 'NICK %.200s\r\n' "$(python -c "print('A'*200)")"

# Nick with control characters
printf 'NICK \x01\x02test\r\n'

# Nick starting with digit
printf 'NICK 1badnick\r\n'

# Nick with tilde
printf 'NICK test~name\r\n'

# Rapid nick changes
for i in $(seq 1 100); do printf 'NICK nick%d\r\n' $i; done
```

### Target 3: Channel Operations
```
# Oversized channel name
printf 'JOIN #%.300s\r\n' "$(python -c "print('A'*300)")"

# Channel with null bytes
printf 'JOIN #test\x00hidden\r\n'

# MODE with maximum parameters
printf 'MODE #test +oooooo n1 n2 n3 n4 n5 n6\r\n'

# Extended ban fuzzing
printf 'MODE #test +b ~a:%.200s\r\n' "$(python -c "print('A'*200)")"
```

### Target 4: Server Protocol (requires S2S link)
```
# Malformed BURST
AB B #test 0 +nt :AAAAAA:o,BBBBBB

# NICK introduction with mismatched parameter count
AB N nick 1 0 user host +o AAAAAA :realname

# Oversized SVSIDENT
AB SI AAAAAA $(python -c "print('A'*200)")

# SVSMODE with invalid modes
AB SM AAAAAA +ZZZZZZZ
```

### AFL++ Harness Strategy

The recommended approach is to create a harness that:
1. Initializes the server in a minimal state (fake local server, one connected pseudo-server)
2. Feeds mutated input to `parse_client()` or `parse_server()`
3. Uses AddressSanitizer (ASAN) and UndefinedBehaviorSanitizer (UBSAN)
4. Seeds the corpus with valid IRC protocol messages for each command type

---

## PASS 9 — Exploit Development Analysis

### Exploit Chain 1: Compromised Leaf Server → Full Network Takeover

**Prerequisites:** Attacker controls one linked server.

**Step 1:** Introduce a fake user via NICK:
```
<attacker_numeric> N admin 1 <timestamp> fakeadmin fake.host +oiwsg B]AAAB AAAAAA :Fake Admin
```

**Step 2:** Set account on fake user:
```
<attacker_numeric> AC AAAAAA R admin
```

**Step 3:** Grant all oper privileges:
```
<attacker_numeric> PRIVS AAAAAA WHOX DISPLAY CHAN_LIMIT MODE_LCHAN DEOP_LCHAN WALK_LCHAN LOCAL_KILL REHASH RESTART DIE GLINE LOCAL_GLINE JUPE LOCAL_JUPE OPMODE ...
```

**Step 4:** Use the opered fake user to issue network-wide commands (GLINE all users, SQUIT servers, etc.).

**Final capability:** Complete network denial of service, mass user disconnection, channel takeover, and data exfiltration of all visible messages.

### Exploit Chain 2: WEBIRC Password Leak → IP Spoofing → Ban Evasion

**Prerequisites:** WEBIRC password leaked from web gateway config.

**Step 1:** Connect directly to IRC port.
**Step 2:** Send `WEBIRC <password> gateway spoofed.host 127.0.0.1`
**Step 3:** Server replaces attacker's real IP with 127.0.0.1 (or any chosen IP).
**Step 4:** All G-lines, Z-lines, and IP bans against attacker's real IP are bypassed.
**Step 5:** Attacker can impersonate connections from any IP, including trusted admin IPs.

**With WFLAG_TRUSTACCOUNT:** The attacker can also set an arbitrary account name, gaining +r status and bypassing `~a:` extended bans and registered-only channels.

### Exploit Chain 3: Cloaking Key Overflow (Config-Triggered)

**Prerequisites:** Admin writes overly long cloaking key in config (>496 chars).

**Trigger:** Any user connection triggers `hidehost_ipv4()` or `hidehost_ipv6()`.

**Step 1:** `ircd_snprintf` fills `buf[512]` safely.
**Step 2:** `DoMD5()` writes 16 bytes to `res[512]`.
**Step 3:** `strcpy(res+16, KEY1)` copies 497+ bytes starting at offset 16, writing past `res[512]`.
**Step 4:** Stack overflow — attacker-controlled data (the key) overwrites the return address.

**Impact:** Arbitrary code execution as the IRCd process. Requires malicious config but could be triggered by config injection via REHASH if an oper account is compromised.

### Vulnerability Severity Summary

| ID | Description | CVSS Est. | Remote? |
|----|------------|-----------|---------|
| PRIV-02 | No SVS* source restriction | 9.8 | Yes (via linked server) |
| PRIV-01 | Remote OPER cleartext password | 7.5 | Yes (passive intercept) |
| PRIV-05 | WEBIRC static password | 8.1 | Yes (if password leaked) |
| MEM-01 | Cloaking key strcpy overflow | 7.8 | No (requires config access) |
| PRIV-06 | IAuth full override | 8.6 | No (requires process compromise) |
| MEM-06 | Watch list strcat accumulation | 5.3 | Possible (needs investigation) |

---

## PASS 10 — Secure Refactor Recommendations

### Patch 1: Add SVS* Source Validation

**Problem:** Any linked server can issue SVS* commands.
**Fix:** Add a "services server" (U-line) check. Only servers explicitly configured as services should be allowed to issue SVS* commands.

```c
/* Add to each ms_svs* handler: */
if (!IsService(sptr) && !find_conf_byname(cli_confs(cptr), cli_name(sptr), CONF_UWORLD)) {
    return protocol_violation(sptr, "SVS* command from non-service server");
}
```

### Patch 2: Replace strcpy in Cloaking with Bounded Copy

**Problem:** `strcpy(res+16, KEY)` can overflow if key > 496 chars.
**Fix:**
```c
/* Replace all instances of: */
strcpy(res+16, KEY1);
/* With: */
ircd_strncpy(res+16, KEY1, sizeof(res) - 16);
```

Additionally, add key length validation at config load time:
```c
#define MAX_CLOAK_KEY_LEN 128
if (strlen(key) > MAX_CLOAK_KEY_LEN) {
    log_write(LS_CONFIG, L_ERROR, 0, "Cloaking key too long (max %d)", MAX_CLOAK_KEY_LEN);
    return 0;
}
```

### Patch 3: Eliminate All Remaining strcpy/strcat Usage

Replace the ~75 remaining `strcpy`/`strcat` calls with bounded alternatives:

| Current | Replacement |
|---------|-------------|
| `strcpy(dst, src)` | `ircd_strncpy(dst, src, sizeof(dst))` |
| `strcat(dst, src)` | `strncat(dst, src, sizeof(dst) - strlen(dst) - 1)` or use the `pos`-tracking pattern from `client_print_privs()` |

The `client_print_privs()` function already demonstrates the correct bounded pattern using `memcpy` with position tracking — this should be the template for all similar accumulation code.

### Patch 4: Encrypt Remote OPER Passwords

**Problem:** Remote OPER sends password in cleartext over S2S.
**Fix:** Either:
a) Remove `FEAT_REMOTE_OPER` entirely (recommended), or
b) Implement challenge-response: server sends a random challenge, client responds with HMAC(password, challenge)

### Patch 5: Restrict WEBIRC Account Trust

**Problem:** `WFLAG_TRUSTACCOUNT` allows WEBIRC to set arbitrary account names.
**Fix:** Remove `WFLAG_TRUSTACCOUNT` or require that account names set via WEBIRC are verified through SASL authentication afterward.

### Patch 6: Add Explicit BUFSIZE Enforcement in Packet Layer

The current packet handlers silently truncate messages exceeding BUFSIZE:
```c
else if (endp < client_buffer + BUFSIZE)
    ++endp;
```
This is correct but should log when truncation occurs, as it may indicate an attack:
```c
else if (endp < client_buffer + BUFSIZE)
    ++endp;
else if (!cli_truncwarn(cptr)) {
    log_write(LS_SYSTEM, L_WARNING, 0, "Message truncated from %s", cli_name(cptr));
    cli_truncwarn(cptr) = 1;
}
```

### Patch 7: Harden IRCv3 Tag Parsing

The current tag-skipping code in `parse_client()`:
```c
if (*ch == '@') {
    for (++ch; *ch && *ch != ' '; ++ch)
        ;
    while (*ch == ' ') ch++;
}
```
Should validate that the tag section doesn't consume the entire buffer and add a maximum tag length check:
```c
if (*ch == '@') {
    char *tag_start = ch;
    for (++ch; *ch && *ch != ' '; ++ch)
        ;
    if ((ch - tag_start) > 8191) { /* IRCv3 tag limit */
        /* reject or truncate */
    }
    while (*ch == ' ') ch++;
}
```

### Patch 8: Validate Cloaking Key Length at Load Time

In `ircd_features.c` where cloaking keys are set, add:
```c
case FEAT_HOST_HIDING_KEY1:
case FEAT_HOST_HIDING_KEY2:
case FEAT_HOST_HIDING_KEY3:
    if (strlen(value) > 128) {
        log_write(LS_CONFIG, L_ERROR, 0, "Cloaking key exceeds maximum length of 128");
        return 0;
    }
    break;
```

### Compilation Recommendations

Build with security hardening flags:
```
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
LDFLAGS += -Wl,-z,relro,-z,now -pie
```

Enable AddressSanitizer during testing:
```
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
```

---

## Appendix: File Reference

| File | Lines | Security Role |
|------|-------|--------------|
| `ircd/parse.c` | 1,697 | Protocol parser, command dispatch |
| `ircd/packet.c` | 166 | Packet framing, BUFSIZE enforcement |
| `ircd/channel.c` | 5,088 | Channel state, mode processing |
| `ircd/s_auth.c` | 2,890 | Client registration, IAuth |
| `ircd/s_user.c` | 2,715 | User management, mode setting |
| `ircd/m_oper.c` | 286 | Operator authentication |
| `ircd/m_sa.c` | 332 | Network admin force commands |
| `ircd/m_server.c` | 793 | Server link introduction |
| `ircd/m_burst.c` | 762 | Network synchronization |
| `ircd/m_webirc.c` | 273 | Web gateway IP spoofing |
| `ircd/ircd_cloaking.c` | ~260 | Host cloaking (vulnerable strcpy) |
| `ircd/m_nick.c` | ~600 | Nick registration and collision |
| `ircd/client.c` | ~500 | Client struct management |
| `ircd/ircd_string.c` | 952 | String utilities (ircd_strncpy) |
| `ircd/s_conf.c` | 1,672 | Configuration parsing |
